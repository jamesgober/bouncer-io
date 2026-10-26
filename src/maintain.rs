//! Work that is not on a request path: eject-now sweeps, checks on tickets
//! that have stopped crossing checkpoints, and cleanup of revocation entries
//! no live ticket can still need. Either the caller drives
//! [`Bouncer::maintain`](crate::Bouncer::maintain), or one parked thread does
//! it; with nothing pending it never wakes.

use core::time::Duration;
use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex, Weak},
};

use crate::{
    bouncer::Shared,
    directive::{Actor, Reason},
    events::{self, Emit},
    keys::ConnId,
    registry::{F_LIVE, F_PENDING_CLIENT, F_REVOKED, KIND_CONNECTION, KIND_REQUEST, generation},
    revoke::Target,
    sync::{AtomicU64, Ordering},
    ticket::{check_cell, mark_revoked, source_of, subject_of},
    time::Now,
    verdict::{DenialCode, Reference},
};

/// How bouncer closes a connection it is not holding: from eject-now
/// sweeps, from checks on idle tickets, and from `deny_and_eject`.
///
/// The integration implements it over the transport's kill handle (net-io
/// closes with `SO_LINGER` 0). Fire and forget: failures are the transport's
/// events.
///
/// # Examples
///
/// ```
/// use bouncer_io::{Bouncer, CloseKind, ConnId, Ejector};
/// use std::sync::{Arc, Mutex};
///
/// #[derive(Default)]
/// struct Kills(Mutex<Vec<ConnId>>);
/// impl Ejector for Kills {
///     fn eject(&self, conn: ConnId, _kind: CloseKind) {
///         self.0.lock().unwrap().push(conn);
///     }
/// }
/// let kills = Arc::new(Kills::default());
/// let bouncer = Bouncer::builder().ejector(kills.clone()).try_build()?;
/// let conn = bouncer.door("192.0.2.7".parse()?)?;      // idle: never crosses a checkpoint
/// bouncer.apply(bouncer_io::Directive::revoke(conn.conn()).eject_now())?;
/// assert_eq!(*kills.0.lock().unwrap(), vec![conn.conn()]);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub trait Ejector: Send + Sync {
    /// Closes the connection.
    fn eject(&self, conn: ConnId, kind: CloseKind);
}

/// How to close.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseKind {
    /// At once, with a reset (`SO_LINGER` 0).
    Abort,
    /// After the pending bytes (a denial) are flushed, or the deadline
    /// passes, whichever is first; then a reset.
    AfterFlush {
        /// The longest wait for the flush.
        deadline: Duration,
    },
}

/// What one maintenance step did.
///
/// # Examples
///
/// ```
/// let bouncer = bouncer_io::Bouncer::new();
/// let report = bouncer.maintain(bouncer.now());
/// assert_eq!(report.next_due, None);       // nothing to do until something is revoked
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MaintenanceReport {
    /// Tickets checked by an eject-now sweep.
    pub swept: u32,
    /// Connections closed through the `Ejector`.
    pub ejected: u32,
    /// Idle tickets checked on their behalf.
    pub idle_checked: u32,
    /// Revocation entries removed because no live ticket needs them.
    pub reclaimed: u32,
    /// Journal records written (arrives with persistence).
    pub journal_written: u32,
    /// When more work is next due; `None` when nothing is pending.
    pub next_due: Option<Now>,
}

/// Maintenance state of one bouncer.
pub(crate) struct Maintenance {
    /// Epoch values sampled at maintenance runs, oldest first, to tell how
    /// long a ticket has gone without a checkpoint.
    samples: Mutex<VecDeque<(u64, Now)>>,
    /// Proxied requests still waiting for their client, by (cell,
    /// generation): when a run first saw them, and whether they were
    /// reported (edge case 22, D-097).
    pending: Mutex<HashMap<(u32, u32), (Now, bool)>>,
    sweep_requested: AtomicU64,
    thread: Mutex<Option<std::thread::Thread>>,
    stop: AtomicU64,
    /// 0 not started, 1 parked, 2 running, 3 stopped.
    state: AtomicU64,
    pub(crate) max_unchecked: Duration,
    pub(crate) interval: Duration,
}

impl Maintenance {
    pub(crate) fn new(max_unchecked: Duration) -> Maintenance {
        Maintenance {
            samples: Mutex::new(VecDeque::new()),
            pending: Mutex::new(HashMap::new()),
            sweep_requested: AtomicU64::new(0),
            thread: Mutex::new(None),
            stop: AtomicU64::new(0),
            state: AtomicU64::new(0),
            max_unchecked,
            interval: Duration::from_secs(10).min(max_unchecked),
        }
    }

    /// `true` when a thread does the work.
    pub(crate) fn has_thread(&self) -> bool {
        self.thread.lock().map(|t| t.is_some()).unwrap_or(false)
    }

    /// Wakes the maintainer thread, if there is one.
    pub(crate) fn wake(&self) {
        if let Ok(t) = self.thread.lock() {
            if let Some(t) = t.as_ref() {
                t.unpark();
            }
        }
    }

    /// The maintainer thread's state.
    pub(crate) fn state(&self) -> crate::admin::MaintainerState {
        use crate::admin::MaintainerState;
        match self.state.load(Ordering::Acquire) {
            1 => MaintainerState::Parked,
            2 => MaintainerState::Running,
            3 => MaintainerState::Stopped,
            _ => MaintainerState::NotStarted,
        }
    }

    fn set_state(&self, s: u64) {
        self.state.store(s, Ordering::Release);
    }

    /// Whether a maintenance run already reported this pending request
    /// (then its release reports nothing more).
    pub(crate) fn reported_pending(&self, index: u32, gen_: u32) -> bool {
        self.pending
            .lock()
            .map(|p| p.get(&(index, gen_)).is_some_and(|&(_, r)| r))
            .unwrap_or(false)
    }

    pub(crate) fn request_sweep(&self) {
        self.sweep_requested.fetch_add(1, Ordering::AcqRel);
        self.wake();
    }

    pub(crate) fn stop(&self) {
        self.stop.store(1, Ordering::Release);
        self.wake();
    }
}

/// One bounded maintenance step.
pub(crate) fn run(shared: &Shared, now: Now) -> MaintenanceReport {
    crate::metrics::meter!(shared.meters, sweeps);
    let mut report = MaintenanceReport::default();
    let epoch = shared.epoch.load();
    let sweep = shared.maintenance.sweep_requested.swap(0, Ordering::AcqRel) > 0;
    if sweep {
        let (swept, ejected) = sweep_all(shared, epoch);
        report.swept = swept;
        report.ejected += ejected;
    }
    if let Ok(n) = shared.persist_flush(now, false) {
        report.journal_written = n;
    }
    report_unresolved(shared, now);
    let persist_due = shared.persist_due();
    if shared.revocations.is_empty() {
        if let Ok(mut s) = shared.maintenance.samples.lock() {
            s.clear();
        }
        report.next_due = persist_due;
        return report;
    }
    // Idle tickets: checked by no checkpoint since an epoch that was current
    // `max_unchecked` ago.
    let idle_before = {
        let mut s = shared
            .maintenance
            .samples
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if s.back().is_none_or(|&(e, _)| e != epoch) {
            s.push_back((epoch, now));
        }
        // Nothing can be idle before `max_unchecked` has passed at all.
        let horizon = now.as_nanos().checked_sub(
            u64::try_from(shared.maintenance.max_unchecked.as_nanos()).unwrap_or(u64::MAX),
        );
        let mut cutoff = None;
        while let (Some(&(e, at)), Some(horizon)) = (s.front(), horizon) {
            if at.as_nanos() <= horizon {
                cutoff = Some(e);
                if s.len() > 1 {
                    s.pop_front();
                    continue;
                }
            }
            break;
        }
        cutoff
    };
    let mut min_seen = epoch;
    let cells = &shared.registry.cells;
    for (index, cell) in cells.iter().enumerate() {
        let st = cell.state.load(Ordering::Acquire);
        if st & F_LIVE == 0 || st & (F_REVOKED | F_PENDING_CLIENT) != 0 {
            continue;
        }
        let gen_ = generation(st);
        let mut seen = cell.seen.load(Ordering::Acquire);
        if seen != epoch && idle_before.is_some_and(|cut| seen <= cut) {
            report.idle_checked += 1;
            match check_cell(shared, index as u32, gen_, epoch) {
                Ok(()) => seen = epoch,
                Err(_) => {
                    report.ejected += eject_revoked(shared, index as u32, true);
                    continue;
                }
            }
        }
        min_seen = min_seen.min(seen);
    }
    report.reclaimed = shared.revocations.remove_born_by(min_seen);
    let revocations_due = (!shared.revocations.is_empty()).then(|| {
        Now::from_nanos(now.as_nanos().saturating_add(
            u64::try_from(shared.maintenance.interval.as_nanos()).unwrap_or(u64::MAX),
        ))
    });
    report.next_due = match (revocations_due, persist_due) {
        (Some(a), Some(b)) => Some(if a.as_nanos() <= b.as_nanos() { a } else { b }),
        (a, b) => a.or(b),
    };
    report
}

/// Reports proxied requests whose adapter has not bound the real client
/// `max_unchecked` after a run first saw them (the handshake deadline; such
/// a request is denied at every checkpoint meanwhile). One scan of the
/// registry per run; nothing on the hot path. A request released before a
/// run reports it is reported at its release instead.
fn report_unresolved(shared: &Shared, now: Now) {
    let Ok(mut pending) = shared.maintenance.pending.lock() else {
        return;
    };
    let max = u64::try_from(shared.maintenance.max_unchecked.as_nanos()).unwrap_or(u64::MAX);
    let mut live = Vec::new();
    for (index, cell) in shared.registry.cells.iter().enumerate() {
        let st = cell.state.load(Ordering::Acquire);
        if st & F_LIVE == 0 || st & 0xff != KIND_REQUEST || st & F_PENDING_CLIENT == 0 {
            continue;
        }
        let key = (index as u32, generation(st));
        live.push(key);
        let entry = pending.entry(key).or_insert((now, false));
        if !entry.1 && now.as_nanos().saturating_sub(entry.0.as_nanos()) >= max {
            entry.1 = true;
            Emit {
                subject: subject_of(cell),
                ..Emit::new(events::signals::DOOR_PROXY_HOP_UNRESOLVED)
            }
            .send(shared);
        }
    }
    if pending.len() > live.len() {
        live.sort_unstable();
        pending.retain(|k, _| live.binary_search(k).is_ok());
    }
}

/// Checks every live ticket now and ejects the denied connections. Returns
/// (tickets found denied, connections ejected).
pub(crate) fn sweep_all(shared: &Shared, epoch: u64) -> (u32, u32) {
    let mut denied = 0;
    let mut ejected = 0;
    for (index, cell) in shared.registry.cells.iter().enumerate() {
        let st = cell.state.load(Ordering::Acquire);
        if st & F_LIVE == 0 || st & F_PENDING_CLIENT != 0 {
            continue;
        }
        if check_cell(shared, index as u32, generation(st), epoch).is_err() {
            denied += 1;
            ejected += eject_revoked(shared, index as u32, false);
        }
    }
    // Requests revoked above may have revoked their connections after the
    // connection cells were visited.
    for (index, cell) in shared.registry.cells.iter().enumerate() {
        let st = cell.state.load(Ordering::Acquire);
        if st & F_LIVE != 0 && st & F_REVOKED != 0 && st & 0xff == KIND_CONNECTION {
            ejected += eject_revoked(shared, index as u32, false);
        }
    }
    (denied, ejected)
}

/// Ejects a revoked connection cell once (through the `Ejector`), and
/// reports a missing checkpoint for idle ones. Returns 1 when ejected.
fn eject_revoked(shared: &Shared, index: u32, idle: bool) -> u32 {
    let cell = shared.registry.cell(index);
    let st = cell.state.load(Ordering::Acquire);
    if st & F_LIVE == 0 || st & F_REVOKED == 0 {
        return 0;
    }
    if idle {
        events::emit_ticket(
            shared,
            events::signals::CHECKPOINT_MISSING,
            cell,
            Reference::new(0),
        );
    }
    if st & 0xff != KIND_CONNECTION {
        // A denied request ejects its connection when the revocation took
        // the connection too.
        let link = cell.link.load(Ordering::Relaxed);
        let (pi, pg) = ((link >> 32) as u32, link as u32);
        let pst = shared.registry.cell(pi).state.load(Ordering::Acquire);
        if generation(pst) == pg && pst & F_REVOKED != 0 {
            return eject_revoked(shared, pi, false);
        }
        return 0;
    }
    // Eject each connection once: the cancel flag marks it done.
    let gen_ = generation(st);
    let first = crate::sync::update(&cell.state, Ordering::AcqRel, Ordering::Acquire, |s| {
        (generation(s) == gen_ && s & crate::registry::F_CANCELLED == 0)
            .then_some(s | crate::registry::F_CANCELLED)
    })
    .is_ok();
    let Some(ejector) = shared.ejector.as_ref() else {
        return 0;
    };
    if !first {
        return 0;
    }
    let conn = ConnId(cell.conn.load(Ordering::Relaxed));
    // The cell may have been released and reissued meanwhile: only eject if
    // it is still the same ticket.
    if generation(cell.state.load(Ordering::Acquire)) != gen_ {
        return 0;
    }
    ejector.eject(conn, crate::maintain::CloseKind::Abort);
    crate::metrics::meter!(shared.meters, ejections);
    1
}

/// Marks every live ticket matching `target` revoked, without the
/// revocation table (used when the table is full). Returns how many.
pub(crate) fn direct_sweep(
    shared: &Shared,
    target: &Target,
    code: DenialCode,
    keep_connection: bool,
) -> u32 {
    let mut n = 0;
    for cell in shared.registry.cells.iter() {
        let st = cell.state.load(Ordering::Acquire);
        if st & F_LIVE == 0 {
            continue;
        }
        if matches_target(cell, target) && mark_revoked(cell, generation(st), code) {
            n += 1;
            if st & 0xff != KIND_CONNECTION && !keep_connection {
                let link = cell.link.load(Ordering::Relaxed);
                mark_revoked(shared.registry.cell((link >> 32) as u32), link as u32, code);
            }
        }
    }
    n
}

/// `true` when a cell carries the target's key.
pub(crate) fn matches_target(cell: &crate::registry::Cell, target: &Target) -> bool {
    let s = subject_of(cell);
    match *target {
        Target::Connection(c) => s.conn == Some(c),
        Target::Request(r) => s.request == Some(r),
        Target::Session(k) => s.session == Some(k),
        Target::Account(k) => s.account == Some(k),
        Target::Tenant(k) => s.tenant == Some(k),
        Target::Fingerprint(k) => s.fingerprint == Some(k),
        Target::Source(c) => source_of(cell).is_some_and(|a| c.contains(a)),
    }
}

/// Starts the parked maintainer thread.
pub(crate) fn spawn(shared: &Arc<Shared>) -> Result<(), std::io::ErrorKind> {
    let weak: Weak<Shared> = Arc::downgrade(shared);
    let handle = std::thread::Builder::new()
        .name("bouncer-maintainer".into())
        .spawn(move || {
            // Marks the state stopped however the loop ends, a panic included.
            struct Stopped(Weak<Shared>);
            impl Drop for Stopped {
                fn drop(&mut self) {
                    if let Some(shared) = self.0.upgrade() {
                        shared.maintenance.set_state(3);
                    }
                }
            }
            let _stopped = Stopped(weak.clone());
            loop {
                let Some(shared) = weak.upgrade() else { return };
                if shared.maintenance.stop.load(Ordering::Acquire) != 0 {
                    return;
                }
                shared.maintenance.set_state(2);
                let now = shared.now();
                let report = run(&shared, now);
                shared.maintenance.set_state(1);
                drop(shared);
                match report.next_due {
                    None => std::thread::park(),
                    Some(due) => std::thread::park_timeout(Duration::from_nanos(
                        due.as_nanos().saturating_sub(now.as_nanos()),
                    )),
                }
            }
        })
        .map_err(|e| e.kind())?;
    *shared
        .maintenance
        .thread
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(handle.thread().clone());
    // Parked until its first run says otherwise (it may already be running).
    let _ = shared
        .maintenance
        .state
        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire);
    Ok(())
}

/// Reports a revocation.
pub(crate) fn report_revocation(
    shared: &Shared,
    target: &Target,
    actor: Actor,
    reason: Reason,
    reference: Reference,
    confidence: Option<u8>,
) {
    if shared.sink.is_none() {
        return;
    }
    let mut subject = events::Subject::default();
    match *target {
        Target::Connection(c) => subject.conn = Some(c),
        Target::Request(r) => subject.request = Some(r),
        Target::Session(k) => subject.session = Some(k),
        Target::Account(k) => subject.account = Some(k),
        Target::Tenant(k) => subject.tenant = Some(k),
        Target::Source(c) => subject.prefix = Some(c),
        Target::Fingerprint(k) => subject.fingerprint = Some(k),
    }
    Emit {
        actor,
        reason,
        subject,
        reference,
        confidence,
        ..Emit::new(events::signals::REVOKE_APPLIED)
    }
    .send(shared);
}
