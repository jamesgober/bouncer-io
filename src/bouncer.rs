//! The bouncer and its builder.

use core::{cell::Cell as StdCell, fmt, time::Duration};
use std::{net::IpAddr, sync::Arc, time::SystemTime};

use clock_lib::{Clock, Monotonic, SystemClock};

use crate::{
    allow::{AllowKind, AllowList},
    bans::{
        BanDuration, BanId, BanMemory, BanSpec, DurationPolicy, Guards, LiftSpec, Lifted,
        compiled::PrefixSet,
        escalate::{EscalationPolicy, Plan},
    },
    budgets::{Budgets, DoorBudgets, IdentityBudgets, IdentityKey, IdentityKind},
    directive::{Action, Actor, Applied, BanKeys, Directive, Reason},
    door::{DatagramVerdict, Judgement, Provenance, Refusal},
    error::{BouncerError, ConfigError, ConfigProblem},
    events::{self, Emit, EventSink},
    hash::{HashKey, Seeds},
    keys::{BanKey, Cidr, ConnId, RequestId, normalize},
    maintain::{self, Ejector, Maintenance, MaintenanceReport},
    metrics::{Meters, meter},
    published::Published,
    registry::{
        F_CHARGED, F_DETACHED, F_IMMUNE, F_LIVE, F_PROXY_HOP, KIND_CONNECTION, KIND_REQUEST,
        P_SESSION, Registry, Shard, generation,
    },
    revoke::{Record, Revocation, RevocationEpoch, Revocations, RevokeMode, Target, target_key},
    share::NodeId,
    strikes::{Counters, Enforcement, Posture, StrikeRules},
    sync::{AtomicU32, AtomicU64, Ordering},
    ticket::{self, Issue, Ticket, TicketKind, TicketTag, mark_revoked, subject_of},
    time::Now,
    verdict::{DenialCode, DenialTable, Reference, Verdict},
};

/// Most tickets a bouncer holds: the cell index has 24 bits per shard.
const MAX_TICKETS: u32 = 1 << 24;
/// Most shards.
const MAX_SHARDS: u16 = 256;
/// Most ban entries.
const MAX_BAN_CAPACITY: u32 = 1 << 26;

/// State every shard reads: time, ban memory, allow list, trusted proxies,
/// revocations, budgets, events.
pub(crate) struct Shared {
    clock: Arc<dyn Clock>,
    start: Monotonic,
    /// Wall time when the bouncer started: `start` on the wall clock.
    pub(crate) start_wall: SystemTime,
    /// This node, when sharing is configured.
    pub(crate) node: Option<NodeId>,
    pub(crate) bans: BanMemory,
    pub(crate) allow: Published<PrefixSet<AllowKind>>,
    /// Entries in the allow list now: the door skips the list when zero.
    pub(crate) allow_len: AtomicU32,
    /// The latest whole second the door has seen: a clock reading for
    /// coarse uses (shared-address windows) without reading the clock.
    seen_secs: AtomicU64,
    pub(crate) proxies: PrefixSet<()>,
    pub(crate) references: HashKey,
    pub(crate) tickets_capacity: u32,
    pub(crate) registry: Registry,
    pub(crate) epoch: Arc<RevocationEpoch>,
    pub(crate) revocations: Revocations,
    pub(crate) budgets: DoorBudgets,
    pub(crate) identity: IdentityBudgets,
    pub(crate) sources: crate::sources::Sources,
    pub(crate) persist: Option<crate::persist::Persist>,
    pub(crate) share: crate::share::Share,
    /// Each node's ban per key and the lifts covering them: on a node that
    /// shares (it has a node id), the source of truth the ban table follows
    /// (D-096).
    pub(crate) ledger: Option<std::sync::Mutex<crate::ledger::Ledger>>,
    pub(crate) max_clock_skew: Duration,
    /// 0 normal, 1 strict.
    posture: AtomicU32,
    strict_divisor: u32,
    strict_revokes_unauthenticated: bool,
    pub(crate) strikes: StrikeRules,
    pub(crate) counters: Counters,
    pub(crate) enforcement: Enforcement,
    pub(crate) denials: DenialTable,
    pub(crate) sink: Option<Arc<dyn EventSink>>,
    pub(crate) ejector: Option<Arc<dyn Ejector>>,
    pub(crate) maintenance: Maintenance,
    pub(crate) revocation_rate: Option<rate_net::Gcra>,
    pub(crate) format: Arc<dyn crate::format::DenialFormat>,
    /// Counters of cold paths (bans, revocations, maintenance).
    #[cfg_attr(not(feature = "metrics"), allow(dead_code))]
    pub(crate) meters: Meters,
    /// Budgets of the sampled event signals.
    pub(crate) samplers: crate::events::Samplers,
}

impl Shared {
    #[inline]
    pub(crate) fn now(&self) -> Now {
        Now::from_duration(self.clock.now().saturating_duration_since(self.start))
    }

    /// Notes a time the door saw (cheap: one load, a store once a second).
    #[inline]
    pub(crate) fn saw(&self, now: Now) {
        let s = now.secs();
        if s > self.seen_secs.load(Ordering::Relaxed) {
            self.seen_secs.store(s, Ordering::Relaxed);
        }
    }

    /// Whole seconds, as of the door's latest check (the clock itself when
    /// the door has seen nothing yet). For coarse windows only.
    #[inline]
    pub(crate) fn recent_secs(&self) -> u64 {
        match self.seen_secs.load(Ordering::Relaxed) {
            0 => self.now().secs(),
            s => s,
        }
    }

    /// The wall clock now.
    pub(crate) fn wall(&self) -> SystemTime {
        SystemTime::from(self.clock.wall())
    }

    /// Persistence records queued and not yet written.
    pub(crate) fn journal_backlog(&self) -> u32 {
        self.persist
            .as_ref()
            .map_or(0, crate::persist::Persist::backlog)
    }

    /// The last persistence failure, while the last write failed.
    pub(crate) fn last_persist_error(&self) -> Option<std::io::ErrorKind> {
        self.persist
            .as_ref()
            .and_then(crate::persist::Persist::last_error)
    }

    /// The offence history of a key.
    pub(crate) fn offender_record(
        &self,
        key: &BanKey,
        now_secs: u64,
    ) -> Option<crate::admin::OffenderRecord> {
        let o = self.bans.offender(key, now_secs)?;
        Some(crate::admin::OffenderRecord {
            offences: o.score,
            last: self.wall_at(o.last),
        })
    }

    /// Whether an address is flagged as shared.
    pub(crate) fn is_shared_source(&self, addr: IpAddr, now_secs: u64) -> bool {
        self.sources.is_shared(addr, now_secs)
    }

    /// Reports a ban an insert took out: evicted from a full table (journaled
    /// as removed), or expired and reclaimed.
    fn report_gone(&self, gone: Option<(BanKey, bool)>) {
        let Some((key, evicted)) = gone else {
            return;
        };
        if evicted {
            self.log_removed(&[key]);
        }
        self.forget_shared(&[key]);
        Emit {
            subject: subject_of_key(&key),
            ..Emit::new(if evicted {
                events::signals::BAN_EVICTED
            } else {
                events::signals::BAN_EXPIRED
            })
        }
        .send(self);
    }

    /// Bookkeeping after bans were lifted outside `lift` (persistence).
    pub(crate) fn after_lift(&self, lifted: &[crate::bans::view::Held]) {
        let keys: Vec<BanKey> = lifted.iter().map(|h| h.key).collect();
        self.log_removed(&keys);
        self.forget_shared(&keys);
    }

    /// Whether an immune allow-list entry covers `cidr`.
    pub(crate) fn immune_covers(&self, cidr: &Cidr) -> bool {
        self.allow.with(|set| {
            set.find_covering_map(cidr, |k| (*k == AllowKind::Immune).then_some(()))
                .is_some()
        })
    }

    #[inline]
    pub(crate) fn posture(&self) -> Posture {
        if self.posture.load(Ordering::Relaxed) == 0 {
            Posture::Normal
        } else {
            Posture::Strict
        }
    }

    /// What one admission costs at the door: 1, or the strict divisor.
    #[inline]
    pub(crate) fn door_divisor(&self) -> u32 {
        if self.posture.load(Ordering::Relaxed) == 0 {
            1
        } else {
            self.strict_divisor
        }
    }

    /// Adds a ban and reports it.
    pub(crate) fn ban(
        &self,
        spec: &BanSpec,
        policy: Option<DurationPolicy>,
    ) -> Result<BanId, BouncerError> {
        let allow = self.allow.load();
        let guards = Guards {
            immune: &allow,
            proxies: &self.proxies,
        };
        let planned = self.bans.ban_plan(spec, &guards, self.now(), policy);
        let (result, plan) = match planned {
            Ok((id, plan, gone, own)) => {
                self.report_gone(gone);
                meter!(self.meters, bans_added);
                self.record_ban(&spec.key, id, own.as_ref());
                (Ok(id), plan)
            }
            Err(e) => (Err(e), None),
        };
        if let Some(plan) = plan {
            self.escalate(plan, spec.actor, spec.reason);
        }
        if self.sink.is_some() {
            let signal = match &result {
                Ok(_) => Some(events::signals::BAN_ADDED),
                Err(BouncerError::BanTableFull { .. }) => Some(events::signals::BAN_TABLE_FULL),
                Err(BouncerError::AllowListed { .. } | BouncerError::TrustedProxyTarget)
                    if spec.actor.is_automated() =>
                {
                    Some(events::signals::BAN_REFUSED_ALLOWLISTED)
                }
                Err(_) => None,
            };
            if let Some(signal) = signal {
                let reference = match &result {
                    Ok(id) => self.reference(id.get()),
                    Err(_) => Reference::new(0),
                };
                Emit {
                    actor: spec.actor,
                    reason: spec.reason,
                    subject: subject_of_key(&spec.key),
                    reference,
                    evidence: spec.evidence,
                    ..Emit::new(signal)
                }
                .send(self);
            }
        }
        result
    }
}

impl Shared {
    /// Escalates a parent prefix whose children are due, and the next level
    /// up when that one is due too. Refused, with an event, over an
    /// allow-list entry, a trusted proxy, or an address flagged as shared.
    fn escalate(&self, mut plan: Plan, actor: Actor, reason: Reason) {
        // The ladder has at most a few levels; the bound is a backstop.
        for _ in 0..8 {
            let now = self.now();
            let secs = now.secs();
            let parent = plan.parent;
            let subject = events::Subject {
                prefix: Some(parent),
                ..events::Subject::default()
            };
            let blocked = self.allow.with(|s| s.overlaps(&parent))
                || self.proxies.overlaps(&parent)
                || self.sources.any_within(&parent, secs);
            if blocked {
                self.bans.refuse_escalation(&plan, secs);
                Emit {
                    actor,
                    reason,
                    subject,
                    mode: crate::strikes::Mode::Observe,
                    ..Emit::new(events::signals::BAN_ESCALATED)
                }
                .send(self);
                return;
            }
            let duration = match self.bans.escalated_secs(&plan) {
                Some(s) => BanDuration::Fixed(Duration::from_secs(s)),
                None if actor.may_ban_permanently() => BanDuration::Permanent,
                None => BanDuration::Fixed(Duration::from_secs(self.bans.max_secs())),
            };
            let parent_until = match duration {
                BanDuration::Fixed(d) => {
                    u32::try_from(secs.saturating_add(crate::time::ceil_secs(d)))
                        .unwrap_or(u32::MAX)
                }
                _ => 0,
            };
            let spec = BanSpec {
                duration,
                ..BanSpec::prefix(parent).by(actor).because(reason)
            };
            let allow = self.allow.load();
            let guards = Guards {
                immune: &allow,
                proxies: &self.proxies,
            };
            match self.bans.ban_plan(&spec, &guards, now, None) {
                Ok((id, next, gone, own)) => {
                    self.report_gone(gone);
                    self.record_ban(&BanKey::Prefix(parent), id, own.as_ref());
                    let folded = self.bans.fold(&plan.children, parent_until);
                    self.record_folded(&folded);
                    meter!(self.meters, bans_escalated);
                    Emit {
                        actor,
                        reason,
                        subject,
                        reference: self.reference(id.get()),
                        ..Emit::new(events::signals::BAN_ESCALATED)
                    }
                    .send(self);
                    match next {
                        Some(n) => plan = n,
                        None => return,
                    }
                }
                Err(_) => {
                    self.bans.refuse_escalation(&plan, secs);
                    return;
                }
            }
        }
    }
}

/// The subject of an event about one ban key.
pub(crate) fn subject_of_key(key: &BanKey) -> events::Subject {
    let mut s = events::Subject::default();
    match *key {
        BanKey::Address(a) => s.source = Some(a),
        BanKey::Prefix(c) => s.prefix = Some(c),
        BanKey::Session(k) => s.session = Some(k),
        BanKey::Account(k) => s.account = Some(k),
        BanKey::Tenant(k) => s.tenant = Some(k),
        BanKey::Fingerprint(k) => s.fingerprint = Some(k),
        BanKey::FingerprintIn(k, c) => {
            s.fingerprint = Some(k);
            s.prefix = Some(c);
        }
    }
    s
}

struct Inner {
    shared: Arc<Shared>,
    shards: Box<[Arc<Shard>]>,
    capacity: Capacity,
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.shared.maintenance.stop();
        // Best effort: what is queued reaches the store.
        let _ = self.shared.persist_flush(self.shared.now(), true);
    }
}

/// The gate itself. One `Bouncer` serves a whole process; clones share all
/// state. Every method takes `&self` and may be called from any thread.
///
/// # Examples
///
/// ```
/// use bouncer_io::{Bouncer, Reason, RequestId};
///
/// let bouncer = Bouncer::new();
/// bouncer.ban("198.51.100.9".parse::<std::net::IpAddr>()?)?;
/// assert!(bouncer.door("198.51.100.9".parse()?).is_err());   // refused at the door
///
/// let conn = bouncer.door("203.0.113.7".parse()?)?;
/// let mut request = conn.request(RequestId(1))?;
/// assert!(request.checkpoint().is_pass());
/// bouncer.revoke(conn.conn(), Reason::ADMIN)?;               // from any thread
/// assert!(request.checkpoint().is_deny());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone)]
pub struct Bouncer {
    inner: Arc<Inner>,
}

impl Default for Bouncer {
    fn default() -> Self {
        Bouncer::new()
    }
}

impl fmt::Debug for Bouncer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Bouncer")
            .field("shards", &self.inner.shards.len())
            .field("capacity", &self.inner.capacity)
            .finish_non_exhaustive()
    }
}

thread_local! {
    static SHARD_HINT: StdCell<u32> = const { StdCell::new(u32::MAX) };
}

static NEXT_HINT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// This thread's preferred shard: assigned round robin on first use.
#[inline]
fn shard_hint() -> u32 {
    SHARD_HINT
        .try_with(|h| {
            let v = h.get();
            if v != u32::MAX {
                return v;
            }
            let v = NEXT_HINT.fetch_add(1, std::sync::atomic::Ordering::Relaxed) & 0x7fff_ffff;
            h.set(v);
            v
        })
        .unwrap_or(0)
}

impl Bouncer {
    /// The state every shard reads.
    pub(crate) fn shared(&self) -> &Shared {
        &self.inner.shared
    }

    /// The shards.
    #[cfg(feature = "metrics")]
    pub(crate) fn shards(&self) -> &[Arc<Shard>] {
        &self.inner.shards
    }

    /// A bouncer with safe defaults: 65,536 tickets, 1,048,576 ban entries,
    /// 65,536 revocation entries, automatic keys at IPv4 /32 and /24 and IPv6
    /// /64, /56, /48, door budgets of 20 connections per second (burst 40)
    /// and 64 concurrent per address, local heuristics in observe mode, no
    /// event sink, no ejector, no maintainer thread.
    ///
    /// # Examples
    ///
    /// ```
    /// let bouncer = bouncer_io::Bouncer::new();
    /// let same_gate = bouncer.clone();         // shares every table
    /// # let _ = same_gate;
    /// ```
    #[must_use]
    pub fn new() -> Bouncer {
        // The default configuration is valid by construction, and spawns no
        // thread, so building it cannot fail.
        BouncerBuilder::default().build_with(PrefixSet::empty())
    }

    /// Starts a [`BouncerBuilder`] with the same defaults as `new`.
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::{Bouncer, Cidr};
    /// let bouncer = Bouncer::builder()
    ///     .tickets(262_144)
    ///     .trusted_proxies(&["10.0.0.0/8".parse::<Cidr>()?])
    ///     .try_build()?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn builder() -> BouncerBuilder {
        BouncerBuilder::default()
    }

    /// Checkpoint B1, before a byte is read: trusted proxy, allow list, ban
    /// memory, and door budgets, from the peer address alone. On success it
    /// issues a connection ticket.
    ///
    /// Reads the clock once and numbers the connection itself; use
    /// [`door_at`](Self::door_at) when the transport already has both.
    ///
    /// # Errors
    ///
    /// A [`Refusal`], for logs and metrics only: the peer must see an
    /// abortive close and nothing else, whatever the reason.
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::{Bouncer, Refusal};
    /// let bouncer = Bouncer::new();
    /// bouncer.ban("203.0.113.7".parse::<std::net::IpAddr>()?)?;
    /// // IPv4-mapped IPv6 is the same client as plain IPv4.
    /// assert!(matches!(bouncer.door("::ffff:203.0.113.7".parse()?), Err(Refusal::Banned { .. })));
    /// assert!(bouncer.door("192.0.2.44".parse()?).is_ok());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[inline]
    pub fn door(&self, peer: IpAddr) -> Result<Ticket, Refusal> {
        let now = self.inner.shared.now();
        self.enter(None, peer, Provenance::Socket, now)
    }

    /// The door for transports that number their connections and read the
    /// time at accept.
    ///
    /// # Errors
    ///
    /// As [`door`](Self::door).
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::{Bouncer, ConnId, Provenance};
    /// let bouncer = Bouncer::new();
    /// let now = bouncer.now();
    /// let ticket = bouncer.door_at(ConnId(41), "192.0.2.10".parse()?, Provenance::Socket, now)?;
    /// assert_eq!(ticket.conn(), ConnId(41));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[inline]
    pub fn door_at(
        &self,
        conn: ConnId,
        peer: IpAddr,
        provenance: Provenance,
        now: Now,
    ) -> Result<Ticket, Refusal> {
        self.enter(Some(conn), peer, provenance, now)
    }

    fn enter(
        &self,
        conn: Option<ConnId>,
        peer: IpAddr,
        provenance: Provenance,
        now: Now,
    ) -> Result<Ticket, Refusal> {
        let shared = &self.inner.shared;
        let peer = normalize(peer);
        shared.saw(now);
        let mut hashes = crate::bans::AddrHashes::new(shared.bans.hasher(), peer);
        let (mut flags, source, charge) =
            match shared.judge_hashed(peer, provenance, now, &mut hashes) {
                Judgement::Admit { immune, exempt } => {
                    (if immune { F_IMMUNE } else { 0 }, Some(peer), !exempt)
                }
                Judgement::ProxyHop => (F_PROXY_HOP, None, false),
                Judgement::Refuse(r) => {
                    self.report_refusal(r, peer);
                    return Err(r);
                }
            };
        if charge {
            if let Err(over) = shared
                .budgets
                .admit_hashed(&mut hashes, now, shared.door_divisor())
            {
                let r = Refusal::OverBudget {
                    retry_after: over.0,
                };
                self.report_refusal(r, peer);
                return Err(r);
            }
            if shared.budgets.has_concurrency() {
                flags |= F_CHARGED;
            }
        }
        flags |= provenance.code() << crate::registry::PROVENANCE_SHIFT;
        let shards = &self.inner.shards;
        let first = shard_hint() as usize & (shards.len() - 1);
        let shard = &shards[first];
        let id = conn.map(|c| c.0);
        let issued = Ticket::issue(
            shard,
            first,
            Issue {
                kind: TicketKind::Connection,
                flags,
                conn: id,
                source,
                request: None,
                parent: None,
            },
        );
        match issued {
            Some(t) => {
                meter!(shard.meters, admitted);
                Ok(t)
            }
            None => {
                if charge {
                    shared.budgets.release_connection(Some(peer), now);
                }
                self.report_refusal(Refusal::RegistryFull, peer);
                Err(Refusal::RegistryFull)
            }
        }
    }

    #[cold]
    fn report_refusal(&self, refusal: Refusal, peer: IpAddr) {
        let shared = &self.inner.shared;
        match refusal {
            Refusal::Banned { .. } => meter!(shared.meters, refused_ban),
            Refusal::OverBudget { .. } => meter!(shared.meters, refused_budget),
            Refusal::RegistryFull => meter!(shared.meters, refused_registry_full),
            Refusal::Posture => meter!(shared.meters, refused_posture),
        }
        if shared.sink.is_none() {
            return;
        }
        let (signal, reference) = match refusal {
            Refusal::Banned { reference } => (events::signals::DOOR_REFUSED_BAN, reference),
            Refusal::OverBudget { .. } => (events::signals::DOOR_REFUSED_BUDGET, Reference::new(0)),
            Refusal::RegistryFull => (
                events::signals::DOOR_REFUSED_REGISTRY_FULL,
                Reference::new(0),
            ),
            _ => return,
        };
        let subject = events::Subject {
            source: Some(peer),
            ..events::Subject::default()
        };
        Emit {
            subject,
            reference,
            ..Emit::new(signal)
        }
        .send(shared);
    }

    /// Adds a ban. An address or `Cidr` converts directly (timed by the
    /// duration policy, actor [`Actor::App`](crate::Actor::App)); a
    /// [`BanSpec`] sets the rest. Takes effect at the next door check on every
    /// thread; connections already admitted are not touched (use
    /// [`apply`](Self::apply) with `Directive::revoke_and_ban` for that).
    ///
    /// # Errors
    ///
    /// `AllowListed`, `TrustedProxyTarget`, `InvalidPrefix` (also for an
    /// automated actor at a length that is not automatic), `InvalidTarget`,
    /// `PermanentNotAllowed`, `InvalidDuration`, `BanTableFull`.
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::{Bouncer, Cidr};
    /// let bouncer = Bouncer::new();
    /// bouncer.ban("203.0.113.0/24".parse::<Cidr>()?)?;
    /// bouncer.ban("2001:db8:7::/48".parse::<Cidr>()?)?;
    /// assert!(bouncer.door("203.0.113.50".parse()?).is_err());
    /// assert!(bouncer.door("2001:db8:7:1::9".parse()?).is_err());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn ban(&self, spec: impl Into<BanSpec>) -> Result<BanId, BouncerError> {
        self.inner.shared.ban(&spec.into(), None)
    }

    /// Removes the bans on exactly this key. A wider prefix ban that covers
    /// it is not lifted.
    ///
    /// # Errors
    ///
    /// `NotFound` when nothing was banned under this key; `InvalidPrefix`.
    ///
    /// # Examples
    ///
    /// ```
    /// let bouncer = bouncer_io::Bouncer::new();
    /// let addr: std::net::IpAddr = "198.51.100.9".parse()?;
    /// bouncer.ban(addr)?;
    /// bouncer.lift(addr)?;
    /// assert!(bouncer.door(addr).is_ok());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn lift(&self, spec: impl Into<LiftSpec>) -> Result<Lifted, BouncerError> {
        let shared = &self.inner.shared;
        let spec = spec.into();
        let result = if shared.ledger.is_some() {
            shared.lift_shared(&spec)
        } else {
            let r = shared.bans.lift(&spec);
            if r.is_ok() {
                shared.log_lift(&spec.key, spec.actor);
            }
            r
        };
        if let Ok(l) = &result {
            meter!(shared.meters, bans_lifted, l.removed);
            Emit {
                actor: spec.actor,
                reason: spec.reason,
                subject: subject_of_key(&spec.key),
                reference: shared.reference(l.tombstone.get()),
                ..Emit::new(events::signals::BAN_LIFTED)
            }
            .send(shared);
        }
        result
    }

    /// Stops what is running now. Every ticket that carries the target key is
    /// denied at its next checkpoint; a checkpoint that begins after `revoke`
    /// has returned on any thread cannot miss it. The actor is
    /// [`Actor::App`](crate::Actor::App), the mode `AtCheckpoint`, a revoked
    /// request takes its connection with it, and no ban is added; for any
    /// other choice use [`apply`](Self::apply).
    ///
    /// A revocation is not a ban: it ends running work. A connection that
    /// comes back is judged at the door as usual unless a ban was also set.
    ///
    /// # Errors
    ///
    /// `RevocationTableFull`: the revocation still reached every live
    /// matching ticket through a direct sweep before the error returned.
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::{AccountKey, Bouncer, Reason, RequestId};
    ///
    /// let bouncer = Bouncer::new();
    /// let conn = bouncer.door("192.0.2.5".parse()?)?;
    /// let mut request = conn.request(RequestId(1))?;
    /// assert!(request.bind_account(AccountKey(42)).is_pass());
    /// // Password changed: every running request of this account stops.
    /// bouncer.revoke(AccountKey(42), Reason::PASSWORD_CHANGED)?;
    /// assert!(request.checkpoint().is_deny());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn revoke(
        &self,
        target: impl Into<Target>,
        reason: Reason,
    ) -> Result<Revocation, BouncerError> {
        self.revoke_with(
            &target.into(),
            Actor::App,
            reason,
            RevokeMode::AtCheckpoint,
            false,
            DenialCode::Forbidden,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn revoke_with(
        &self,
        target: &Target,
        actor: Actor,
        reason: Reason,
        mode: RevokeMode,
        keep_connection: bool,
        code: DenialCode,
        confidence: Option<u8>,
    ) -> Result<Revocation, BouncerError> {
        let shared = &self.inner.shared;
        let target = match *target {
            Target::Source(c) => {
                if actor.is_automated() && shared.immune_covers(&c) {
                    return Err(BouncerError::AllowListed {
                        key: BanKey::Prefix(c),
                    });
                }
                if shared.proxies.covers(&c) {
                    return Err(BouncerError::TrustedProxyTarget);
                }
                Target::Source(c)
            }
            t => t,
        };
        if actor.is_automated() {
            if let Some(rate) = &shared.revocation_rate {
                let now_d = Duration::from_nanos(shared.now().as_nanos());
                if rate.check_at(now_d).is_deny() {
                    // A revocation storm: the revocation still applies (they are
                    // security actions); the excess is reported.
                    Emit {
                        actor,
                        reason,
                        mode: crate::strikes::Mode::Observe,
                        ..Emit::new(events::signals::REVOKE_APPLIED)
                    }
                    .send(shared);
                }
            }
        }
        let record = Record {
            key: target_key(&target),
            code,
            keep_connection,
            actor: actor.kind(),
            reason,
        };
        let reference = shared.reference(shared.epoch.next() ^ 0x5eed);
        let epoch = match shared.revocations.insert(&record, &shared.epoch) {
            Ok(e) => e,
            Err(()) => {
                maintain::direct_sweep(shared, &target, code, keep_connection);
                shared.epoch.bump();
                meter!(shared.meters, revocations);
                shared.log_revoke(&target, mode, keep_connection, code, actor, reason);
                maintain::report_revocation(shared, &target, actor, reason, reference, confidence);
                return Err(BouncerError::RevocationTableFull {
                    capacity: shared.revocations.capacity(),
                });
            }
        };
        let mut matched_live = None;
        if mode == RevokeMode::EjectNow {
            if shared.maintenance.has_thread() {
                shared.maintenance.request_sweep();
            } else {
                matched_live = Some(maintain::sweep_all(shared, epoch).0);
            }
        } else {
            // Schedule cleanup of the entry.
            shared.maintenance.wake();
        }
        meter!(shared.meters, revocations);
        shared.log_revoke(&target, mode, keep_connection, code, actor, reason);
        maintain::report_revocation(shared, &target, actor, reason, reference, confidence);
        Ok(Revocation {
            epoch,
            reference,
            matched_live,
        })
    }

    /// The single entry for decisions made elsewhere: the security signals
    /// policy, sentinel-sec, the gates, administrators, and other nodes. Safe
    /// from any thread.
    ///
    /// Rules that hold whatever the directive says: automated actors never
    /// touch allow-listed keys or trusted proxies; a directive below the
    /// Medium confidence band (under 30) cannot ban by itself and is applied
    /// as a throttle (`Applied::downgraded`); every applied directive is an
    /// event naming its cause.
    ///
    /// # Errors
    ///
    /// As [`ban`](Self::ban) and [`revoke`](Self::revoke); `InvalidTarget`
    /// when the action does not fit the target (a lift of a connection id, a
    /// throttle of a session at this version).
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::{Actor, Bouncer, Directive, Reason};
    /// use std::time::Duration;
    ///
    /// let bouncer = Bouncer::new();
    /// let applied = bouncer.apply(
    ///     Directive::ban("198.51.100.77".parse::<std::net::IpAddr>()?)
    ///         .by(Actor::Policy(12))
    ///         .because(Reason::POLICY)
    ///         .confidence(20),                              // too low to ban by itself
    /// )?;
    /// assert!(applied.downgraded && applied.throttled && applied.ban.is_none());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn apply(&self, directive: Directive) -> Result<Applied, BouncerError> {
        let d = directive;
        // Below the Medium band nothing bans by itself; a shared address
        // (likely a NAT) is banned only by an administrator, the
        // application, a gate, sentinel, or a confident policy.
        let low = d.confidence.is_some_and(|c| c < 30) || self.shared_target(&d);
        let code = d.deny_with.unwrap_or(DenialCode::Forbidden);
        let mut applied = Applied::default();
        match d.action {
            Action::Throttle { factor, duration } => {
                self.throttle(&d.target, factor, duration)?;
                applied.throttled = true;
            }
            Action::Ban(duration) => {
                if low {
                    self.throttle(&d.target, 4, downgrade_duration(duration))?;
                    applied.throttled = true;
                    applied.downgraded = true;
                } else {
                    self.ban_target(&d, duration, &mut applied)?;
                }
            }
            Action::Revoke(mode) => {
                applied.revocation = Some(self.revoke_with(
                    &d.target,
                    d.actor,
                    d.reason,
                    mode,
                    d.keep_connection,
                    code,
                    d.confidence,
                )?);
            }
            Action::RevokeAndBan(mode, duration) => {
                // Ban first, while the tickets that carry the keys are live.
                if low {
                    self.throttle(&d.target, 4, downgrade_duration(duration))
                        .ok();
                    applied.throttled = true;
                    applied.downgraded = true;
                } else {
                    self.ban_target(&d, duration, &mut applied)?;
                }
                applied.revocation = Some(self.revoke_with(
                    &d.target,
                    d.actor,
                    d.reason,
                    mode,
                    d.keep_connection,
                    code,
                    d.confidence,
                )?);
            }
            Action::Lift => {
                let key = match d.target {
                    Target::Source(c) => host_or_prefix(c),
                    Target::Session(k) => BanKey::Session(k),
                    Target::Account(k) => BanKey::Account(k),
                    Target::Tenant(k) => BanKey::Tenant(k),
                    Target::Fingerprint(k) => BanKey::Fingerprint(k),
                    _ => return Err(BouncerError::InvalidTarget),
                };
                applied.lifted = Some(self.lift(LiftSpec::key(key).by(d.actor).because(d.reason))?);
            }
        }
        Ok(applied)
    }

    /// Whether `d` would ban a shared address on automation's word alone.
    fn shared_target(&self, d: &Directive) -> bool {
        let Target::Source(c) = d.target else {
            return false;
        };
        let weak = match d.actor {
            Actor::Local | Actor::Channel(_) => true,
            Actor::Policy(_) => d.confidence.is_none_or(|c| c < 70),
            _ => false,
        };
        let client_len = match c.family() {
            crate::keys::Family::V4 => 32,
            crate::keys::Family::V6 => 64,
        };
        weak && c.len() >= client_len && {
            let shared = &self.inner.shared;
            shared.sources.is_shared(c.network(), shared.now().secs())
        }
    }

    fn ban_target(
        &self,
        d: &Directive,
        duration: BanDuration,
        applied: &mut Applied,
    ) -> Result<(), BouncerError> {
        let shared = &self.inner.shared;
        let spec = |key: BanKey| {
            let s = BanSpec::key(key)
                .by(d.actor)
                .because(d.reason)
                .evidence(d.evidence);
            BanSpec { duration, ..s }
        };
        let mut record = |r: Result<BanId, BouncerError>| -> Result<(), BouncerError> {
            let id = r?;
            applied.ban.get_or_insert(id);
            applied.bans += 1;
            Ok(())
        };
        match d.target {
            Target::Source(c) => record(shared.ban(&spec(host_or_prefix(c)), None)),
            Target::Session(k) => record(shared.ban(&spec(BanKey::Session(k)), None)),
            Target::Account(k) => record(shared.ban(&spec(BanKey::Account(k)), None)),
            Target::Tenant(k) => record(shared.ban(&spec(BanKey::Tenant(k)), None)),
            Target::Fingerprint(k) => record(shared.ban(&spec(BanKey::Fingerprint(k)), None)),
            Target::Connection(_) | Target::Request(_) => {
                let keys = d.ban_keys.unwrap_or(BanKeys::SOURCE);
                let mut found = false;
                for cell in shared.registry.cells.iter() {
                    if cell.state.load(Ordering::Acquire) & F_LIVE == 0
                        || !maintain::matches_target(cell, &d.target)
                    {
                        continue;
                    }
                    found = true;
                    let s = subject_of(cell);
                    let mut wanted: Vec<BanKey> = Vec::new();
                    if keys.contains(BanKeys::SOURCE) {
                        if let Some(a) = s.source {
                            wanted.push(BanKey::Address(a));
                        }
                    }
                    if keys.contains(BanKeys::FINGERPRINT_IN_PREFIX) {
                        if let (Some(fp), Some(a)) = (s.fingerprint, s.source) {
                            wanted.push(BanKey::FingerprintIn(fp, shared.bans.address_prefix(a)));
                        }
                    }
                    if keys.contains(BanKeys::SESSION) {
                        if let Some(k) = s.session {
                            wanted.push(BanKey::Session(k));
                        }
                    }
                    if keys.contains(BanKeys::ACCOUNT) {
                        if let Some(k) = s.account {
                            wanted.push(BanKey::Account(k));
                        }
                    }
                    if keys.contains(BanKeys::TENANT) {
                        if let Some(k) = s.tenant {
                            wanted.push(BanKey::Tenant(k));
                        }
                    }
                    for key in wanted {
                        record(shared.ban(&spec(key), None))?;
                    }
                }
                if !found {
                    return Ok(());
                }
                Ok(())
            }
        }
    }

    fn throttle(
        &self,
        target: &Target,
        factor: u8,
        duration: Duration,
    ) -> Result<(), BouncerError> {
        let shared = &self.inner.shared;
        let now = shared.now().secs();
        let until = now.saturating_add(crate::time::ceil_secs(duration).max(1));
        let factor = factor.clamp(2, 16);
        let identity = |kind: IdentityKind, k0: u64, k1: u64| {
            shared
                .identity
                .throttle(IdentityKey { kind, k0, k1 }, factor, until, now);
        };
        match *target {
            Target::Source(c) => {
                if shared.proxies.covers(&c) {
                    return Err(BouncerError::TrustedProxyTarget);
                }
                let cidr = match c.family() {
                    crate::keys::Family::V6 if c.len() > 64 => c.parent(64).unwrap_or(c),
                    _ => c,
                };
                shared.budgets.throttle(&cidr, factor, until, now);
            }
            Target::Session(k) => {
                let (k0, k1) = k.words();
                identity(IdentityKind::Session, k0, k1);
            }
            Target::Account(k) => identity(IdentityKind::Account, (k.0 >> 64) as u64, k.0 as u64),
            Target::Tenant(k) => identity(IdentityKind::Tenant, 0, k.0),
            Target::Fingerprint(k) => {
                let (k0, k1) = k.words();
                identity(IdentityKind::Fingerprint, k0, k1);
            }
            Target::Connection(_) | Target::Request(_) => return Err(BouncerError::InvalidTarget),
        }
        Ok(())
    }

    /// Issues a request ticket under a connection held as a [`TicketTag`].
    ///
    /// # Errors
    ///
    /// `Stale` (released, or another bouncer's tag), `Revoked`,
    /// `RegistryFull`, `NotAConnectionTicket`.
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::{Bouncer, RequestId};
    /// let bouncer = Bouncer::new();
    /// let tag = bouncer.door("192.0.2.8".parse()?)?.into_tag();
    /// let request = bouncer.request(tag, RequestId(9))?;
    /// assert_eq!(request.conn(), bouncer.request(tag, RequestId(10))?.conn());
    /// # drop(request);
    /// bouncer.release(tag);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn request(&self, connection: TicketTag, id: RequestId) -> Result<Ticket, BouncerError> {
        let shards = &self.inner.shards;
        let shard = &shards[shard_hint() as usize & (shards.len() - 1)];
        ticket::issue_request(shard, connection.index(), connection.generation(), id)
    }

    /// Checkpoint B6b for a transport: call it before every socket write.
    /// Pass the tag of the request whose response is being written when the
    /// transport knows it, or the connection's tag otherwise (which also
    /// checks the request most recently issued on it). A stale or unknown tag
    /// is denied (fail closed).
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::{Bouncer, Reason, Verdict};
    /// let bouncer = Bouncer::new();
    /// let ticket = bouncer.door("192.0.2.9".parse()?)?;
    /// let conn = ticket.conn();
    /// let tag = ticket.into_tag();                   // the transport keeps only this
    /// assert!(bouncer.egress(tag).is_pass());
    /// bouncer.revoke(conn, Reason::ADMIN)?;
    /// assert!(matches!(bouncer.egress(tag), Verdict::Deny(_)));
    /// bouncer.release(tag);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[inline]
    pub fn egress(&self, ticket: TicketTag) -> Verdict {
        let shared = &self.inner.shared;
        ticket::egress(shared, &shared.epoch, ticket)
    }

    /// Releases a connection ticket held as a tag. Live request tickets under
    /// it are denied from then on. Returns `false` when the tag was already
    /// released, is stale, or is not a detached connection ticket.
    ///
    /// # Examples
    ///
    /// ```
    /// let bouncer = bouncer_io::Bouncer::new();
    /// let tag = bouncer.door("192.0.2.12".parse()?)?.into_tag();
    /// assert!(bouncer.release(tag));
    /// assert!(!bouncer.release(tag));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn release(&self, connection: TicketTag) -> bool {
        let shared = &self.inner.shared;
        let index = connection.index();
        if index as usize >= shared.registry.cells.len() {
            return false;
        }
        let st = shared.registry.cell(index).state.load(Ordering::Acquire);
        if generation(st) != connection.generation()
            || st & F_DETACHED == 0
            || st & 0xff != KIND_CONNECTION
        {
            return false;
        }
        let shard = &self.inner.shards[shared.registry.shard_of(index) % self.inner.shards.len()];
        ticket::release_cell(shard, index, connection.generation())
    }

    /// Switches between [`Posture::Normal`] and [`Posture::Strict`]
    /// (lockdown).
    ///
    /// Strict divides the door budgets by
    /// [`strict_budget_divisor`](BouncerBuilder::strict_budget_divisor)
    /// and switches the strike kinds listed in
    /// [`Enforcement::strict`](crate::Enforcement::strict) from observe to
    /// enforce. Nothing already admitted is revoked unless
    /// [`strict_revokes_unauthenticated`](BouncerBuilder::strict_revokes_unauthenticated)
    /// is set; then every request ticket with no bound session is revoked.
    /// Refusing whole listeners during a lockdown is the transport's job.
    /// A change is reported as `bouncer.posture.changed`.
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::{Bouncer, Posture};
    /// let bouncer = Bouncer::new();
    /// bouncer.set_posture(Posture::Strict);
    /// assert_eq!(bouncer.posture(), Posture::Strict);
    /// bouncer.set_posture(Posture::Normal);
    /// ```
    pub fn set_posture(&self, posture: Posture) {
        let shared = &self.inner.shared;
        let code = u32::from(posture == Posture::Strict);
        if shared.posture.swap(code, Ordering::AcqRel) == code {
            return;
        }
        Emit {
            actor: Actor::App,
            reason: Reason::LOCKDOWN,
            ..Emit::new(events::signals::POSTURE_CHANGED)
        }
        .send(shared);
        if posture != Posture::Strict || !shared.strict_revokes_unauthenticated {
            return;
        }
        let mut any = false;
        for cell in shared.registry.cells.iter() {
            let st = cell.state.load(Ordering::Acquire);
            if st & F_LIVE == 0
                || st & 0xff != KIND_REQUEST
                || st & F_IMMUNE != 0
                || cell.present() & P_SESSION != 0
            {
                continue;
            }
            any |= mark_revoked(cell, generation(st), DenialCode::Unavailable);
        }
        if any {
            // Marked before the bump: a checkpoint that sees the new epoch
            // sees the flags.
            shared.epoch.bump();
            shared.maintenance.wake();
        }
    }

    /// The current posture.
    #[must_use]
    pub fn posture(&self) -> Posture {
        self.inner.shared.posture()
    }

    /// The per-datagram door for UDP: ban memory, then the rate budgets
    /// (no concurrency). `verified` says the source has proven it receives
    /// (a completed handshake, a returned cookie). An unverified source is
    /// never struck or banned, and is charged only at its prefix, because a
    /// UDP source address can be forged to frame a victim.
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::{Bouncer, DatagramVerdict};
    /// let bouncer = Bouncer::new();
    /// let verdict = bouncer.datagram("198.51.100.20".parse()?, false, bouncer.now());
    /// assert_eq!(verdict, DatagramVerdict::Accept);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn datagram(&self, source: IpAddr, verified: bool, now: Now) -> DatagramVerdict {
        let shared = &self.inner.shared;
        let source = normalize(source);
        match shared.judge(source, Provenance::Socket, now) {
            Judgement::ProxyHop => DatagramVerdict::Accept,
            Judgement::Refuse(_) => {
                meter!(shared.meters, refused_ban);
                DatagramVerdict::Drop
            }
            Judgement::Admit { exempt: true, .. } => DatagramVerdict::Accept,
            Judgement::Admit { .. } => {
                match shared
                    .budgets
                    .datagram(source, verified, now, shared.door_divisor())
                {
                    Ok(()) => DatagramVerdict::Accept,
                    Err(_) => {
                        meter!(shared.meters, refused_budget);
                        DatagramVerdict::Drop
                    }
                }
            }
        }
    }

    /// The bouncer's monotonic time base, for the `_at` functions.
    #[must_use]
    pub fn now(&self) -> Now {
        self.inner.shared.now()
    }

    /// Does a bounded amount of every pending job: eject-now sweeps, checks
    /// on tickets that have not crossed a checkpoint for `max_unchecked`
    /// (checked on their behalf; matching ones are ejected and reported as
    /// `checkpoint.missing`), and cleanup of revocation entries no live
    /// ticket needs. Returns when more work is due, or `None` when nothing is
    /// pending. Use it when your own worker drives maintenance; otherwise
    /// enable the parked thread with [`BouncerBuilder::maintainer`].
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::{AccountKey, Bouncer, Reason};
    /// let bouncer = Bouncer::new();
    /// bouncer.revoke(AccountKey(1), Reason::ADMIN)?;
    /// let report = bouncer.maintain(bouncer.now());
    /// assert_eq!(report.reclaimed, 1);          // no live ticket can need it
    /// assert_eq!(bouncer.maintain(bouncer.now()).next_due, None);
    /// # Ok::<(), bouncer_io::BouncerError>(())
    /// ```
    pub fn maintain(&self, now: Now) -> MaintenanceReport {
        maintain::run(&self.inner.shared, now)
    }

    /// The memory every table reserved at construction, and the entry limits.
    /// Memory never grows past these numbers.
    ///
    /// # Examples
    ///
    /// ```
    /// let cap = bouncer_io::Bouncer::builder().tickets(1024).ban_capacity(4096).try_build()?.capacity();
    /// assert!(cap.tickets >= 1024);
    /// assert_eq!(cap.bans, 4096);
    /// assert!(cap.total_bytes >= cap.table_bytes);
    /// # Ok::<(), bouncer_io::BouncerError>(())
    /// ```
    #[must_use]
    pub fn capacity(&self) -> Capacity {
        let shared = &self.inner.shared;
        let mut c = self.inner.capacity;
        c.table_bytes = shared.bans.table_bytes();
        c.total_bytes = c.table_bytes
            + shared.bans.admin_bytes()
            + shared.registry.bytes()
            + shared.allow.with(PrefixSet::bytes)
            + shared.proxies.bytes()
            + shared.revocations.bytes()
            + shared.budgets.bytes()
            + shared.identity.bytes()
            + shared.sources.bytes()
            + shared.counters.bytes()
            + shared.ledger.as_ref().map_or(0, |m| {
                m.lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .bytes()
            });
        c
    }
}

fn host_or_prefix(c: Cidr) -> BanKey {
    if c.len() == c.family().max_len() {
        BanKey::Address(c.network())
    } else {
        BanKey::Prefix(c)
    }
}

fn downgrade_duration(d: BanDuration) -> Duration {
    match d {
        BanDuration::Fixed(f) => f,
        _ => Duration::from_secs(600),
    }
}

/// Reserved memory and entry limits, from [`Bouncer::capacity`].
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Capacity {
    /// Tickets (connections plus in-flight requests).
    pub tickets: u32,
    /// Dynamic ban entries.
    pub bans: u32,
    /// Revocation entries.
    pub revocations: u32,
    /// Budget keys per tier.
    pub budget_keys: u32,
    /// Bytes of the dynamic ban table.
    pub table_bytes: u64,
    /// Bytes of every table together (on a node that shares, its ledger of
    /// each node's bans too, which grows with the bans it holds).
    pub total_bytes: u64,
}

/// Configuration for a [`Bouncer`]. Every setter is optional; `try_build`
/// validates everything at once and allocates every table.
///
/// # Examples
///
/// ```
/// use bouncer_io::{Bouncer, DurationPolicy, Enforcement, StrikeKind};
/// use std::time::Duration;
/// let bouncer = Bouncer::builder()
///     .durations(DurationPolicy::default().base(Duration::from_secs(900)).max(Duration::from_secs(86_400)))
///     .enforcement(Enforcement::observe_all().enforce(StrikeKind::ProxyViolation))
///     .ipv6_lengths(&[64, 48])
///     .try_build()?;
/// # Ok::<(), bouncer_io::BouncerError>(())
/// ```
#[must_use]
pub struct BouncerBuilder {
    tickets: u32,
    shards: Option<u16>,
    ban_capacity: u32,
    revocation_capacity: u32,
    ipv4_lengths: Vec<u8>,
    ipv6_lengths: Vec<u8>,
    durations: DurationPolicy,
    escalation: EscalationPolicy,
    allow: AllowList,
    trusted_proxies: Vec<Cidr>,
    budgets: Budgets,
    strikes: StrikeRules,
    enforcement: Enforcement,
    denials: DenialTable,
    sink: Option<Arc<dyn EventSink>>,
    ejector: Option<Arc<dyn Ejector>>,
    format: Option<Arc<dyn crate::format::DenialFormat>>,
    epoch: Option<Arc<RevocationEpoch>>,
    clock: Option<Arc<dyn Clock>>,
    seed: Option<[u8; 32]>,
    max_unchecked: Duration,
    maintainer: bool,
    revocation_rate_limit: u32,
    strict_budget_divisor: u8,
    strict_revokes_unauthenticated: bool,
    node: Option<NodeId>,
    persistence: Option<Box<dyn crate::persist::Persistence>>,
    mac_key: Option<[u8; 32]>,
    on_load_failure: crate::persist::LoadFailure,
    max_wall_jump: Duration,
    strict_wall_jump: bool,
    max_clock_skew: Duration,
    channel_import_rate: u32,
}

impl Default for BouncerBuilder {
    fn default() -> Self {
        BouncerBuilder {
            tickets: crate::DEFAULT_TICKETS,
            shards: None,
            ban_capacity: crate::DEFAULT_BAN_CAPACITY,
            revocation_capacity: crate::DEFAULT_REVOCATION_CAPACITY,
            ipv4_lengths: crate::DEFAULT_IPV4_LENGTHS.to_vec(),
            ipv6_lengths: crate::DEFAULT_IPV6_LENGTHS.to_vec(),
            durations: DurationPolicy::default(),
            escalation: EscalationPolicy::default(),
            allow: AllowList::new(),
            trusted_proxies: Vec::new(),
            budgets: Budgets::default(),
            strikes: StrikeRules::default(),
            enforcement: Enforcement::default(),
            denials: DenialTable::default(),
            sink: None,
            ejector: None,
            format: None,
            epoch: None,
            clock: None,
            seed: None,
            max_unchecked: Duration::from_secs(60),
            maintainer: false,
            revocation_rate_limit: 10_000,
            strict_budget_divisor: 2,
            strict_revokes_unauthenticated: false,
            node: None,
            persistence: None,
            mac_key: None,
            on_load_failure: crate::persist::LoadFailure::Refuse,
            max_wall_jump: Duration::from_secs(3600),
            strict_wall_jump: false,
            max_clock_skew: Duration::from_secs(300),
            channel_import_rate: 100_000,
        }
    }
}

impl fmt::Debug for BouncerBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BouncerBuilder")
            .field("tickets", &self.tickets)
            .field("shards", &self.shards)
            .field("ban_capacity", &self.ban_capacity)
            .field("revocation_capacity", &self.revocation_capacity)
            .field("ipv4_lengths", &self.ipv4_lengths)
            .field("ipv6_lengths", &self.ipv6_lengths)
            .field("maintainer", &self.maintainer)
            .finish_non_exhaustive()
    }
}

impl BouncerBuilder {
    /// Registry capacity: one ticket per connection and one per in-flight
    /// request, 128 bytes each (default 65,536).
    pub fn tickets(mut self, capacity: u32) -> Self {
        self.tickets = capacity;
        self
    }

    /// Registry shards, rounded down to a power of two and to at most the
    /// ticket count (default: one per core, at most 256).
    pub fn shards(mut self, count: u16) -> Self {
        self.shards = Some(count);
        self
    }

    /// Dynamic ban table entries (default 1,048,576).
    pub fn ban_capacity(mut self, entries: u32) -> Self {
        self.ban_capacity = entries;
        self
    }

    /// Revocation table entries (default 65,536).
    pub fn revocation_capacity(mut self, entries: u32) -> Self {
        self.revocation_capacity = entries;
        self
    }

    /// Automatic key lengths for IPv4; must include 32 (default `[32, 24]`).
    pub fn ipv4_lengths(mut self, lengths: &[u8]) -> Self {
        self.ipv4_lengths = lengths.to_vec();
        self
    }

    /// Automatic key lengths for IPv6; 128 is refused because one host
    /// controls its whole /64 (default `[64, 56, 48]`).
    pub fn ipv6_lengths(mut self, lengths: &[u8]) -> Self {
        self.ipv6_lengths = lengths.to_vec();
        self
    }

    /// How long automatic bans last.
    pub fn durations(mut self, policy: DurationPolicy) -> Self {
        self.durations = policy;
        self
    }

    /// Prefix escalation (default [`EscalationPolicy::default()`]).
    pub fn escalation(mut self, policy: EscalationPolicy) -> Self {
        self.escalation = policy;
        self
    }

    /// The allow list, compiled at build.
    pub fn allow(mut self, list: AllowList) -> Self {
        self.allow = list;
        self
    }

    /// Proxies whose PROXY and forwarded headers are believed; never banned,
    /// struck, or budgeted. Use the same list the transport uses.
    pub fn trusted_proxies(mut self, cidrs: &[Cidr]) -> Self {
        self.trusted_proxies = cidrs.to_vec();
        self
    }

    /// Door budgets ([`Budgets::off`] for none).
    pub fn budgets(mut self, budgets: Budgets) -> Self {
        self.budgets = budgets;
        self
    }

    /// Strike weights, windows, thresholds.
    pub fn strikes(mut self, rules: StrikeRules) -> Self {
        self.strikes = rules;
        self
    }

    /// Observe or enforce, per strike kind (default: observe every kind).
    pub fn enforcement(mut self, modes: Enforcement) -> Self {
        self.enforcement = modes;
        self
    }

    /// The fixed message and application code per denial code.
    pub fn denials(mut self, table: DenialTable) -> Self {
        self.denials = table;
        self
    }

    /// Where every event goes (the security signal bridge, audit).
    pub fn event_sink(mut self, sink: Arc<dyn EventSink>) -> Self {
        self.sink = Some(sink);
        self
    }

    /// How bouncer closes connections it is not holding (sweeps, idle
    /// checks, `deny_and_eject`).
    pub fn ejector(mut self, ejector: Arc<dyn Ejector>) -> Self {
        self.ejector = Some(ejector);
        self
    }

    /// The protocol formatter `deny_and_eject` uses (default `NoFormat`:
    /// close without a reply).
    pub fn denial_format(mut self, format: Arc<dyn crate::format::DenialFormat>) -> Self {
        self.format = Some(format);
        self
    }

    /// An epoch word owned by the security core, shared with other modules.
    pub fn epoch(mut self, epoch: Arc<RevocationEpoch>) -> Self {
        self.epoch = Some(epoch);
        self
    }

    /// The time source; a `clock_lib::ManualClock` in tests.
    pub fn clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = Some(clock);
        self
    }

    /// Fixed seeds for hashing, jitter, and references: tests and
    /// simulations only. Production seeds come from the operating system.
    pub fn seed(mut self, seed: [u8; 32]) -> Self {
        self.seed = Some(seed);
        self
    }

    /// How long a ticket may go without a checkpoint before maintenance
    /// checks it on its behalf (default 60 seconds).
    pub fn max_unchecked(mut self, idle: Duration) -> Self {
        self.max_unchecked = idle;
        self
    }

    /// Spawn one maintenance thread that parks until work is due (default
    /// `false`: call [`Bouncer::maintain`] yourself).
    pub fn maintainer(mut self, spawn: bool) -> Self {
        self.maintainer = spawn;
        self
    }

    /// Revocations per second accepted from automated actors before the
    /// excess is reported as a storm (default 10,000; they still apply).
    pub fn revocation_rate_limit(mut self, per_second: u32) -> Self {
        self.revocation_rate_limit = per_second;
        self
    }

    /// Where bans, lift tombstones, and offender memory survive restarts.
    /// State is loaded in `try_build`, before the first door check.
    pub fn persistence(mut self, store: Box<dyn crate::persist::Persistence>) -> Self {
        self.persistence = Some(store);
        self
    }

    /// The key of the keyed BLAKE3 MAC over the snapshot and journal, from
    /// the integrator's key store. Without it only CRC32C checks the bytes.
    pub fn mac_key(mut self, key: [u8; 32]) -> Self {
        self.mac_key = Some(key);
        self
    }

    /// What to do when persisted state is corrupt or tampered with (default
    /// [`LoadFailure::Refuse`](crate::LoadFailure::Refuse)).
    pub fn on_load_failure(mut self, policy: crate::persist::LoadFailure) -> Self {
        self.on_load_failure = policy;
        self
    }

    /// A wall-clock jump between save and load larger than this is reported
    /// (default 1 hour).
    pub fn max_wall_jump(mut self, jump: Duration) -> Self {
        self.max_wall_jump = jump;
        self
    }

    /// Keep bans across a forward jump past `max_wall_jump` (counting their
    /// time from the last save) instead of letting them expire (default
    /// `false`).
    pub fn strict_wall_jump(mut self, keep: bool) -> Self {
        self.strict_wall_jump = keep;
        self
    }

    /// Imported records stamped further in the future than this are refused
    /// (default 5 minutes).
    pub fn max_clock_skew(mut self, skew: Duration) -> Self {
        self.max_clock_skew = skew;
        self
    }

    /// This node's id, stamped on every record it exports; required for
    /// `export_delta`. 0 is refused at `try_build`.
    pub fn node(mut self, id: NodeId) -> Self {
        self.node = Some(id);
        self
    }

    /// How much [`Posture::Strict`] divides the door budgets by (default 2):
    /// each admission costs that many tokens and the concurrency limits
    /// shrink by it. Zero is refused at `try_build`.
    pub fn strict_budget_divisor(mut self, divisor: u8) -> Self {
        self.strict_budget_divisor = divisor;
        self
    }

    /// Whether entering [`Posture::Strict`] revokes every request ticket
    /// with no bound session (default `false`).
    pub fn strict_revokes_unauthenticated(mut self, revoke: bool) -> Self {
        self.strict_revokes_unauthenticated = revoke;
        self
    }

    /// Validates the configuration and allocates every table.
    ///
    /// # Errors
    ///
    /// [`BouncerError::Config`] naming the field and the accepted range;
    /// [`BouncerError::Spawn`] when the maintainer thread cannot start.
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::{Bouncer, BouncerError, ConfigProblem};
    /// let err = Bouncer::builder().ipv6_lengths(&[128]).try_build().unwrap_err();
    /// assert!(matches!(err, BouncerError::Config(e) if e.problem == ConfigProblem::HostBansForbidden));
    /// ```
    pub fn try_build(self) -> Result<Bouncer, BouncerError> {
        check_range(
            "tickets",
            u64::from(self.tickets),
            1,
            u64::from(MAX_TICKETS),
        )?;
        check_range(
            "ban_capacity",
            u64::from(self.ban_capacity),
            1,
            u64::from(MAX_BAN_CAPACITY),
        )?;
        check_range(
            "revocation_capacity",
            u64::from(self.revocation_capacity),
            1,
            u64::from(MAX_BAN_CAPACITY),
        )?;
        check_range(
            "revocation_rate_limit",
            u64::from(self.revocation_rate_limit),
            1,
            u64::from(u32::MAX),
        )?;
        if let Some(s) = self.shards {
            check_range("shards", u64::from(s), 1, u64::from(MAX_SHARDS))?;
        }
        if self.max_unchecked.is_zero() {
            return Err(ConfigError::new("max_unchecked", ConfigProblem::InvalidDuration).into());
        }
        if self.ipv4_lengths.is_empty()
            || self.ipv4_lengths.iter().any(|&l| l > 32)
            || !self.ipv4_lengths.contains(&32)
        {
            return Err(ConfigError::new("ipv4_lengths", ConfigProblem::InvalidLength).into());
        }
        if self.ipv6_lengths.contains(&128) {
            return Err(ConfigError::new("ipv6_lengths", ConfigProblem::HostBansForbidden).into());
        }
        if self.ipv6_lengths.is_empty() || self.ipv6_lengths.iter().any(|&l| l > 128) {
            return Err(ConfigError::new("ipv6_lengths", ConfigProblem::InvalidLength).into());
        }
        self.durations.validate("durations")?;
        self.escalation.validate()?;
        self.strikes.validate()?;
        self.denials.validate()?;
        self.budgets.validate()?;
        if self.node == Some(NodeId(0)) {
            return Err(ConfigError::new("node", ConfigProblem::TooSmall { min: 1 }).into());
        }
        if self.strict_budget_divisor == 0 {
            return Err(
                ConfigError::new("strict_budget_divisor", ConfigProblem::InvalidFactor).into(),
            );
        }
        if self.max_clock_skew.is_zero() {
            return Err(ConfigError::new("max_clock_skew", ConfigProblem::InvalidDuration).into());
        }
        let allow = self.allow.compile()?;
        let maintainer = self.maintainer;
        let (policy, jump, strict) = (
            self.on_load_failure,
            self.max_wall_jump,
            self.strict_wall_jump,
        );
        let bouncer = self.build_with(allow);
        bouncer.inner.shared.load_persisted(policy, jump, strict)?;
        if maintainer {
            maintain::spawn(&bouncer.inner.shared).map_err(BouncerError::Spawn)?;
        }
        Ok(bouncer)
    }

    /// Allocates every table from a validated configuration.
    fn build_with(mut self, allow: PrefixSet<AllowKind>) -> Bouncer {
        let seeds = match self.seed {
            Some(s) => Seeds::from_bytes(s),
            None => Seeds::random(),
        };
        let clock: Arc<dyn Clock> = match &self.clock {
            Some(c) => Arc::clone(c),
            None => Arc::new(SystemClock),
        };
        let mut v4 = self.ipv4_lengths.clone();
        v4.sort_unstable();
        v4.dedup();
        let mut v6 = self.ipv6_lengths.clone();
        v6.sort_unstable();
        v6.dedup();
        let proxies = PrefixSet::build(
            &self
                .trusted_proxies
                .iter()
                .map(|c| (*c, ()))
                .collect::<Vec<_>>(),
            |a, _| *a,
        );

        let wanted = u32::from(self.shards.unwrap_or_else(default_shards));
        let shard_count = prev_power_of_two(wanted.min(self.tickets).max(1));
        let per_shard = self.tickets.div_ceil(shard_count);
        let tickets = per_shard * shard_count;
        let epoch = self
            .epoch
            .clone()
            .unwrap_or_else(|| Arc::new(RevocationEpoch::new()));
        let mut rng = crate::hash::Rng::from_seed(seeds.rng ^ 0x0b0b);
        let derived = |rng: &mut crate::hash::Rng| HashKey::new(rng.next_u64(), rng.next_u64());
        // The table's key: one keyed hash of a prefix serves the ban lookup
        // and the door budgets.
        let budgets = DoorBudgets::new(&self.budgets, seeds.tables, self.tickets);
        let identity = IdentityBudgets::new(&self.budgets, derived(&mut rng), Now::default());
        let revocation_rate =
            rate_net::Quota::rate(self.revocation_rate_limit, Duration::from_secs(1))
                .ok()
                .map(rate_net::Gcra::new);

        let shared = Arc::new(Shared {
            start: clock.now(),
            start_wall: SystemTime::from(clock.wall()),
            node: self.node,
            persist: self
                .persistence
                .take()
                .map(|s| crate::persist::Persist::new(s, self.mac_key)),
            share: crate::share::Share::new(self.channel_import_rate),
            ledger: self
                .node
                .map(|_| std::sync::Mutex::new(crate::ledger::Ledger::new(self.ban_capacity))),
            max_clock_skew: self.max_clock_skew,
            clock,
            bans: BanMemory::new(
                self.ban_capacity,
                seeds.tables,
                &v4,
                &v6,
                self.durations,
                self.escalation,
                seeds.rng,
            ),
            allow_len: AtomicU32::new(allow.len() as u32),
            seen_secs: AtomicU64::new(0),
            allow: Published::new(allow),
            proxies,
            references: seeds.references,
            tickets_capacity: tickets,
            registry: Registry::new(shard_count, per_shard),
            epoch: Arc::clone(&epoch),
            revocations: Revocations::new(self.revocation_capacity, derived(&mut rng)),
            budgets,
            identity,
            sources: crate::sources::Sources::new(
                self.budgets.capacity_keys().min(65_536),
                derived(&mut rng),
            ),
            posture: AtomicU32::new(0),
            strict_divisor: u32::from(self.strict_budget_divisor.max(1)),
            strict_revokes_unauthenticated: self.strict_revokes_unauthenticated,
            strikes: self.strikes.clone(),
            counters: Counters::new(65_536, derived(&mut rng)),
            enforcement: self.enforcement,
            denials: self.denials.clone(),
            sink: self.sink.clone(),
            ejector: self.ejector.clone(),
            maintenance: Maintenance::new(self.max_unchecked),
            revocation_rate,
            format: self
                .format
                .clone()
                .unwrap_or_else(|| Arc::new(crate::format::NoFormat)),
            meters: Meters::new(),
            samplers: crate::events::Samplers::default(),
        });
        let shards: Box<[Arc<Shard>]> = (0..shard_count)
            .map(|_| {
                Arc::new(Shard {
                    epoch: Arc::clone(&epoch),
                    shared: Arc::clone(&shared),
                    meters: Meters::new(),
                })
            })
            .collect();
        let capacity = Capacity {
            tickets,
            bans: shared.bans.capacity(),
            revocations: shared.revocations.capacity(),
            budget_keys: shared.budgets.capacity(),
            table_bytes: 0,
            total_bytes: 0,
        };
        if let Some(node) = shared.node {
            shared.bans.set_node(node.0);
        }
        Bouncer {
            inner: Arc::new(Inner {
                shared,
                shards,
                capacity,
            }),
        }
    }
}

fn check_range(field: &'static str, v: u64, min: u64, max: u64) -> Result<(), ConfigError> {
    if v < min {
        return Err(ConfigError::new(field, ConfigProblem::TooSmall { min }));
    }
    if v > max {
        return Err(ConfigError::new(field, ConfigProblem::TooLarge { max }));
    }
    Ok(())
}

fn default_shards() -> u16 {
    let cores = std::thread::available_parallelism().map_or(1, |n| n.get());
    u16::try_from(cores.next_power_of_two().min(usize::from(MAX_SHARDS))).unwrap_or(MAX_SHARDS)
}

fn prev_power_of_two(n: u32) -> u32 {
    if n == 0 {
        1
    } else {
        1 << (31 - n.leading_zeros())
    }
}

#[cfg(all(test, not(bouncer_loom)))]
mod tests {
    use super::*;

    #[test]
    fn test_bouncer_and_ticket_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Bouncer>();
        assert_send_sync::<Ticket>();
    }

    #[test]
    fn test_epoch_near_its_end_every_ticket_sees_each_change() {
        // Edge case 34: the epoch starts at `u64::MAX - 2`; three
        // revocations move it past the end. The epoch never takes the value
        // that marks always-checking tickets, so a self-revoked ticket stays
        // denied, and a normal ticket sees each change.
        let epoch = Arc::new(RevocationEpoch::starting_at(u64::MAX - 2));
        let b = Bouncer::builder()
            .epoch(Arc::clone(&epoch))
            .budgets(crate::Budgets::off())
            .try_build()
            .unwrap();
        let conn = b.door("192.0.2.1".parse().unwrap()).unwrap();
        let mut watched = conn.request(crate::RequestId(1)).unwrap();
        let session = crate::SessionKey::from_digest([3; 16]);
        assert!(watched.bind_session(session).is_pass());
        let other = b.door("192.0.2.2".parse().unwrap()).unwrap();
        let mut gone = other.request(crate::RequestId(2)).unwrap();
        let _ = gone.deny_and_eject(&mut crate::Collected::new());
        assert_eq!(
            epoch.current(),
            u64::MAX - 1,
            "the self-revocation moved it"
        );
        let mut seen = Vec::new();
        for i in 0..2u128 {
            let _ = b.revoke(crate::AccountKey(100 + i), crate::Reason::ADMIN);
            seen.push(epoch.current());
            assert!(watched.checkpoint().is_pass(), "unrelated change {i}");
            assert!(gone.checkpoint().is_deny(), "self-revoked stays denied");
        }
        let _ = b.revoke(session, crate::Reason::LOGOUT);
        seen.push(epoch.current());
        assert!(
            watched.checkpoint().is_deny(),
            "the third change is its own"
        );
        assert!(gone.checkpoint().is_deny());
        assert!(!seen.contains(&u64::MAX), "{seen:?}");
        assert_eq!(seen, [0, 1, 2], "u64::MAX is stepped over");
    }

    #[test]
    fn test_prev_power_of_two() {
        assert_eq!(prev_power_of_two(1), 1);
        assert_eq!(prev_power_of_two(3), 2);
        assert_eq!(prev_power_of_two(256), 256);
        assert_eq!(prev_power_of_two(0), 1);
    }

    #[test]
    fn test_builder_validation_errors_name_fields() {
        let cases: [(BouncerBuilder, &str); 8] = [
            (Bouncer::builder().tickets(0), "tickets"),
            (Bouncer::builder().tickets(MAX_TICKETS + 1), "tickets"),
            (Bouncer::builder().ban_capacity(0), "ban_capacity"),
            (
                Bouncer::builder().revocation_capacity(0),
                "revocation_capacity",
            ),
            (Bouncer::builder().shards(0), "shards"),
            (Bouncer::builder().ipv4_lengths(&[24]), "ipv4_lengths"),
            (Bouncer::builder().ipv6_lengths(&[]), "ipv6_lengths"),
            (
                Bouncer::builder().max_unchecked(Duration::ZERO),
                "max_unchecked",
            ),
        ];
        for (b, field) in cases {
            match b.try_build() {
                Err(BouncerError::Config(e)) => assert_eq!(e.field, field),
                other => panic!("{field}: {other:?}"),
            }
        }
        assert!(matches!(
            Bouncer::builder()
                .durations(DurationPolicy::default().factor(0))
                .try_build(),
            Err(BouncerError::Config(ConfigError {
                problem: ConfigProblem::InvalidFactor,
                ..
            }))
        ));
        let long: &'static str = Box::leak("x".repeat(300).into_boxed_str());
        assert!(matches!(
            Bouncer::builder()
                .denials(DenialTable::new().message(DenialCode::Forbidden, long))
                .try_build(),
            Err(BouncerError::Config(ConfigError {
                problem: ConfigProblem::MessageTooLong,
                ..
            }))
        ));
    }

    #[test]
    fn test_builder_shards_never_exceed_tickets() {
        let b = Bouncer::builder()
            .tickets(3)
            .shards(64)
            .try_build()
            .unwrap();
        assert_eq!(b.inner.shards.len(), 2);
        assert!(b.capacity().tickets >= 3);
    }

    #[test]
    fn test_new_has_default_capacity() {
        let b = Bouncer::new();
        let c = b.capacity();
        assert!(c.tickets >= crate::DEFAULT_TICKETS);
        assert_eq!(c.bans, crate::DEFAULT_BAN_CAPACITY);
        assert!(c.revocations >= crate::DEFAULT_REVOCATION_CAPACITY);
        assert!(format!("{b:?}").contains("Bouncer"));
    }
}
