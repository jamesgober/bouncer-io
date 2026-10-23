//! In-flight revocation: the epoch every checkpoint reads, and the tables a
//! checkpoint consults after the epoch moves.
//!
//! Revoking inserts the key into the revocation table of its kind (under the
//! writer lock, a cold path), then moves the epoch with a Release increment
//! followed by a sequentially consistent fence. A checkpoint whose Acquire
//! load reads the new epoch therefore sees the entry, and a before-commit
//! checkpoint (a sequentially consistent load) that starts after `revoke`
//! returned cannot miss it (loom model L-1).

use std::{
    net::IpAddr,
    sync::{Mutex, MutexGuard},
};

use crate::{
    bans::{
        BanMemory,
        table::{self, Entry, Inserted, Probe, Table, TableKey, TableWriter},
    },
    directive::{ActorKind, Reason},
    hash::HashKey,
    keys::{AccountKey, Cidr, ConnId, Family, FingerprintKey, RequestId, SessionKey, TenantKey},
    registry::{
        Cell, K_ACCOUNT, K_FINGERPRINT, K_REQUEST, K_SESSION, K_SOURCE, K_TENANT, P_ACCOUNT,
        P_FINGERPRINT, P_REQUEST, P_SESSION, P_SOURCE, P_SOURCE_V6, P_TENANT,
    },
    sync::{AtomicU64, Ordering, fence},
    verdict::{DenialCode, Reference},
};

/// The word every checkpoint reads, alone on its cache line.
///
/// By default each bouncer owns one. A security core that owns the process's
/// shared security state passes its own with
/// [`BouncerBuilder::epoch`](crate::BouncerBuilder::epoch), so other modules
/// read the same word.
///
/// # Examples
///
/// ```
/// use bouncer_io::{Bouncer, Reason, RevocationEpoch};
/// use std::sync::Arc;
///
/// let epoch = Arc::new(RevocationEpoch::new());          // owned by the security core
/// let bouncer = Bouncer::builder().epoch(epoch.clone()).try_build()?;
/// let before = epoch.current();
/// bouncer.revoke(bouncer_io::AccountKey(1), Reason::ADMIN)?;
/// assert!(epoch.current() > before);
/// # Ok::<(), bouncer_io::BouncerError>(())
/// ```
#[repr(align(64))]
pub struct RevocationEpoch {
    value: AtomicU64,
}

impl Default for RevocationEpoch {
    fn default() -> Self {
        RevocationEpoch::new()
    }
}

impl core::fmt::Debug for RevocationEpoch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RevocationEpoch")
            .field("current", &self.current())
            .finish()
    }
}

impl RevocationEpoch {
    /// A new epoch at zero.
    #[must_use]
    pub fn new() -> RevocationEpoch {
        RevocationEpoch {
            value: AtomicU64::new(0),
        }
    }

    /// The current value (an Acquire load).
    #[must_use]
    pub fn current(&self) -> u64 {
        self.load()
    }

    #[inline]
    pub(crate) fn load(&self) -> u64 {
        self.value.load(Ordering::Acquire)
    }

    #[inline]
    pub(crate) fn load_seq_cst(&self) -> u64 {
        self.value.load(Ordering::SeqCst)
    }

    /// Moves the epoch so every live ticket re-checks at its next checkpoint,
    /// and returns the new value. The fence pairs with the sequentially
    /// consistent load of the before-commit checkpoint and with binds.
    pub(crate) fn bump(&self) -> u64 {
        let v = self.value.fetch_add(1, Ordering::Release).wrapping_add(1);
        fence(Ordering::SeqCst);
        v
    }

    /// The next value a bump will produce (the birth of a new revocation).
    pub(crate) fn next(&self) -> u64 {
        self.value.load(Ordering::Acquire).wrapping_add(1)
    }
}

/// What to revoke.
///
/// Every key type converts into it, so `bouncer.revoke(session, reason)` reads
/// naturally. `Source` covers every ticket whose source falls inside the
/// prefix; a trusted proxy inside it is not revoked, its real clients are.
///
/// # Examples
///
/// ```
/// use bouncer_io::{AccountKey, Target};
/// let t: Target = AccountKey(42).into();
/// assert_eq!(t, Target::Account(AccountKey(42)));
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Target {
    /// One connection, and every request on it.
    Connection(ConnId),
    /// One request, and (unless the directive keeps it) its connection.
    Request(RequestId),
    /// Every ticket carrying the session.
    Session(SessionKey),
    /// Every ticket carrying the account.
    Account(AccountKey),
    /// Every ticket carrying the tenant.
    Tenant(TenantKey),
    /// Every ticket whose source falls inside the prefix.
    Source(Cidr),
    /// Every ticket carrying the fingerprint.
    Fingerprint(FingerprintKey),
}

impl From<ConnId> for Target {
    fn from(c: ConnId) -> Self {
        Target::Connection(c)
    }
}
impl From<RequestId> for Target {
    fn from(r: RequestId) -> Self {
        Target::Request(r)
    }
}
impl From<SessionKey> for Target {
    fn from(k: SessionKey) -> Self {
        Target::Session(k)
    }
}
impl From<AccountKey> for Target {
    fn from(k: AccountKey) -> Self {
        Target::Account(k)
    }
}
impl From<TenantKey> for Target {
    fn from(k: TenantKey) -> Self {
        Target::Tenant(k)
    }
}
impl From<Cidr> for Target {
    fn from(c: Cidr) -> Self {
        Target::Source(c)
    }
}
impl From<IpAddr> for Target {
    fn from(a: IpAddr) -> Self {
        Target::Source(Cidr::host(a))
    }
}
impl From<FingerprintKey> for Target {
    fn from(k: FingerprintKey) -> Self {
        Target::Fingerprint(k)
    }
}

/// When a revocation acts.
///
/// # Examples
///
/// ```
/// assert_eq!(bouncer_io::RevokeMode::default(), bouncer_io::RevokeMode::AtCheckpoint);
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RevokeMode {
    /// Denied at the next checkpoint.
    #[default]
    AtCheckpoint,
    /// Also closes matching connections that are not crossing checkpoints
    /// (idle keep-alive, parked WebSockets) through the `Ejector`.
    EjectNow,
}

/// The receipt of a revocation.
///
/// # Examples
///
/// ```
/// let bouncer = bouncer_io::Bouncer::new();
/// let receipt = bouncer.revoke(bouncer_io::AccountKey(9), bouncer_io::Reason::ADMIN)?;
/// assert!(receipt.epoch > 0);
/// # Ok::<(), bouncer_io::BouncerError>(())
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Revocation {
    /// The epoch value that carries this revocation.
    pub epoch: u64,
    /// The reference events and audit use for it.
    pub reference: Reference,
    /// For `EjectNow`: live tickets found and flagged by the sweep.
    pub matched_live: Option<u32>,
}

/// Entry flag: revoking a request leaves its connection open.
pub(crate) const FLAG_KEEP_CONNECTION: u8 = 2;

/// One revocation to record.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Record {
    pub(crate) key: TableKey,
    pub(crate) code: DenialCode,
    pub(crate) keep_connection: bool,
    pub(crate) actor: ActorKind,
    pub(crate) reason: Reason,
}

/// A match: the denial code and whether the connection stays open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Hit {
    pub(crate) code: DenialCode,
    pub(crate) keep_connection: bool,
}

impl Hit {
    fn from_entry(e: &Entry) -> Hit {
        Hit {
            code: DenialCode::from_number(e.offences as u8),
            keep_connection: e.flags & FLAG_KEEP_CONNECTION != 0,
        }
    }
}

struct Writer {
    table: TableWriter,
    counts_kind: [u32; 16],
    counts_v4: [u32; 33],
    counts_v6: [u32; 129],
}

/// The revocation tables of one bouncer: one lock-free table for every kind,
/// with masks of the kinds and source lengths in use so a check probes only
/// what can match.
pub(crate) struct Revocations {
    table: Table,
    kinds: AtomicU64,
    source_v4: AtomicU64,
    source_v6: [AtomicU64; 3],
    writer: Mutex<Writer>,
}

/// The table key of a connection id.
pub(crate) fn connection_key(conn: u64) -> TableKey {
    TableKey {
        kind: table::KIND_CONNECTION,
        len: 0,
        k0: 0,
        k1: conn,
    }
}

/// The table key of a request id.
pub(crate) fn request_key(r: u128) -> TableKey {
    TableKey {
        kind: table::KIND_REQUEST,
        len: 0,
        k0: (r >> 64) as u64,
        k1: r as u64,
    }
}

/// The table key of a revocation target.
pub(crate) fn target_key(target: &Target) -> TableKey {
    match *target {
        Target::Connection(c) => connection_key(c.0),
        Target::Request(r) => request_key(r.0),
        Target::Session(s) => {
            let (k0, k1) = s.words();
            TableKey {
                kind: table::KIND_SESSION,
                len: 0,
                k0,
                k1,
            }
        }
        Target::Account(a) => TableKey {
            kind: table::KIND_ACCOUNT,
            len: 0,
            k0: (a.0 >> 64) as u64,
            k1: a.0 as u64,
        },
        Target::Tenant(t) => TableKey {
            kind: table::KIND_TENANT,
            len: 0,
            k0: 0,
            k1: t.0,
        },
        Target::Source(c) => BanMemory::prefix_key(&c),
        Target::Fingerprint(f) => {
            let (k0, k1) = f.words();
            TableKey {
                kind: table::KIND_FINGERPRINT,
                len: 0,
                k0,
                k1,
            }
        }
    }
}

fn set_bit(word: &AtomicU64, bit: u32, on: bool) {
    if on {
        word.fetch_or(1u64 << bit, Ordering::Release);
    } else {
        word.fetch_and(!(1u64 << bit), Ordering::Release);
    }
}

impl Revocations {
    pub(crate) fn new(capacity: u32, key: HashKey) -> Revocations {
        Revocations {
            table: Table::new(capacity, key),
            kinds: AtomicU64::new(0),
            source_v4: AtomicU64::new(0),
            source_v6: [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)],
            writer: Mutex::new(Writer {
                table: TableWriter::default(),
                counts_kind: [0; 16],
                counts_v4: [0; 33],
                counts_v6: [0; 129],
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Writer> {
        self.writer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(crate) fn capacity(&self) -> u32 {
        self.table.capacity()
    }

    pub(crate) fn bytes(&self) -> u64 {
        self.table.bytes()
    }

    /// Live entries.
    pub(crate) fn live(&self) -> u32 {
        self.lock().table.live()
    }

    /// `true` when nothing is recorded: checks skip every probe.
    #[inline]
    pub(crate) fn is_empty(&self) -> bool {
        self.kinds.load(Ordering::Acquire) == 0
    }

    /// Records a revocation and moves the epoch, both under the writer lock,
    /// so births are unique and increasing: an entry born at `b` was in the
    /// table before the epoch reached `b`, and cleanup removes it only when
    /// every live ticket has checked at `b` or later. Returns the new epoch;
    /// `Err` (epoch unmoved) when the table is full.
    pub(crate) fn insert(&self, r: &Record, epoch: &RevocationEpoch) -> Result<u64, ()> {
        let mut w = self.lock();
        let birth = epoch.next();
        let entry = Entry {
            key: r.key,
            flags: if r.keep_connection {
                FLAG_KEEP_CONNECTION
            } else {
                0
            },
            actor: r.actor,
            reason: r.reason,
            offences: u16::from(r.code.number() as u8),
            until: 0,
            issued: 0,
            id: birth,
        };
        let writer = &mut *w;
        // A second revocation of the same key keeps the stronger code and the
        // newer birth.
        let merged = |old: &Entry| {
            let old_code = DenialCode::from_number(old.offences as u8);
            Entry {
                offences: u16::from(old_code.max(r.code).number() as u8),
                ..entry
            }
        };
        match self.table.insert(&mut writer.table, entry, 0, merged) {
            Ok(Inserted::Merged { .. }) => {}
            Ok(Inserted::New { removed, .. }) => {
                if let Some(old) = removed {
                    self.count(writer, &old.key, false);
                }
                self.count(writer, &r.key, true);
            }
            Err(()) => return Err(()),
        }
        Ok(epoch.bump())
    }

    fn count(&self, w: &mut Writer, key: &TableKey, add: bool) {
        let bump = |c: &mut u32| {
            if add {
                *c += 1;
            } else {
                *c = c.saturating_sub(1);
            }
            *c
        };
        let kind = usize::from(key.kind & 15);
        let n = bump(&mut w.counts_kind[kind]);
        set_bit(&self.kinds, u32::from(key.kind & 63), n > 0);
        match key.kind {
            table::KIND_V4 => {
                let n = bump(&mut w.counts_v4[usize::from(key.len.min(32))]);
                set_bit(&self.source_v4, u32::from(key.len), n > 0);
            }
            table::KIND_V6 => {
                let len = key.len.min(128);
                let n = bump(&mut w.counts_v6[usize::from(len)]);
                set_bit(
                    &self.source_v6[usize::from(len / 64)],
                    u32::from(len % 64),
                    n > 0,
                );
            }
            _ => {}
        }
    }

    /// Removes entries born at or before `epoch`: no live ticket can still
    /// need them. Returns how many were removed.
    pub(crate) fn remove_born_by(&self, epoch: u64) -> u32 {
        let mut w = self.lock();
        let writer = &mut *w;
        let removed = self
            .table
            .remove_where(&mut writer.table, |e| e.id <= epoch);
        for e in &removed {
            self.count(writer, &e.key, false);
        }
        removed.len() as u32
    }

    #[inline]
    fn has_kind(&self, kinds: u64, kind: u8) -> bool {
        kinds & (1u64 << kind) != 0
    }

    #[inline]
    fn probe(&self, key: &TableKey) -> Option<Hit> {
        match self.table.find(key, 0) {
            Probe::Hit(e) => Some(Hit::from_entry(&e)),
            // A slot rewritten for longer than the spin bound: fail closed.
            Probe::Busy => Some(Hit {
                code: DenialCode::Unavailable,
                keep_connection: false,
            }),
            Probe::Miss => None,
        }
    }

    /// The first revocation matching any key bound on `cell`.
    pub(crate) fn matches(&self, cell: &Cell) -> Option<Hit> {
        let kinds = self.kinds.load(Ordering::Acquire);
        if kinds == 0 {
            return None;
        }
        let present = cell.present();
        let word = |i: usize| cell.keys[i].load(Ordering::Relaxed);
        if self.has_kind(kinds, table::KIND_CONNECTION) {
            if let Some(h) = self.probe(&connection_key(cell.conn.load(Ordering::Relaxed))) {
                return Some(h);
            }
        }
        if present & P_REQUEST != 0 && self.has_kind(kinds, table::KIND_REQUEST) {
            let r = (u128::from(word(K_REQUEST)) << 64) | u128::from(word(K_REQUEST + 1));
            if let Some(h) = self.probe(&request_key(r)) {
                return Some(h);
            }
        }
        for (bit, kind, at, two) in [
            (P_SESSION, table::KIND_SESSION, K_SESSION, true),
            (P_ACCOUNT, table::KIND_ACCOUNT, K_ACCOUNT, true),
            (P_TENANT, table::KIND_TENANT, K_TENANT, false),
            (P_FINGERPRINT, table::KIND_FINGERPRINT, K_FINGERPRINT, true),
        ] {
            if present & bit != 0 && self.has_kind(kinds, kind) {
                let key = if two {
                    TableKey {
                        kind,
                        len: 0,
                        k0: word(at),
                        k1: word(at + 1),
                    }
                } else {
                    TableKey {
                        kind,
                        len: 0,
                        k0: 0,
                        k1: word(at),
                    }
                };
                if let Some(h) = self.probe(&key) {
                    return Some(h);
                }
            }
        }
        if present & P_SOURCE != 0 {
            let hi = word(K_SOURCE);
            let lo = word(K_SOURCE + 1);
            let source = if present & P_SOURCE_V6 != 0 {
                IpAddr::from(std::net::Ipv6Addr::from(
                    (u128::from(hi) << 64) | u128::from(lo),
                ))
            } else {
                IpAddr::from(std::net::Ipv4Addr::from(lo as u32))
            };
            if let Some(h) = self.matches_source(source) {
                return Some(h);
            }
        }
        None
    }

    /// The first source-prefix revocation covering `addr`.
    pub(crate) fn matches_source(&self, addr: IpAddr) -> Option<Hit> {
        let host = Cidr::host(addr);
        let visit = |len: u8| {
            host.parent(len)
                .and_then(|p| self.probe(&BanMemory::prefix_key(&p)))
        };
        match host.family() {
            Family::V4 => {
                let mut m = self.source_v4.load(Ordering::Acquire);
                while m != 0 {
                    let len = m.trailing_zeros() as u8;
                    m &= m - 1;
                    if let Some(h) = visit(len) {
                        return Some(h);
                    }
                }
            }
            Family::V6 => {
                for (w, word) in self.source_v6.iter().enumerate() {
                    let mut m = word.load(Ordering::Acquire);
                    while m != 0 {
                        let len = (w as u32 * 64 + m.trailing_zeros()) as u8;
                        m &= m - 1;
                        if let Some(h) = visit(len) {
                            return Some(h);
                        }
                    }
                }
            }
        }
        None
    }

    /// The revocation of one key, for binds.
    pub(crate) fn matches_key(&self, key: &TableKey) -> Option<Hit> {
        if !self.has_kind(self.kinds.load(Ordering::Acquire), key.kind) {
            return None;
        }
        self.probe(key)
    }
}
