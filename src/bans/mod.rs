//! Ban memory: what is banned, for how long, and by whom.
//!
//! Bans at the automatic prefix lengths and identity bans live in the
//! dynamic [`table`]; administrator prefixes of any other length live in a
//! compiled set that is rebuilt on change and swapped whole. Readers never
//! take a lock: the table is read through per-slot sequence locks and the
//! compiled set through a per-thread cache keyed by a version word.

pub(crate) mod compiled;
pub(crate) mod escalate;
pub(crate) mod offenders;
pub(crate) mod restore;
pub(crate) mod table;
pub(crate) mod view;

use core::{cell::RefCell, time::Duration};
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex, MutexGuard, RwLock},
};

use self::{
    compiled::PrefixSet,
    escalate::{EscalationPolicy, Plan, Tracker},
    offenders::{Offence, Offenders},
    table::{Entry, FLAG_EVICTABLE, Inserted, Probe, Table, TableKey, TableWriter},
};
use crate::{
    directive::{Actor, ActorKind, Evidence, Reason},
    error::{BouncerError, ConfigError, ConfigProblem},
    hash::{HashKey, Rng},
    keys::{BanKey, Cidr, Family, normalize},
    sync::{AtomicU64, Ordering},
    time::{Now, ceil_secs},
};

/// Identifies one ban, for events, listings, and lifts.
///
/// # Examples
///
/// ```
/// let bouncer = bouncer_io::Bouncer::new();
/// let a = bouncer.ban("198.51.100.1".parse::<std::net::IpAddr>()?)?;
/// let b = bouncer.ban("198.51.100.2".parse::<std::net::IpAddr>()?)?;
/// assert_ne!(a, b);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BanId(u64);

impl BanId {
    pub(crate) const fn from_raw(id: u64) -> BanId {
        BanId(id)
    }

    /// The raw value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// How long a ban lasts.
///
/// # Examples
///
/// ```
/// use bouncer_io::{BanDuration, BanSpec};
/// use std::time::Duration;
/// let spec = BanSpec::address("192.0.2.1".parse()?).for_duration(Duration::from_secs(60));
/// assert_eq!(spec.duration, BanDuration::Fixed(Duration::from_secs(60)));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BanDuration {
    /// The duration policy: growing for repeat offenders, with jitter.
    #[default]
    Policy,
    /// Exactly this long (rounded up to whole seconds). Zero is refused.
    Fixed(Duration),
    /// Until lifted. Only for actors that may ban permanently.
    Permanent,
}

/// Describes a ban: key, duration, actor, reason, evidence.
///
/// The defaults are the duration policy, [`Actor::App`], and
/// [`Reason::ADMIN`]. An address or prefix converts directly.
///
/// # Examples
///
/// ```
/// use bouncer_io::{Actor, BanSpec, Bouncer, Reason};
/// use std::time::Duration;
///
/// let bouncer = Bouncer::new();
/// bouncer.ban(
///     BanSpec::address("198.51.100.9".parse()?)
///         .for_duration(Duration::from_secs(3600))
///         .by(Actor::Admin(17))
///         .because(Reason::ADMIN),
/// )?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Copy)]
pub struct BanSpec {
    /// What is banned.
    pub key: BanKey,
    /// For how long.
    pub duration: BanDuration,
    /// Who decided.
    pub actor: Actor,
    /// Why.
    pub reason: Reason,
    /// Supporting evidence, for events.
    pub evidence: Evidence<'static>,
}

impl BanSpec {
    /// A ban of any key.
    #[must_use]
    pub fn key(key: impl Into<BanKey>) -> BanSpec {
        BanSpec {
            key: key.into().normalized(),
            duration: BanDuration::Policy,
            actor: Actor::App,
            reason: Reason::ADMIN,
            evidence: Evidence::none(),
        }
    }

    /// A ban of one client: an IPv4 address, or an IPv6 address's /64.
    #[must_use]
    pub fn address(addr: IpAddr) -> BanSpec {
        BanSpec::key(BanKey::Address(normalize(addr)))
    }

    /// A ban of a prefix.
    #[must_use]
    pub fn prefix(cidr: Cidr) -> BanSpec {
        BanSpec::key(BanKey::Prefix(cidr))
    }

    /// Lasts exactly `duration`.
    #[must_use]
    pub fn for_duration(mut self, duration: Duration) -> BanSpec {
        self.duration = BanDuration::Fixed(duration);
        self
    }

    /// Lasts until lifted.
    #[must_use]
    pub fn permanent(mut self) -> BanSpec {
        self.duration = BanDuration::Permanent;
        self
    }

    /// Who decided.
    #[must_use]
    pub fn by(mut self, actor: Actor) -> BanSpec {
        self.actor = actor;
        self
    }

    /// Why.
    #[must_use]
    pub fn because(mut self, reason: Reason) -> BanSpec {
        self.reason = reason;
        self
    }

    /// Supporting evidence.
    #[must_use]
    pub fn evidence(mut self, evidence: Evidence<'static>) -> BanSpec {
        self.evidence = evidence;
        self
    }
}

impl From<IpAddr> for BanSpec {
    fn from(addr: IpAddr) -> Self {
        BanSpec::address(addr)
    }
}
impl From<Cidr> for BanSpec {
    fn from(cidr: Cidr) -> Self {
        BanSpec::prefix(cidr)
    }
}
impl From<BanKey> for BanSpec {
    fn from(key: BanKey) -> Self {
        BanSpec::key(key)
    }
}

/// Describes a lift: key, actor, reason.
///
/// # Examples
///
/// ```
/// use bouncer_io::{Actor, Bouncer, LiftSpec, Reason};
/// let bouncer = Bouncer::new();
/// let addr: std::net::IpAddr = "198.51.100.9".parse()?;
/// bouncer.ban(addr)?;
/// let lifted = bouncer.lift(LiftSpec::key(addr).by(Actor::Admin(17)).because(Reason::ADMIN))?;
/// assert_eq!(lifted.removed, 1);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Copy)]
pub struct LiftSpec {
    /// What is lifted: bans on exactly this key.
    pub key: BanKey,
    /// Who decided.
    pub actor: Actor,
    /// Why.
    pub reason: Reason,
}

impl LiftSpec {
    /// A lift of any key, by [`Actor::App`] for [`Reason::ADMIN`].
    #[must_use]
    pub fn key(key: impl Into<BanKey>) -> LiftSpec {
        LiftSpec {
            key: key.into().normalized(),
            actor: Actor::App,
            reason: Reason::ADMIN,
        }
    }

    /// Who decided.
    #[must_use]
    pub fn by(mut self, actor: Actor) -> LiftSpec {
        self.actor = actor;
        self
    }

    /// Why.
    #[must_use]
    pub fn because(mut self, reason: Reason) -> LiftSpec {
        self.reason = reason;
        self
    }
}

impl From<IpAddr> for LiftSpec {
    fn from(addr: IpAddr) -> Self {
        LiftSpec::key(addr)
    }
}
impl From<Cidr> for LiftSpec {
    fn from(cidr: Cidr) -> Self {
        LiftSpec::key(cidr)
    }
}
impl From<BanKey> for LiftSpec {
    fn from(key: BanKey) -> Self {
        LiftSpec::key(key)
    }
}

/// What a lift removed.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lifted {
    /// Bans removed (0 or 1 at this version; prefix folding arrives with
    /// escalation).
    pub removed: u32,
    /// The id recorded for the lift itself.
    pub tombstone: BanId,
}

/// How long automatic bans last, growing for repeat offenders.
///
/// `duration = min(base * factor^min(offences, step_cap), max) + random(0..=jitter)`,
/// saturating. The jitter stops an attacker timing its return to the second.
///
/// # Examples
///
/// ```
/// use bouncer_io::DurationPolicy;
/// use std::time::Duration;
/// let policy = DurationPolicy::default().base(Duration::from_secs(300)).factor(3).max(Duration::from_secs(86_400));
/// # let _ = policy;
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DurationPolicy {
    base: Duration,
    factor: u32,
    step_cap: u8,
    max: Duration,
    jitter: Duration,
    half_life: Duration,
}

impl Default for DurationPolicy {
    fn default() -> Self {
        DurationPolicy {
            base: Duration::from_secs(600),
            factor: 2,
            step_cap: 20,
            max: Duration::from_secs(7 * 24 * 3600),
            jitter: Duration::from_secs(60),
            half_life: Duration::from_secs(24 * 3600),
        }
    }
}

impl DurationPolicy {
    /// The first ban's length (default 10 minutes).
    #[must_use]
    pub fn base(mut self, d: Duration) -> Self {
        self.base = d;
        self
    }

    /// Growth per repeat offence (default 2).
    #[must_use]
    pub fn factor(mut self, f: u32) -> Self {
        self.factor = f;
        self
    }

    /// Offences after which the growth stops (default 20).
    #[must_use]
    pub fn step_cap(mut self, n: u8) -> Self {
        self.step_cap = n;
        self
    }

    /// The longest ban (default 7 days), before jitter.
    #[must_use]
    pub fn max(mut self, d: Duration) -> Self {
        self.max = d;
        self
    }

    /// Random extra time, uniform in `0..=jitter` (default 60 seconds).
    #[must_use]
    pub fn jitter(mut self, d: Duration) -> Self {
        self.jitter = d;
        self
    }

    /// How fast offender memory forgets: an offence counts half after this
    /// long (default 24 hours). Offences rounded from the decayed score
    /// drive the next ban's length.
    #[must_use]
    pub fn half_life(mut self, d: Duration) -> Self {
        self.half_life = d;
        self
    }

    /// The first ban's length in whole seconds.
    pub(crate) fn base_secs(&self) -> u64 {
        ceil_secs(self.base)
    }

    /// The longest ban in whole seconds, before jitter.
    pub(crate) fn max_secs(&self) -> u64 {
        ceil_secs(self.max)
    }

    pub(crate) fn validate(&self, field: &'static str) -> Result<(), ConfigError> {
        if self.base.is_zero() || self.max < self.base {
            return Err(ConfigError::new(field, ConfigProblem::InvalidDuration));
        }
        if self.factor == 0 {
            return Err(ConfigError::new(field, ConfigProblem::InvalidFactor));
        }
        if self.half_life.is_zero() {
            return Err(ConfigError::new(field, ConfigProblem::InvalidDuration));
        }
        Ok(())
    }

    /// The length in whole seconds for a key with `offences` earlier bans.
    pub(crate) fn seconds(&self, offences: u16, rng: &mut Rng) -> u64 {
        let steps = u32::from(offences.min(u16::from(self.step_cap)));
        let growth = u64::from(self.factor)
            .checked_pow(steps)
            .unwrap_or(u64::MAX);
        let max = ceil_secs(self.max);
        let grown = ceil_secs(self.base).saturating_mul(growth).min(max);
        grown.saturating_add(rng.below_or_equal(ceil_secs(self.jitter)))
    }

    /// The largest value [`seconds`](Self::seconds) can return.
    #[cfg(all(test, not(bouncer_loom)))]
    pub(crate) fn ceiling(&self) -> u64 {
        ceil_secs(self.max).saturating_add(ceil_secs(self.jitter))
    }
}

/// An administrator prefix ban in the compiled set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AdminEntry {
    pub(crate) id: u64,
    pub(crate) until: u32,
    pub(crate) issued: u32,
    pub(crate) actor: ActorKind,
    pub(crate) reason: Reason,
}

impl AdminEntry {
    fn expired(&self, now_secs: u64) -> bool {
        self.until != 0 && u64::from(self.until) <= now_secs
    }
}

/// The answer of a door-side lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Lookup {
    Clear,
    Banned(u64),
    /// A writer held a slot past the spin bound; the caller fails closed.
    Busy,
}

/// Where a key is stored.
enum Placement {
    Dynamic(TableKey),
    Admin(Cidr),
}

/// Lengths probed together in one door lookup.
const PROBE_BATCH: usize = 8;

/// Most administrator prefixes the compiled set holds.
pub(crate) const MAX_ADMIN_PREFIXES: usize = 1 << 20;

struct Writer {
    table: TableWriter,
    /// Live entries per (kind, length), to keep the present masks exact.
    counts_v4: [u32; 33],
    counts_v6: [u32; 129],
    counts_ident: [u32; 16],
    admin: Vec<(Cidr, AdminEntry)>,
    /// The originals of compound fingerprint keys (stored as digests), by
    /// (length, digest words): for listings, persistence, and sharing.
    compound: HashMap<(u8, u64, u64), (crate::keys::FingerprintKey, Cidr)>,
    rng: Rng,
    next_id: u64,
    offenders: Offenders,
    tracker: Tracker,
}

/// The per-thread cache of the administrator set: bouncer id, version, set.
type AdminCache = Option<(u64, u64, Arc<PrefixSet<AdminEntry>>)>;

thread_local! {
    static ADMIN_CACHE: RefCell<AdminCache> = const { RefCell::new(None) };
}

static NEXT_UID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// What a ban did: its id, an escalation now due, a ban the insert took out
/// (`true` when evicted, `false` when expired), and the ban the call itself
/// produced (`None` when a wider ban already covered it).
pub(crate) type Planned = (BanId, Option<Plan>, Option<(BanKey, bool)>, Option<Own>);

/// The ban one call produced, before any merge with a ban already stored
/// under the key: what a sharing node records as its own (D-096).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Own {
    pub(crate) until: u32,
    pub(crate) issued: u32,
    pub(crate) actor: ActorKind,
    pub(crate) reason: Reason,
    pub(crate) offences: u16,
}

/// The ban memory of one bouncer.
pub(crate) struct BanMemory {
    table: Table,
    present_v4: AtomicU64,
    present_v6: [AtomicU64; 3],
    present_ident: AtomicU64,
    admin_version: AtomicU64,
    admin_count: AtomicU64,
    admin: RwLock<Arc<PrefixSet<AdminEntry>>>,
    uid: u64,
    writer: Mutex<Writer>,
    auto_v4: u64,
    auto_v6: [u64; 3],
    host_v6: u8,
    policy: DurationPolicy,
    escalation: EscalationPolicy,
    fingerprint_keys: (HashKey, HashKey),
    /// Expired entries reclaimed by inserts, and entries evicted.
    expired: std::sync::atomic::AtomicU64,
    evicted: std::sync::atomic::AtomicU64,
}

/// The keyed hashes of one address's prefixes, each computed at most once
/// per door check and shared by the ban lookup and the door budgets.
pub(crate) struct AddrHashes {
    host: Cidr,
    key: HashKey,
    lens: [u8; 8],
    vals: [u64; 8],
    n: usize,
}

impl AddrHashes {
    #[inline]
    pub(crate) fn new(key: HashKey, addr: IpAddr) -> AddrHashes {
        AddrHashes {
            host: Cidr::host(addr),
            key,
            lens: [0; 8],
            vals: [0; 8],
            n: 0,
        }
    }

    pub(crate) fn host(&self) -> &Cidr {
        &self.host
    }

    /// The table hash of the address's prefix of length `len`.
    #[inline]
    pub(crate) fn get(&mut self, len: u8) -> u64 {
        if let Some(i) = self.lens[..self.n].iter().position(|&l| l == len) {
            return self.vals[i];
        }
        let p = self.host.parent(len).unwrap_or(self.host);
        let h = table::hash_key(&self.key, &BanMemory::prefix_key(&p));
        if self.n < 8 {
            self.lens[self.n] = len;
            self.vals[self.n] = h;
            self.n += 1;
        }
        h
    }
}

/// The allow and trusted-proxy sets a ban is checked against.
pub(crate) struct Guards<'a> {
    pub(crate) immune: &'a PrefixSet<crate::allow::AllowKind>,
    pub(crate) proxies: &'a PrefixSet<()>,
}

impl BanMemory {
    pub(crate) fn new(
        capacity: u32,
        key: HashKey,
        v4_lengths: &[u8],
        v6_lengths: &[u8],
        policy: DurationPolicy,
        escalation: EscalationPolicy,
        rng_seed: u64,
    ) -> BanMemory {
        let mut auto_v4 = 0u64;
        for &l in v4_lengths {
            auto_v4 |= 1u64 << l;
        }
        let mut auto_v6 = [0u64; 3];
        for &l in v6_lengths {
            auto_v6[usize::from(l / 64)] |= 1u64 << (l % 64);
        }
        let host_v6 = v6_lengths
            .iter()
            .copied()
            .filter(|&l| l <= 64)
            .max()
            .unwrap_or_else(|| v6_lengths.iter().copied().min().unwrap_or(64));
        let mut rng = Rng::from_seed(rng_seed);
        let fingerprint_keys = (
            HashKey::new(rng.next_u64(), rng.next_u64()),
            HashKey::new(rng.next_u64(), rng.next_u64()),
        );
        BanMemory {
            table: Table::new(capacity, key),
            present_v4: AtomicU64::new(0),
            present_v6: [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)],
            present_ident: AtomicU64::new(0),
            admin_version: AtomicU64::new(0),
            admin_count: AtomicU64::new(0),
            admin: RwLock::new(Arc::new(PrefixSet::empty())),
            uid: NEXT_UID.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            writer: Mutex::new(Writer {
                table: TableWriter::default(),
                counts_v4: [0; 33],
                counts_v6: [0; 129],
                counts_ident: [0; 16],
                admin: Vec::new(),
                compound: HashMap::new(),
                rng,
                next_id: 1,
                offenders: Offenders::new(
                    (capacity as usize / 4).max(1024),
                    ceil_secs(policy.half_life),
                ),
                tracker: Tracker::default(),
            }),
            auto_v4,
            auto_v6,
            host_v6,
            policy,
            escalation,
            fingerprint_keys,
            expired: std::sync::atomic::AtomicU64::new(0),
            evicted: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Expired entries reclaimed so far.
    #[cfg_attr(not(feature = "metrics"), allow(dead_code))]
    pub(crate) fn expired_total(&self) -> u64 {
        self.expired.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Entries evicted so far.
    #[cfg_attr(not(feature = "metrics"), allow(dead_code))]
    pub(crate) fn evicted_total(&self) -> u64 {
        self.evicted.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn lock(&self) -> MutexGuard<'_, Writer> {
        // A panic while holding the lock leaves the table consistent (every
        // slot write is complete or not started), so a poisoned lock is safe
        // to keep using.
        self.writer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Bytes reserved by the dynamic table.
    pub(crate) fn table_bytes(&self) -> u64 {
        self.table.bytes()
    }

    /// Entries the dynamic table holds at most.
    pub(crate) fn capacity(&self) -> u32 {
        self.table.capacity()
    }

    /// Live entries (including expired ones not yet reclaimed).
    #[cfg(all(test, not(bouncer_loom)))]
    pub(crate) fn live(&self) -> u32 {
        self.lock().table.live()
    }

    fn is_auto(&self, family: Family, len: u8) -> bool {
        match family {
            Family::V4 => len <= 32 && self.auto_v4 & (1u64 << len) != 0,
            Family::V6 => {
                len <= 128 && self.auto_v6[usize::from(len / 64)] & (1u64 << (len % 64)) != 0
            }
        }
    }

    pub(crate) fn prefix_key(cidr: &Cidr) -> TableKey {
        let kind = match cidr.family() {
            Family::V4 => table::KIND_V4,
            Family::V6 => table::KIND_V6,
        };
        TableKey {
            kind,
            len: cidr.len(),
            k0: (cidr.bits() >> 64) as u64,
            k1: cidr.bits() as u64,
        }
    }

    /// The table key of a fingerprint within a prefix: a keyed 128-bit digest
    /// of both, so the compound key fits the table's two words.
    pub(crate) fn fingerprint_in_key(
        &self,
        fp: &crate::keys::FingerprintKey,
        cidr: &Cidr,
    ) -> TableKey {
        let (hi, lo) = fp.words();
        let meta = u64::from(cidr.len()) | (u64::from(cidr.family() == Family::V6) << 8);
        let (a, b) = &self.fingerprint_keys;
        let h = a.hash3(hi, lo, meta);
        let k0 = a.hash3(h, (cidr.bits() >> 64) as u64, cidr.bits() as u64);
        let h2 = b.hash3(lo, hi, meta);
        let k1 = b.hash3(h2, cidr.bits() as u64, (cidr.bits() >> 64) as u64);
        TableKey {
            kind: table::KIND_FINGERPRINT_IN,
            len: cidr.len(),
            k0,
            k1,
        }
    }

    /// The prefix an address key is stored under: /32 for IPv4, the most
    /// specific automatic length up to /64 for IPv6.
    pub(crate) fn address_prefix(&self, addr: IpAddr) -> Cidr {
        let addr = normalize(addr);
        let len = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => self.host_v6,
        };
        // Lengths are validated at build, so this cannot fail; fall back to
        // the host prefix anyway rather than panic.
        Cidr::new(addr, len).unwrap_or_else(|_| Cidr::host(addr))
    }

    fn place(&self, key: &BanKey, actor: Actor) -> Result<Placement, BouncerError> {
        Ok(match *key {
            BanKey::Address(addr) => {
                Placement::Dynamic(Self::prefix_key(&self.address_prefix(addr)))
            }
            BanKey::Prefix(c) => {
                if self.is_auto(c.family(), c.len()) {
                    Placement::Dynamic(Self::prefix_key(&c))
                } else if actor.is_automated() {
                    return Err(BouncerError::InvalidPrefix {
                        len: c.len(),
                        family: c.family(),
                        host_bits_set: false,
                    });
                } else {
                    Placement::Admin(c)
                }
            }
            BanKey::Session(s) => {
                let (k0, k1) = s.words();
                Placement::Dynamic(TableKey {
                    kind: table::KIND_SESSION,
                    len: 0,
                    k0,
                    k1,
                })
            }
            BanKey::Account(a) => Placement::Dynamic(TableKey {
                kind: table::KIND_ACCOUNT,
                len: 0,
                k0: (a.0 >> 64) as u64,
                k1: a.0 as u64,
            }),
            BanKey::Tenant(t) => Placement::Dynamic(TableKey {
                kind: table::KIND_TENANT,
                len: 0,
                k0: 0,
                k1: t.0,
            }),
            BanKey::Fingerprint(fp) => {
                if actor.is_automated() {
                    return Err(BouncerError::InvalidTarget);
                }
                let (k0, k1) = fp.words();
                Placement::Dynamic(TableKey {
                    kind: table::KIND_FINGERPRINT,
                    len: 0,
                    k0,
                    k1,
                })
            }
            BanKey::FingerprintIn(fp, c) => {
                if !self.is_auto(c.family(), c.len()) {
                    return Err(BouncerError::InvalidPrefix {
                        len: c.len(),
                        family: c.family(),
                        host_bits_set: false,
                    });
                }
                Placement::Dynamic(self.fingerprint_in_key(&fp, &c))
            }
        })
    }

    /// Refuses keys covered by an immune allow entry or a trusted proxy.
    fn guard(&self, key: &BanKey, guards: &Guards<'_>) -> Result<(), BouncerError> {
        let cidr = match *key {
            BanKey::Address(a) => Cidr::host(a),
            BanKey::Prefix(c) | BanKey::FingerprintIn(_, c) => c,
            _ => return Ok(()),
        };
        let immune = guards
            .immune
            .find_covering_map(&cidr, |k| {
                (*k == crate::allow::AllowKind::Immune).then_some(())
            })
            .is_some();
        if immune {
            return Err(BouncerError::AllowListed { key: *key });
        }
        if guards.proxies.covers(&cidr) {
            return Err(BouncerError::TrustedProxyTarget);
        }
        Ok(())
    }

    /// Adds a ban with the bouncer's duration policy.
    #[cfg(all(test, not(bouncer_loom)))]
    pub(crate) fn ban(
        &self,
        spec: &BanSpec,
        guards: &Guards<'_>,
        now: Now,
    ) -> Result<BanId, BouncerError> {
        self.ban_with(spec, guards, now, None)
    }

    /// Adds a ban; `policy` overrides the duration policy (per strike kind).
    #[cfg(all(test, not(bouncer_loom)))]
    pub(crate) fn ban_with(
        &self,
        spec: &BanSpec,
        guards: &Guards<'_>,
        now: Now,
        policy: Option<DurationPolicy>,
    ) -> Result<BanId, BouncerError> {
        self.ban_plan(spec, guards, now, policy).map(|(id, ..)| id)
    }

    /// Adds a ban and reports an escalation it makes due: the parent prefix
    /// and the children to fold, for the caller to check and apply.
    pub(crate) fn ban_plan(
        &self,
        spec: &BanSpec,
        guards: &Guards<'_>,
        now: Now,
        policy: Option<DurationPolicy>,
    ) -> Result<Planned, BouncerError> {
        let key = spec.key.normalized();
        self.guard(&key, guards)?;
        let placement = self.place(&key, spec.actor)?;
        if let BanDuration::Fixed(d) = spec.duration {
            if d.is_zero() {
                return Err(BouncerError::InvalidDuration);
            }
        }
        if spec.duration == BanDuration::Permanent && !spec.actor.may_ban_permanently() {
            return Err(BouncerError::PermanentNotAllowed);
        }
        let now_secs = now.secs();
        let issued = clamp_secs(now_secs);
        let mut w = self.lock();
        let previous = match &placement {
            Placement::Dynamic(k) => {
                // A ban still in force counts its own history; once it has
                // expired, offender memory (with its decay) decides.
                let held = self
                    .table
                    .get_owned(k)
                    .filter(|e| !e.expired(now_secs))
                    .map(|e| e.offences.saturating_add(1));
                let remembered = w.offenders.offences(k, now_secs);
                match held {
                    Some(h) => Some(h.max(remembered)),
                    None if remembered > 0 => Some(remembered),
                    None => None,
                }
            }
            Placement::Admin(_) => None,
        };
        let until = match spec.duration {
            BanDuration::Permanent => 0,
            BanDuration::Fixed(d) => end(now_secs, ceil_secs(d)),
            BanDuration::Policy => {
                let secs = policy
                    .unwrap_or(self.policy)
                    .seconds(previous.unwrap_or(0), &mut w.rng);
                end(now_secs, secs.max(1))
            }
        };
        // A wider ban that already outlasts this one covers it: automation
        // stores nothing new (the table stays compact under a flood). An
        // explicit ban is stored anyway, so lifting the prefix keeps it.
        if let (Placement::Dynamic(tkey), true) = (&placement, spec.actor.is_automated()) {
            if let Some(covering) = self.covering_wider(tkey, until, now_secs) {
                return Ok((BanId(covering), None, None, None));
            }
        }
        let id = w.next_id;
        w.next_id += 1;
        let actor = spec.actor.kind();
        let own = Own {
            until,
            issued,
            actor,
            reason: spec.reason,
            offences: previous.unwrap_or(0),
        };
        match placement {
            Placement::Dynamic(tkey) => {
                let flags = if actor == ActorKind::Local && until != 0 {
                    FLAG_EVICTABLE
                } else {
                    0
                };
                let entry = Entry {
                    key: tkey,
                    flags,
                    actor,
                    reason: spec.reason,
                    offences: previous.unwrap_or(0),
                    until,
                    issued,
                    id,
                };
                let writer = &mut *w;
                let result = self
                    .table
                    .insert(&mut writer.table, entry, now_secs, |old| {
                        merge(old, &entry, now_secs)
                    });
                let mut gone = None;
                let id = match result {
                    Ok(Inserted::Merged { previous }) => BanId(previous.id),
                    Ok(Inserted::New { removed, evicted }) => {
                        if let Some(r) = removed {
                            gone = self.key_of(writer, &r.key).map(|k| (k, evicted));
                            self.count(writer, &r.key, false);
                            let counter = if evicted {
                                &self.evicted
                            } else {
                                &self.expired
                            };
                            counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                        self.count(writer, &tkey, true);
                        if let BanKey::FingerprintIn(fp, c) = key {
                            self.remember_compound(writer, &tkey, fp, c);
                        }
                        BanId(id)
                    }
                    Err(()) => {
                        return Err(BouncerError::BanTableFull {
                            capacity: self.table.capacity(),
                        });
                    }
                };
                writer.offenders.record(tkey, now_secs);
                let plan = self.plan(writer, &tkey, now_secs);
                Ok((id, plan, gone, Some(own)))
            }
            Placement::Admin(cidr) => {
                let entry = AdminEntry {
                    id,
                    until,
                    issued,
                    actor,
                    reason: spec.reason,
                };
                let writer = &mut *w;
                writer.admin.retain(|(_, e)| !e.expired(now_secs));
                let id = match writer.admin.iter_mut().find(|(c, _)| *c == cidr) {
                    Some((_, existing)) => {
                        existing.until = longer(existing.until, until);
                        existing.actor = actor;
                        existing.reason = spec.reason;
                        existing.id
                    }
                    None => {
                        if writer.admin.len() >= MAX_ADMIN_PREFIXES {
                            return Err(BouncerError::BanTableFull {
                                capacity: MAX_ADMIN_PREFIXES as u32,
                            });
                        }
                        writer.admin.push((cidr, entry));
                        id
                    }
                };
                self.publish_admin(&writer.admin);
                Ok((BanId(id), None, None, Some(own)))
            }
        }
    }

    /// The id of an unexpired ban at a shorter automatic length that covers
    /// `tkey` and lasts at least until `until` (0 = permanent).
    fn covering_wider(&self, tkey: &TableKey, until: u32, now_secs: u64) -> Option<u64> {
        let c = view::cidr_of(tkey)?;
        (0..c.len())
            .rev()
            .filter(|&l| self.is_auto(c.family(), l))
            .filter_map(|l| c.parent(l))
            .filter_map(|p| self.table.get_owned(&Self::prefix_key(&p)))
            .find(|e| !e.expired(now_secs) && (e.until == 0 || (until != 0 && e.until >= until)))
            .map(|e| e.id)
    }

    /// Notes a newly banned address or prefix for escalation; returns the
    /// plan when its parent is due.
    fn plan(&self, w: &mut Writer, tkey: &TableKey, now_secs: u64) -> Option<Plan> {
        let child = view::cidr_of(tkey)?;
        let parent = Tracker::parent_of(&self.escalation, &child, |l| {
            self.is_auto(child.family(), l)
        })?;
        let children = w.tracker.note(&self.escalation, parent, child, now_secs)?;
        let mut longest = Some(0u64);
        let mut keys = Vec::with_capacity(children.len());
        for c in &children {
            let k = Self::prefix_key(c);
            if let Some(e) = self.table.get_owned(&k) {
                if e.expired(now_secs) {
                    continue;
                }
                longest = match (longest, e.until) {
                    (_, 0) | (None, _) => None,
                    (Some(l), u) => Some(l.max(u64::from(u).saturating_sub(now_secs))),
                };
                keys.push(k);
            }
        }
        // Children evicted or expired since they were counted still count;
        // the one just banned is always there to time the parent.
        (!keys.is_empty()).then_some(Plan {
            parent,
            children: keys,
            longest,
        })
    }

    /// The duration of an escalated parent: the longest remaining child times
    /// the factor, capped by the policy's maximum. `None` for permanent.
    pub(crate) fn escalated_secs(&self, plan: &Plan) -> Option<u64> {
        plan.longest.map(|l| {
            l.max(1)
                .saturating_mul(u64::from(self.escalation.factor))
                .min(self.policy.max_secs())
                .max(1)
        })
    }

    /// Removes children folded into a parent that ends at `parent_until`
    /// (0 = permanent). A child that outlasts the parent stays.
    pub(crate) fn fold(&self, children: &[TableKey], parent_until: u32) -> Vec<BanKey> {
        let mut w = self.lock();
        let writer = &mut *w;
        let mut n = Vec::new();
        for k in children {
            let Some(e) = self.table.get_owned(k) else {
                continue;
            };
            let outlasts = parent_until != 0 && (e.until == 0 || e.until > parent_until);
            if outlasts {
                continue;
            }
            if self.table.remove(&mut writer.table, k).is_some() {
                self.count(writer, k, false);
                if let Some(c) = view::cidr_of(k) {
                    n.push(if c.len() == c.family().max_len() {
                        BanKey::Address(c.network())
                    } else {
                        BanKey::Prefix(c)
                    });
                }
            }
        }
        n
    }

    /// Puts the children of a refused escalation back in the tracker; past
    /// the quota, the earliest-ending evictable children are dropped from
    /// the table so one allocation cannot fill it.
    pub(crate) fn refuse_escalation(&self, plan: &Plan, now_secs: u64) -> u32 {
        let mut w = self.lock();
        let writer = &mut *w;
        let quota = usize::from(self.escalation.max_children);
        let mut dropped = 0;
        let mut held: Vec<Entry> = plan
            .children
            .iter()
            .filter_map(|k| self.table.get_owned(k))
            .collect();
        if held.len() > quota {
            held.sort_by_key(|e| if e.until == 0 { u32::MAX } else { e.until });
            let excess = held.len() - quota;
            let mut kept = Vec::new();
            for e in held {
                if dropped < excess as u32
                    && e.evictable()
                    && self.table.remove(&mut writer.table, &e.key).is_some()
                {
                    self.count(writer, &e.key, false);
                    dropped += 1;
                    continue;
                }
                kept.push(e);
            }
            held = kept;
        }
        let cidrs: Vec<Cidr> = held.iter().filter_map(|e| view::cidr_of(&e.key)).collect();
        writer
            .tracker
            .restore(&self.escalation, plan.parent, &cidrs, now_secs);
        dropped
    }

    /// The longest ban of the duration policy, in whole seconds.
    pub(crate) fn max_secs(&self) -> u64 {
        self.policy.max_secs()
    }

    /// The offence record of a ban key.
    pub(crate) fn offender(&self, key: &BanKey, now_secs: u64) -> Option<Offence> {
        let Ok(Placement::Dynamic(tkey)) = self.place(&key.normalized(), Actor::App) else {
            return None;
        };
        self.lock().offenders.get(&tkey, now_secs)
    }

    /// Removes the ban on exactly this key.
    pub(crate) fn lift(&self, spec: &LiftSpec) -> Result<Lifted, BouncerError> {
        let key = spec.key.normalized();
        // Lifts are allowed for every actor; placement only finds the slot.
        let placement = self.place(&key, Actor::App)?;
        let mut w = self.lock();
        let writer = &mut *w;
        let removed = match placement {
            Placement::Dynamic(tkey) => match self.table.remove(&mut writer.table, &tkey) {
                Some(_) => {
                    self.count(writer, &tkey, false);
                    if let Some(child) = view::cidr_of(&tkey) {
                        let parent = Tracker::parent_of(&self.escalation, &child, |l| {
                            self.is_auto(child.family(), l)
                        });
                        if let Some(parent) = parent {
                            writer.tracker.forget(&parent, &child);
                        }
                    }
                    1
                }
                None => 0,
            },
            Placement::Admin(cidr) => {
                let before = writer.admin.len();
                writer.admin.retain(|(c, _)| *c != cidr);
                let n = (before - writer.admin.len()) as u32;
                if n > 0 {
                    self.publish_admin(&writer.admin);
                }
                n
            }
        };
        if removed == 0 {
            return Err(BouncerError::NotFound);
        }
        let tombstone = BanId(writer.next_id);
        writer.next_id += 1;
        Ok(Lifted { removed, tombstone })
    }

    /// A new id from this bouncer's sequence (a lift's tombstone id).
    pub(crate) fn new_id(&self) -> BanId {
        let mut w = self.lock();
        let id = BanId(w.next_id);
        w.next_id += 1;
        id
    }

    /// Refuses keys an allow-list entry or a trusted proxy covers.
    pub(crate) fn check(&self, key: &BanKey, guards: &Guards<'_>) -> Result<(), BouncerError> {
        self.guard(&key.normalized(), guards)
    }

    /// Whether an actor of `kind` could set this ban here: automation may
    /// not ban a bare fingerprint, a prefix at a length that is not
    /// automatic, or permanently (Sentinel may ban permanently).
    pub(crate) fn allowed_for(&self, key: &BanKey, kind: ActorKind, permanent: bool) -> bool {
        let actor = match kind {
            ActorKind::App | ActorKind::Admin => Actor::App,
            ActorKind::Sentinel => Actor::Sentinel,
            _ => Actor::Local,
        };
        if permanent && !actor.may_ban_permanently() {
            return false;
        }
        self.place(&key.normalized(), actor).is_ok()
    }

    fn publish_admin(&self, list: &[(Cidr, AdminEntry)]) {
        let set = PrefixSet::build(list, |a, _| *a);
        let count = set.len() as u64;
        *self
            .admin
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(set);
        self.admin_count.store(count, Ordering::Release);
        self.admin_version.fetch_add(1, Ordering::Release);
    }

    /// Keeps the per-length counts and the present masks exact.
    fn count(&self, w: &mut Writer, key: &TableKey, add: bool) {
        let bump = |c: &mut u32| {
            if add {
                *c += 1;
            } else {
                *c = c.saturating_sub(1);
            }
            *c
        };
        match key.kind {
            table::KIND_V4 => {
                let n = bump(&mut w.counts_v4[usize::from(key.len.min(32))]);
                set_bit(&self.present_v4, u32::from(key.len), n > 0);
            }
            table::KIND_V6 => {
                let len = key.len.min(128);
                let n = bump(&mut w.counts_v6[usize::from(len)]);
                set_bit(
                    &self.present_v6[usize::from(len / 64)],
                    u32::from(len % 64),
                    n > 0,
                );
            }
            kind => {
                let n = bump(&mut w.counts_ident[usize::from(kind & 15)]);
                set_bit(&self.present_ident, u32::from(kind & 63), n > 0);
            }
        }
    }

    /// Door-side lookup of an address: every automatic length in use, then
    /// the administrator set.
    ///
    /// The probes for the lengths in use are prepared first and their first
    /// tag words loaded together, so their cache misses overlap instead of
    /// queueing.
    #[inline]
    pub(crate) fn lookup_addr(&self, addr: IpAddr, now_secs: u64) -> Lookup {
        let mut hashes = AddrHashes::new(self.table.hasher(), addr);
        self.lookup_hashed(&mut hashes, now_secs)
    }

    /// The table's hash key, for [`AddrHashes`].
    pub(crate) fn hasher(&self) -> HashKey {
        self.table.hasher()
    }

    /// As [`lookup_addr`](Self::lookup_addr), through a hash cache the door
    /// budgets reuse.
    #[inline]
    pub(crate) fn lookup_hashed(&self, hashes: &mut AddrHashes, now_secs: u64) -> Lookup {
        let host = *hashes.host();
        let addr = host.network();
        let mut busy = false;
        let mut lengths = [0u8; PROBE_BATCH];
        let mut count = 0;
        let mut overflow = false;
        let mut take = |len: u8| {
            if count < PROBE_BATCH {
                lengths[count] = len;
                count += 1;
            } else {
                overflow = true;
            }
        };
        match host.family() {
            Family::V4 => {
                let mut m = self.present_v4.load(Ordering::Acquire);
                while m != 0 {
                    take(m.trailing_zeros() as u8);
                    m &= m - 1;
                }
            }
            Family::V6 => {
                for (word, present) in self.present_v6.iter().enumerate() {
                    let mut m = present.load(Ordering::Acquire);
                    while m != 0 {
                        take((word as u32 * 64 + m.trailing_zeros()) as u8);
                        m &= m - 1;
                    }
                }
            }
        }
        let mut starts = [(0usize, 0u8); PROBE_BATCH];
        for i in 0..count {
            starts[i] = self.table.locate_hash(hashes.get(lengths[i]));
        }
        let mut tags = [0u64; PROBE_BATCH];
        for i in 0..count {
            tags[i] = self.table.first_tags(starts[i].0);
        }
        for i in 0..count {
            // The full key is only compared on a tag match.
            let key = Self::prefix_key(&host.parent(lengths[i]).unwrap_or(host));
            match self
                .table
                .find_at(&key, starts[i].0, starts[i].1, tags[i], now_secs)
            {
                Probe::Hit(e) => return Lookup::Banned(e.id),
                Probe::Busy => busy = true,
                Probe::Miss => {}
            }
        }
        if overflow {
            // More automatic lengths in use than one batch: probe the rest
            // one at a time (only with unusual length configurations).
            match self.lookup_rest(&host, &lengths[..count], now_secs) {
                Probe::Hit(e) => return Lookup::Banned(e.id),
                Probe::Busy => busy = true,
                Probe::Miss => {}
            }
        }
        if self.admin_count.load(Ordering::Acquire) > 0 {
            match self
                .with_admin(|set| set.find_map(addr, |e| (!e.expired(now_secs)).then_some(e.id)))
            {
                Some(Some(id)) => return Lookup::Banned(id),
                Some(None) => {}
                None => busy = true,
            }
        }
        if busy { Lookup::Busy } else { Lookup::Clear }
    }

    /// Probes every length in use that is not in `done`.
    #[cold]
    fn lookup_rest(&self, host: &Cidr, done: &[u8], now_secs: u64) -> Probe {
        let mut busy = false;
        for len in 0..=host.family().max_len() {
            if done.contains(&len) || !self.length_present(host.family(), len) {
                continue;
            }
            if let Some(p) = host.parent(len) {
                match self.table.find(&Self::prefix_key(&p), now_secs) {
                    Probe::Hit(e) => return Probe::Hit(e),
                    Probe::Busy => busy = true,
                    Probe::Miss => {}
                }
            }
        }
        if busy { Probe::Busy } else { Probe::Miss }
    }

    fn length_present(&self, family: Family, len: u8) -> bool {
        match family {
            Family::V4 => len <= 32 && self.present_v4.load(Ordering::Acquire) & (1u64 << len) != 0,
            Family::V6 => {
                len <= 128
                    && self.present_v6[usize::from(len / 64)].load(Ordering::Acquire)
                        & (1u64 << (len % 64))
                        != 0
            }
        }
    }

    /// Lookup of one table key, for identity checks.
    /// Whether any ban of an identity kind may be held (a fingerprint bind
    /// also checks compound keys).
    #[inline]
    pub(crate) fn may_hold(&self, kind: u8) -> bool {
        let mut mask = 1u64 << (kind & 63);
        if kind == table::KIND_FINGERPRINT {
            mask |= 1u64 << table::KIND_FINGERPRINT_IN;
        }
        self.present_ident.load(Ordering::Acquire) & mask != 0
    }

    pub(crate) fn lookup_key(&self, key: &TableKey, now_secs: u64) -> Probe {
        if self.present_ident.load(Ordering::Acquire) & (1u64 << (key.kind & 63)) == 0 {
            return Probe::Miss;
        }
        self.table.find(key, now_secs)
    }

    /// Bind-side check of a fingerprint: a bare fingerprint ban, or a ban of
    /// the fingerprint within any automatic prefix of `source`.
    pub(crate) fn lookup_fingerprint(
        &self,
        fp: &crate::keys::FingerprintKey,
        source: Option<IpAddr>,
        now_secs: u64,
    ) -> Probe {
        let (k0, k1) = fp.words();
        let bare = TableKey {
            kind: table::KIND_FINGERPRINT,
            len: 0,
            k0,
            k1,
        };
        let mut busy = false;
        match self.lookup_key(&bare, now_secs) {
            Probe::Hit(e) => return Probe::Hit(e),
            Probe::Busy => busy = true,
            Probe::Miss => {}
        }
        if let Some(src) = source {
            if self.present_ident.load(Ordering::Acquire) & (1u64 << table::KIND_FINGERPRINT_IN)
                != 0
            {
                let host = Cidr::host(src);
                let lengths: Vec<u8> = match host.family() {
                    Family::V4 => (0..=32u8)
                        .filter(|&l| self.is_auto(Family::V4, l))
                        .collect(),
                    Family::V6 => (0..=128u8)
                        .filter(|&l| self.is_auto(Family::V6, l))
                        .collect(),
                };
                for len in lengths {
                    if let Some(p) = host.parent(len) {
                        match self.table.find(&self.fingerprint_in_key(fp, &p), now_secs) {
                            Probe::Hit(e) => return Probe::Hit(e),
                            Probe::Busy => busy = true,
                            Probe::Miss => {}
                        }
                    }
                }
            }
        }
        if busy { Probe::Busy } else { Probe::Miss }
    }

    /// Runs `f` on the current administrator set through the per-thread
    /// cache; `None` only if neither the cache nor the lock can be used.
    fn with_admin<T>(&self, f: impl FnOnce(&PrefixSet<AdminEntry>) -> T) -> Option<T> {
        let version = self.admin_version.load(Ordering::Acquire);
        let mut f = Some(f);
        let cached = ADMIN_CACHE
            .try_with(|cell| {
                let mut slot = cell.try_borrow_mut().ok()?;
                let fresh =
                    matches!(&*slot, Some((uid, v, _)) if *uid == self.uid && *v == version);
                if !fresh {
                    *slot = Some((self.uid, version, self.read_admin()?));
                }
                let set = slot.as_ref().map(|(_, _, s)| s)?;
                f.take().map(|f| f(set))
            })
            .ok()
            .flatten();
        match cached {
            Some(t) => Some(t),
            None => {
                let set = self.read_admin()?;
                f.take().map(|f| f(&set))
            }
        }
    }

    fn read_admin(&self) -> Option<Arc<PrefixSet<AdminEntry>>> {
        self.admin.read().ok().map(|g| Arc::clone(&g))
    }

    /// Bytes held by the administrator set and offender memory.
    pub(crate) fn admin_bytes(&self) -> u64 {
        self.read_admin().map_or(0, |s| s.bytes()) + self.lock().offenders.bytes()
    }
}

/// Merges a new ban into an existing one with the same key: the longer end
/// wins (permanent above all), the offence count grows, and a ban that is not
/// evictable keeps its actor and reason until it expires.
fn merge(old: &Entry, new: &Entry, now_secs: u64) -> Entry {
    if old.expired(now_secs) {
        return Entry {
            id: old.id,
            offences: old.offences.saturating_add(1),
            ..*new
        };
    }
    let keep_old_owner = !old.evictable();
    Entry {
        key: new.key,
        flags: if keep_old_owner { old.flags } else { new.flags },
        actor: if keep_old_owner { old.actor } else { new.actor },
        reason: if keep_old_owner {
            old.reason
        } else {
            new.reason
        },
        offences: old.offences.saturating_add(1),
        until: longer(old.until, new.until),
        // The later issue time: a lift stamped between two bans of the key
        // must not remove the later one (merges from other nodes arrive in
        // any order).
        issued: old.issued.max(new.issued),
        id: old.id,
    }
}

fn longer(a: u32, b: u32) -> u32 {
    if a == 0 || b == 0 { 0 } else { a.max(b) }
}

fn set_bit(word: &AtomicU64, bit: u32, on: bool) {
    if on {
        word.fetch_or(1u64 << bit, Ordering::Release);
    } else {
        word.fetch_and(!(1u64 << bit), Ordering::Release);
    }
}

/// Seconds since start as a stored `u32`, clamped.
fn clamp_secs(secs: u64) -> u32 {
    u32::try_from(secs).unwrap_or(u32::MAX - 1)
}

/// The stored end of a ban lasting `secs` from `now_secs`; never 0
/// (which means permanent).
fn end(now_secs: u64, secs: u64) -> u32 {
    clamp_secs(now_secs.saturating_add(secs)).clamp(1, u32::MAX - 1)
}

#[cfg(all(test, not(bouncer_loom)))]
mod tests {
    use super::*;
    use crate::allow::AllowKind;

    fn mem(capacity: u32) -> BanMemory {
        BanMemory::new(
            capacity,
            HashKey::new(5, 6),
            &[32, 24],
            &[64, 56, 48],
            DurationPolicy::default().jitter(Duration::ZERO),
            EscalationPolicy::default().off(),
            9,
        )
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn c(s: &str) -> Cidr {
        s.parse().unwrap()
    }

    struct Sets {
        allow: PrefixSet<AllowKind>,
        proxies: PrefixSet<()>,
    }

    impl Sets {
        fn none() -> Self {
            Sets {
                allow: PrefixSet::empty(),
                proxies: PrefixSet::empty(),
            }
        }
        fn guards(&self) -> Guards<'_> {
            Guards {
                immune: &self.allow,
                proxies: &self.proxies,
            }
        }
    }

    #[test]
    fn test_ban_address_and_prefix_refused_at_lookup() {
        let m = mem(64);
        let s = Sets::none();
        m.ban(
            &BanSpec::address(ip("203.0.113.7")),
            &s.guards(),
            Now::default(),
        )
        .unwrap();
        assert!(matches!(
            m.lookup_addr(ip("203.0.113.7"), 0),
            Lookup::Banned(_)
        ));
        assert_eq!(m.lookup_addr(ip("203.0.113.8"), 0), Lookup::Clear);
        m.ban(
            &BanSpec::prefix(c("198.51.100.0/24")),
            &s.guards(),
            Now::default(),
        )
        .unwrap();
        assert!(matches!(
            m.lookup_addr(ip("198.51.100.200"), 0),
            Lookup::Banned(_)
        ));
    }

    #[test]
    fn test_ban_ipv6_address_keys_at_64() {
        let m = mem(64);
        let s = Sets::none();
        m.ban(
            &BanSpec::address(ip("2001:db8:1:2::77")),
            &s.guards(),
            Now::default(),
        )
        .unwrap();
        assert!(matches!(
            m.lookup_addr(ip("2001:db8:1:2:ffff::1"), 0),
            Lookup::Banned(_)
        ));
        assert_eq!(m.lookup_addr(ip("2001:db8:1:3::1"), 0), Lookup::Clear);
    }

    #[test]
    fn test_ban_admin_prefix_any_length_and_automation_refused() {
        let m = mem(64);
        let s = Sets::none();
        m.ban(
            &BanSpec::prefix(c("10.0.0.0/8")),
            &s.guards(),
            Now::default(),
        )
        .unwrap();
        assert!(matches!(
            m.lookup_addr(ip("10.200.0.1"), 0),
            Lookup::Banned(_)
        ));
        let err = m.ban(
            &BanSpec::prefix(c("11.0.0.0/8")).by(Actor::Policy(1)),
            &s.guards(),
            Now::default(),
        );
        assert!(matches!(
            err,
            Err(BouncerError::InvalidPrefix { len: 8, .. })
        ));
        let all = m.ban(
            &BanSpec::prefix(c("0.0.0.0/0")).by(Actor::Local),
            &s.guards(),
            Now::default(),
        );
        assert!(all.is_err());
    }

    #[test]
    fn test_ban_duration_policy_grows_and_caps() {
        let p = DurationPolicy::default().jitter(Duration::ZERO);
        let mut rng = Rng::from_seed(1);
        assert_eq!(p.seconds(0, &mut rng), 600);
        assert_eq!(p.seconds(1, &mut rng), 1200);
        assert_eq!(p.seconds(20, &mut rng), 7 * 24 * 3600);
        assert_eq!(p.seconds(u16::MAX, &mut rng), 7 * 24 * 3600);
        let one = DurationPolicy::default().factor(1).jitter(Duration::ZERO);
        assert_eq!(one.seconds(50, &mut rng), 600);
        let j = DurationPolicy::default();
        for off in 0..40 {
            assert!(j.seconds(off, &mut rng) <= j.ceiling());
        }
    }

    #[test]
    fn test_ban_repeat_offender_gets_longer_ban() {
        let m = mem(64);
        let s = Sets::none();
        let spec = BanSpec::address(ip("192.0.2.1")).by(Actor::Local);
        m.ban(&spec, &s.guards(), Now::default()).unwrap();
        // expire it, then ban again: offences 1, twice as long
        let later = Now::from_nanos(700 * 1_000_000_000);
        assert_eq!(m.lookup_addr(ip("192.0.2.1"), later.secs()), Lookup::Clear);
        m.ban(&spec, &s.guards(), later).unwrap();
        assert!(matches!(
            m.lookup_addr(ip("192.0.2.1"), later.secs() + 1199),
            Lookup::Banned(_)
        ));
        assert_eq!(
            m.lookup_addr(ip("192.0.2.1"), later.secs() + 1200),
            Lookup::Clear
        );
    }

    #[test]
    fn test_ban_fixed_zero_and_permanent_rules() {
        let m = mem(8);
        let s = Sets::none();
        let a = ip("192.0.2.9");
        assert_eq!(
            m.ban(
                &BanSpec::address(a).for_duration(Duration::ZERO),
                &s.guards(),
                Now::default()
            ),
            Err(BouncerError::InvalidDuration)
        );
        assert_eq!(
            m.ban(
                &BanSpec::address(a).permanent().by(Actor::Policy(1)),
                &s.guards(),
                Now::default()
            ),
            Err(BouncerError::PermanentNotAllowed)
        );
        m.ban(
            &BanSpec::address(a).permanent().by(Actor::Admin(1)),
            &s.guards(),
            Now::default(),
        )
        .unwrap();
        assert!(matches!(
            m.lookup_addr(a, u64::from(u32::MAX)),
            Lookup::Banned(_)
        ));
    }

    #[test]
    fn test_ban_allowlisted_and_proxy_refused() {
        let m = mem(8);
        let s = Sets {
            allow: PrefixSet::build(&[(c("10.20.0.0/16"), AllowKind::Immune)], |a, _| *a),
            proxies: PrefixSet::build(&[(c("10.9.0.1/32"), ())], |a, _| *a),
        };
        assert!(matches!(
            m.ban(
                &BanSpec::address(ip("10.20.1.1")),
                &s.guards(),
                Now::default()
            ),
            Err(BouncerError::AllowListed { .. })
        ));
        assert_eq!(
            m.ban(
                &BanSpec::address(ip("10.9.0.1")),
                &s.guards(),
                Now::default()
            ),
            Err(BouncerError::TrustedProxyTarget)
        );
        // a prefix that merely contains an allow entry or a proxy is allowed
        m.ban(
            &BanSpec::prefix(c("10.0.0.0/8")),
            &s.guards(),
            Now::default(),
        )
        .unwrap();
    }

    #[test]
    fn test_lift_removes_exact_key_only() {
        let m = mem(8);
        let s = Sets::none();
        m.ban(
            &BanSpec::prefix(c("203.0.113.0/24")),
            &s.guards(),
            Now::default(),
        )
        .unwrap();
        assert_eq!(
            m.lift(&LiftSpec::key(ip("203.0.113.7"))),
            Err(BouncerError::NotFound)
        );
        assert_eq!(
            m.lift(&LiftSpec::key(c("203.0.113.0/24"))).unwrap().removed,
            1
        );
        assert_eq!(m.lookup_addr(ip("203.0.113.7"), 0), Lookup::Clear);
        m.ban(
            &BanSpec::prefix(c("10.0.0.0/8")),
            &s.guards(),
            Now::default(),
        )
        .unwrap();
        assert_eq!(m.lift(&LiftSpec::key(c("10.0.0.0/8"))).unwrap().removed, 1);
        assert_eq!(m.lookup_addr(ip("10.0.0.1"), 0), Lookup::Clear);
    }

    #[test]
    fn test_present_mask_cleared_when_last_entry_lifted() {
        let m = mem(8);
        let s = Sets::none();
        m.ban(
            &BanSpec::prefix(c("203.0.113.0/24")),
            &s.guards(),
            Now::default(),
        )
        .unwrap();
        assert_ne!(m.present_v4.load(Ordering::Relaxed) & (1 << 24), 0);
        assert_eq!(
            m.lift(&LiftSpec::key(c("203.0.113.0/24"))).unwrap().removed,
            1
        );
        assert_eq!(m.present_v4.load(Ordering::Relaxed) & (1 << 24), 0);
    }

    #[test]
    fn test_admin_never_evicted_table_full() {
        let m = mem(4);
        let s = Sets::none();
        for i in 1..=4u8 {
            m.ban(
                &BanSpec::address(IpAddr::from([192, 0, 2, i])),
                &s.guards(),
                Now::default(),
            )
            .unwrap();
        }
        let r = m.ban(
            &BanSpec::address(ip("192.0.2.200")).by(Actor::Local),
            &s.guards(),
            Now::default(),
        );
        assert_eq!(r, Err(BouncerError::BanTableFull { capacity: 4 }));
        assert_eq!(m.live(), 4);
    }

    #[test]
    fn test_fingerprint_rules() {
        let m = mem(8);
        let s = Sets::none();
        let fp = crate::keys::FingerprintKey::from_digest([4; 16]);
        assert_eq!(
            m.ban(
                &BanSpec::key(fp).by(Actor::Local),
                &s.guards(),
                Now::default()
            ),
            Err(BouncerError::InvalidTarget)
        );
        m.ban(&BanSpec::key(fp), &s.guards(), Now::default())
            .unwrap();
        m.ban(
            &BanSpec::key(BanKey::FingerprintIn(fp, c("203.0.113.0/24"))).by(Actor::Local),
            &s.guards(),
            Now::default(),
        )
        .unwrap();
        let k = m.fingerprint_in_key(&fp, &c("203.0.113.0/24"));
        assert!(matches!(m.lookup_key(&k, 0), Probe::Hit(_)));
        let other = m.fingerprint_in_key(&fp, &c("203.0.114.0/24"));
        assert_eq!(m.lookup_key(&other, 0), Probe::Miss);
    }
}
