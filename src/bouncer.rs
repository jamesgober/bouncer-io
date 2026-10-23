//! The bouncer and its builder.

use core::{cell::Cell as StdCell, fmt};
use std::{net::IpAddr, sync::Arc};

use clock_lib::{Clock, Monotonic, SystemClock};

use crate::{
    allow::{AllowKind, AllowList},
    bans::{
        BanId, BanMemory, BanSpec, DurationPolicy, Guards, LiftSpec, Lifted, compiled::PrefixSet,
    },
    door::{Judgement, Provenance, Refusal},
    error::{BouncerError, ConfigError, ConfigProblem},
    hash::{HashKey, Seeds},
    keys::{Cidr, ConnId, normalize},
    registry::{Epoch, F_IMMUNE, F_PROXY_HOP, Registry, Shard},
    sync::Ordering,
    ticket::{Issue, Ticket, TicketKind},
    time::Now,
};

/// Most tickets a bouncer holds: the cell index has 24 bits per shard.
const MAX_TICKETS: u32 = 1 << 24;
/// Most shards: the shard id has 8 bits.
const MAX_SHARDS: u16 = 256;
/// Most ban entries.
const MAX_BAN_CAPACITY: u32 = 1 << 26;

/// State every shard reads: time, ban memory, allow list, trusted proxies.
pub(crate) struct Shared {
    clock: Arc<dyn Clock>,
    start: Monotonic,
    pub(crate) bans: BanMemory,
    pub(crate) allow: PrefixSet<AllowKind>,
    pub(crate) proxies: PrefixSet<()>,
    pub(crate) references: HashKey,
    pub(crate) tickets_capacity: u32,
    pub(crate) registry: Registry,
}

impl Shared {
    #[inline]
    pub(crate) fn now(&self) -> Now {
        Now::from_duration(self.clock.now().saturating_duration_since(self.start))
    }

    fn guards(&self) -> Guards<'_> {
        Guards {
            immune: &self.allow,
            proxies: &self.proxies,
        }
    }
}

struct Inner {
    shared: Arc<Shared>,
    shards: Box<[Arc<Shard>]>,
    capacity: Capacity,
}

/// The gate itself. One `Bouncer` serves a whole process; clones share all
/// state. Every method takes `&self` and may be called from any thread.
///
/// # Examples
///
/// ```
/// use bouncer_io::{Bouncer, RequestId};
///
/// let bouncer = Bouncer::new();
/// bouncer.ban("198.51.100.9".parse::<std::net::IpAddr>()?)?;
/// assert!(bouncer.door("198.51.100.9".parse()?).is_err());   // refused at the door
///
/// let conn = bouncer.door("203.0.113.7".parse()?)?;
/// let mut request = conn.request(RequestId(1))?;
/// assert!(request.checkpoint().is_pass());
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
    /// A bouncer with safe defaults: 65,536 tickets, 1,048,576 ban entries,
    /// automatic keys at IPv4 /32 and /24 and IPv6 /64, /56, /48, no allow
    /// list, no trusted proxies.
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
        // The default configuration is valid by construction.
        match BouncerBuilder::default().try_build() {
            Ok(b) => b,
            Err(_) => BouncerBuilder::default()
                .tickets(1)
                .ban_capacity(1)
                .build_unchecked(),
        }
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

    /// Checkpoint B1, before a byte is read: trusted proxy, allow list, and
    /// ban memory, from the peer address alone. On success it issues a
    /// connection ticket.
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
        let peer = normalize(peer);
        let (flags, source) = match self.inner.shared.judge(peer, provenance, now) {
            Judgement::Admit { immune } => (if immune { F_IMMUNE } else { 0 }, Some(peer)),
            Judgement::ProxyHop => (F_PROXY_HOP, None),
            Judgement::Refuse(r) => return Err(r),
        };
        let flags = flags | (provenance.code() << crate::registry::PROVENANCE_SHIFT);
        let shards = &self.inner.shards;
        let first = shard_hint() as usize & (shards.len() - 1);
        let shard = &shards[first];
        let id = match conn {
            Some(c) => c.0,
            None => {
                let k = self.inner.shared.registry.next_conn[first].fetch_add(1, Ordering::Relaxed);
                (1u64 << 63) | ((k & ((1u64 << 55) - 1)) << 8) | u64::from(shard.id)
            }
        };
        Ticket::issue(
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
        )
        .ok_or(Refusal::RegistryFull)
    }

    /// Adds a ban. An address or `Cidr` converts directly (timed by the
    /// duration policy, actor [`Actor::App`](crate::Actor::App)); a
    /// [`BanSpec`] sets the rest. Takes effect at the next door check on every
    /// thread; connections already admitted are not touched.
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
        let shared = &self.inner.shared;
        shared
            .bans
            .ban(&spec.into(), &shared.guards(), shared.now())
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
        self.inner.shared.bans.lift(&spec.into())
    }

    /// The bouncer's monotonic time base, for the `_at` functions.
    #[must_use]
    pub fn now(&self) -> Now {
        self.inner.shared.now()
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
        let mut c = self.inner.capacity;
        c.table_bytes = self.inner.shared.bans.table_bytes();
        c.total_bytes = c.table_bytes
            + self.inner.shared.bans.admin_bytes()
            + self.inner.shared.registry.bytes()
            + self.inner.shared.allow.bytes()
            + self.inner.shared.proxies.bytes();
        c
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
    /// Revocation entries (arrives with revocation tables).
    pub revocations: u32,
    /// Budget keys (arrives with budgets).
    pub budget_keys: u32,
    /// Bytes of the dynamic ban table.
    pub table_bytes: u64,
    /// Bytes of every table together.
    pub total_bytes: u64,
}

/// Configuration for a [`Bouncer`]. Every setter is optional; `try_build`
/// validates everything at once and allocates every table.
///
/// # Examples
///
/// ```
/// use bouncer_io::{Bouncer, DurationPolicy};
/// use std::time::Duration;
/// let bouncer = Bouncer::builder()
///     .durations(DurationPolicy::default().base(Duration::from_secs(900)).max(Duration::from_secs(86_400)))
///     .ipv6_lengths(&[64, 48])
///     .try_build()?;
/// # Ok::<(), bouncer_io::BouncerError>(())
/// ```
#[must_use]
pub struct BouncerBuilder {
    tickets: u32,
    shards: Option<u16>,
    ban_capacity: u32,
    ipv4_lengths: Vec<u8>,
    ipv6_lengths: Vec<u8>,
    durations: DurationPolicy,
    allow: AllowList,
    trusted_proxies: Vec<Cidr>,
    clock: Option<Arc<dyn Clock>>,
    seed: Option<[u8; 32]>,
}

impl Default for BouncerBuilder {
    fn default() -> Self {
        BouncerBuilder {
            tickets: crate::DEFAULT_TICKETS,
            shards: None,
            ban_capacity: crate::DEFAULT_BAN_CAPACITY,
            ipv4_lengths: crate::DEFAULT_IPV4_LENGTHS.to_vec(),
            ipv6_lengths: crate::DEFAULT_IPV6_LENGTHS.to_vec(),
            durations: DurationPolicy::default(),
            allow: AllowList::new(),
            trusted_proxies: Vec::new(),
            clock: None,
            seed: None,
        }
    }
}

impl fmt::Debug for BouncerBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BouncerBuilder")
            .field("tickets", &self.tickets)
            .field("shards", &self.shards)
            .field("ban_capacity", &self.ban_capacity)
            .field("ipv4_lengths", &self.ipv4_lengths)
            .field("ipv6_lengths", &self.ipv6_lengths)
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

    /// The allow list, compiled at build.
    pub fn allow(mut self, list: AllowList) -> Self {
        self.allow = list;
        self
    }

    /// Proxies whose PROXY and forwarded headers are believed; never banned
    /// or struck. Use the same list the transport uses.
    pub fn trusted_proxies(mut self, cidrs: &[Cidr]) -> Self {
        self.trusted_proxies = cidrs.to_vec();
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

    /// Validates the configuration and allocates every table.
    ///
    /// # Errors
    ///
    /// [`BouncerError::Config`] naming the field and the accepted range.
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
        if let Some(s) = self.shards {
            check_range("shards", u64::from(s), 1, u64::from(MAX_SHARDS))?;
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
        Ok(self.build_unchecked_with(self.allow.compile()?))
    }

    /// Builds without validating; only for configurations known valid.
    fn build_unchecked(self) -> Bouncer {
        let allow = self.allow.compile().unwrap_or_else(|_| PrefixSet::empty());
        self.build_unchecked_with(allow)
    }

    fn build_unchecked_with(&self, allow: PrefixSet<AllowKind>) -> Bouncer {
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

        let shared = Arc::new(Shared {
            start: clock.now(),
            clock,
            bans: BanMemory::new(
                self.ban_capacity,
                seeds.tables,
                &v4,
                &v6,
                self.durations,
                seeds.rng,
            ),
            allow,
            proxies,
            references: seeds.references,
            tickets_capacity: tickets,
            registry: Registry::new(shard_count, per_shard),
        });
        let epoch = Arc::new(Epoch::new());
        let shards: Box<[Arc<Shard>]> = (0..shard_count)
            .map(|i| {
                Arc::new(Shard {
                    id: i as u8,
                    epoch: Arc::clone(&epoch),
                    shared: Arc::clone(&shared),
                })
            })
            .collect();
        let capacity = Capacity {
            tickets,
            bans: shared.bans.capacity(),
            revocations: 0,
            budget_keys: 0,
            table_bytes: 0,
            total_bytes: 0,
        };
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bouncer_and_ticket_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Bouncer>();
        assert_send_sync::<Ticket>();
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
        let cases: [(BouncerBuilder, &str); 6] = [
            (Bouncer::builder().tickets(0), "tickets"),
            (Bouncer::builder().tickets(MAX_TICKETS + 1), "tickets"),
            (Bouncer::builder().ban_capacity(0), "ban_capacity"),
            (Bouncer::builder().shards(0), "shards"),
            (Bouncer::builder().ipv4_lengths(&[24]), "ipv4_lengths"),
            (Bouncer::builder().ipv6_lengths(&[]), "ipv6_lengths"),
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
        assert!(format!("{b:?}").contains("Bouncer"));
    }
}
