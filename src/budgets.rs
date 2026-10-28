//! Budgets: "is this source over its allowance", one input to the door. Not
//! the purpose of the crate.
//!
//! The rate math is rate-net's GCRA and better-bucket's token bucket (both
//! without default features, so neither brings a third-party crate). Keyed
//! rates keep only a GCRA's arrival time per key, in the key's own slot of
//! bouncer's bounded table, under parameters shared by the tier ([`Pace`],
//! rate-net's integer math, tested against it); the token buckets keep a
//! parallel array.
//! Eviction never resets a limit: a cell is taken over only once it has
//! fully recovered and holds no connections.

use core::time::Duration;
use std::net::IpAddr;

use better_bucket::{BucketConfig, BucketCore};
use rate_net::Quota;

use crate::{
    claims::Claims,
    error::{BouncerError, ConfigError, ConfigProblem},
    hash::HashKey,
    keys::{Cidr, Family, TenantKey},
    sync::{AtomicU32, AtomicU64, Ordering},
    ticket::LaneClass,
    time::Now,
};

/// Most tenant plans one bouncer holds.
const MAX_PLANS: usize = 65_536;

/// A rate: `limit` events per `period`, with a burst.
///
/// bouncer's own type, converted to rate-net's internally, so a new major
/// version of rate-net never changes bouncer's API.
///
/// # Examples
///
/// ```
/// use bouncer_io::Rate;
/// let r = Rate::per_second(20).burst(40);
/// assert_eq!(r.limit(), 20);
/// assert_eq!(r.burst_size(), 40);
/// assert!(Rate::new(0, std::time::Duration::from_secs(1)).is_err());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rate {
    limit: u32,
    period: Duration,
    burst: u32,
}

impl Rate {
    /// `limit` per second; burst equal to the limit.
    #[must_use]
    pub const fn per_second(limit: u32) -> Rate {
        Rate {
            limit,
            period: Duration::from_secs(1),
            burst: limit,
        }
    }

    /// `limit` per minute; burst equal to the limit.
    #[must_use]
    pub const fn per_minute(limit: u32) -> Rate {
        Rate {
            limit,
            period: Duration::from_secs(60),
            burst: limit,
        }
    }

    /// `limit` per `period`.
    ///
    /// # Errors
    ///
    /// [`BouncerError::Config`] for a zero limit or a zero period.
    pub fn new(limit: u32, period: Duration) -> Result<Rate, BouncerError> {
        if limit == 0 {
            return Err(ConfigError::new("rate", ConfigProblem::TooSmall { min: 1 }).into());
        }
        if period.is_zero() {
            return Err(ConfigError::new("rate", ConfigProblem::InvalidDuration).into());
        }
        Ok(Rate {
            limit,
            period,
            burst: limit,
        })
    }

    /// The burst: how many may arrive at once.
    #[must_use]
    pub const fn burst(mut self, burst: u32) -> Rate {
        self.burst = burst;
        self
    }

    /// The limit per period.
    #[must_use]
    pub const fn limit(&self) -> u32 {
        self.limit
    }

    /// The burst size.
    #[must_use]
    pub const fn burst_size(&self) -> u32 {
        self.burst
    }

    fn quota(&self, field: &'static str) -> Result<Quota, ConfigError> {
        if self.limit == 0 || self.burst == 0 {
            return Err(ConfigError::new(field, ConfigProblem::TooSmall { min: 1 }));
        }
        Quota::rate(self.limit, self.period)
            .map(|q| q.with_burst(self.burst))
            .map_err(|_| ConfigError::new(field, ConfigProblem::InvalidDuration))
    }

    /// The token-bucket form: capacity = burst, refilled `limit` per period.
    fn bucket(&self, field: &'static str) -> Result<BucketConfig, ConfigError> {
        BucketConfig::new(self.burst, self.limit, self.period, self.burst)
            .map_err(|_| ConfigError::new(field, ConfigProblem::TooSmall { min: 1 }))
    }
}

/// Budget configuration: door, lane, and tenant budgets.
///
/// | Budget | Key | Checked at |
/// |---|---|---|
/// | accept rate | client, then prefix | door |
/// | concurrency | client, then prefix | door; returned on release |
/// | lane rate | session, else client, per lane | [`Ticket::bind_lane`](crate::Ticket::bind_lane) |
/// | tenant rate (token bucket, per-tenant plans) | tenant | [`Ticket::bind_tenant`](crate::Ticket::bind_tenant) |
/// | tenant in-flight | tenant | `bind_tenant`; returned on release |
///
/// # Examples
///
/// ```
/// use bouncer_io::{Bouncer, Budgets, LaneClass, Rate, TenantKey};
/// let bouncer = Bouncer::builder()
///     .budgets(
///         Budgets::default()
///             .door_rate(Rate::per_second(50).burst(100), Rate::per_second(500))
///             .door_concurrency(32, 256)
///             .lane_rate(LaneClass::Auth, Rate::per_minute(10))
///             .tenant_rate(Rate::per_second(200))
///             .tenant_plan(TenantKey(7), Rate::per_second(2_000).burst(4_000))
///             .tenant_in_flight(64),
///     )
///     .try_build()?;
/// # let _ = bouncer;
/// # Ok::<(), bouncer_io::BouncerError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Budgets {
    door_rate: Option<(Rate, Rate)>,
    door_concurrency: Option<(u32, u32)>,
    lanes: [Option<Rate>; LaneClass::COUNT],
    tenant_rate: Option<Rate>,
    tenant_plans: Vec<(TenantKey, Rate)>,
    tenant_in_flight: Option<u32>,
    capacity: u32,
}

impl Default for Budgets {
    /// Door: 20 per second (burst 40) and 64 concurrent per address; 200 per
    /// second and 512 concurrent per prefix (IPv4 /24, IPv6 /48; an IPv6
    /// "address" is its /64).
    fn default() -> Self {
        Budgets {
            door_rate: Some((Rate::per_second(20).burst(40), Rate::per_second(200))),
            door_concurrency: Some((64, 512)),
            lanes: [None; LaneClass::COUNT],
            tenant_rate: None,
            tenant_plans: Vec::new(),
            tenant_in_flight: None,
            capacity: 65_536,
        }
    }
}

impl Budgets {
    /// No budgets at all.
    #[must_use]
    pub fn off() -> Budgets {
        Budgets {
            door_rate: None,
            door_concurrency: None,
            lanes: [None; LaneClass::COUNT],
            tenant_rate: None,
            tenant_plans: Vec::new(),
            tenant_in_flight: None,
            capacity: 16,
        }
    }

    /// The accept rate per address and per prefix.
    #[must_use]
    pub fn door_rate(mut self, per_address: Rate, per_prefix: Rate) -> Budgets {
        self.door_rate = Some((per_address, per_prefix));
        self
    }

    /// Concurrent connections per address and per prefix.
    #[must_use]
    pub fn door_concurrency(mut self, per_address: u32, per_prefix: u32) -> Budgets {
        self.door_concurrency = Some((per_address, per_prefix));
        self
    }

    /// The rate of one lane, per session (or per client when no session is
    /// bound), charged at [`Ticket::bind_lane`](crate::Ticket::bind_lane).
    #[must_use]
    pub fn lane_rate(mut self, lane: LaneClass, per_key: Rate) -> Budgets {
        self.lanes[lane.index()] = Some(per_key);
        self
    }

    /// The default rate per tenant (a token bucket), charged at
    /// [`Ticket::bind_tenant`](crate::Ticket::bind_tenant).
    #[must_use]
    pub fn tenant_rate(mut self, default: Rate) -> Budgets {
        self.tenant_rate = Some(default);
        self
    }

    /// A tenant's own rate (its plan), replacing the default for that
    /// tenant. A later plan for the same tenant replaces an earlier one.
    #[must_use]
    pub fn tenant_plan(mut self, tenant: TenantKey, rate: Rate) -> Budgets {
        self.tenant_plans.retain(|(t, _)| *t != tenant);
        self.tenant_plans.push((tenant, rate));
        self
    }

    /// Requests in flight per tenant, taken at `bind_tenant` and returned
    /// when the ticket is released.
    #[must_use]
    pub fn tenant_in_flight(mut self, default: u32) -> Budgets {
        self.tenant_in_flight = Some(default);
        self
    }

    /// Keys the budget tables hold at most (default 65,536).
    #[must_use]
    pub fn capacity(mut self, keys: u32) -> Budgets {
        self.capacity = keys;
        self
    }

    pub(crate) fn capacity_keys(&self) -> u32 {
        self.capacity.max(1024)
    }

    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        if self.capacity == 0 || self.capacity > 1 << 24 {
            return Err(ConfigError::new(
                "budgets",
                ConfigProblem::TooSmall { min: 1 },
            ));
        }
        if let Some((a, p)) = self.door_rate {
            a.quota("budgets")?;
            p.quota("budgets")?;
        }
        if let Some((a, p)) = self.door_concurrency {
            if a == 0 || p == 0 {
                return Err(ConfigError::new(
                    "budgets",
                    ConfigProblem::TooSmall { min: 1 },
                ));
            }
        }
        for lane in self.lanes.iter().flatten() {
            lane.quota("budgets")?;
        }
        if let Some(r) = &self.tenant_rate {
            r.bucket("budgets")?;
        }
        if self.tenant_plans.len() > MAX_PLANS {
            return Err(ConfigError::new(
                "budgets",
                ConfigProblem::TooLarge {
                    max: MAX_PLANS as u64,
                },
            ));
        }
        for (_, r) in &self.tenant_plans {
            r.bucket("budgets")?;
        }
        if self.tenant_in_flight == Some(0) {
            return Err(ConfigError::new(
                "budgets",
                ConfigProblem::TooSmall { min: 1 },
            ));
        }
        Ok(())
    }
}

/// GCRA parameters shared by every key of a rate tier; a key's state is
/// one word, its theoretical arrival time in emission intervals, kept in its
/// claim slot. The integer math is rate-net's `Gcra` (exact intervals, a
/// late reading only ever stricter, a fresh word full), split so that a key
/// costs 8 bytes beside its key word instead of a whole limiter.
struct Pace {
    limit: u64,
    period_ns: u64,
    /// `limit * 2^64 / period_ns`.
    per_ns: u128,
    /// `burst - 1`, in intervals.
    tolerance: u64,
    deny_all: bool,
}

impl Pace {
    fn new(q: Quota) -> Pace {
        let period_ns = u64::try_from(q.period().as_nanos()).unwrap_or(u64::MAX);
        let limit = u64::from(q.limit()).min(period_ns);
        let deny_all = limit == 0 || q.burst() == 0;
        let per_ns = if deny_all {
            0
        } else {
            (u128::from(limit) << 64) / u128::from(period_ns)
        };
        Pace {
            limit,
            period_ns,
            per_ns,
            tolerance: u64::from(q.burst().saturating_sub(1)),
            deny_all,
        }
    }

    /// Whole intervals begun by `now_ns`: `floor(now_ns * limit / period)`.
    #[inline]
    fn intervals_at(&self, now_ns: u64) -> u64 {
        let wide = u128::from(now_ns);
        let estimate = ((wide * self.per_ns) >> 64) as u64;
        let next = u128::from(estimate) + 1;
        if next * u128::from(self.period_ns) <= wide * u128::from(self.limit) {
            estimate + 1
        } else {
            estimate
        }
    }

    /// The first nanosecond of interval `interval`.
    fn nanos_at(&self, interval: u64) -> u64 {
        let scaled = u128::from(interval) * u128::from(self.period_ns);
        u64::try_from(scaled.div_ceil(u128::from(self.limit))).unwrap_or(u64::MAX)
    }

    /// Takes `n` units from the key whose arrival time is `tat`; on refusal,
    /// how long until they conform.
    #[inline]
    fn check_n_at(&self, tat: &AtomicU64, n: u32, now: Duration) -> Result<(), Duration> {
        if n == 0 {
            return Ok(());
        }
        let span = u64::from(n - 1);
        if self.deny_all || span > self.tolerance {
            return Err(Duration::MAX);
        }
        let now_ns = u64::try_from(now.as_nanos()).unwrap_or(u64::MAX);
        let now_iv = self.intervals_at(now_ns);
        let ceiling = now_iv.saturating_add(self.tolerance);
        let mut cur = tat.load(Ordering::Acquire);
        loop {
            let effective = cur.max(now_iv);
            if effective.saturating_add(span) > ceiling {
                let ready = self.nanos_at(effective.saturating_add(span) - self.tolerance);
                return Err(Duration::from_nanos(ready.saturating_sub(now_ns).max(1)));
            }
            match tat.compare_exchange_weak(
                cur,
                effective.saturating_add(u64::from(n)),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(()),
                Err(actual) => cur = actual,
            }
        }
    }

    /// Units that would conform now, and the wait until the key is full.
    fn peek(&self, tat: &AtomicU64, now: Duration) -> (u32, Duration) {
        if self.deny_all {
            return (0, Duration::MAX);
        }
        let now_ns = u64::try_from(now.as_nanos()).unwrap_or(u64::MAX);
        let now_iv = self.intervals_at(now_ns);
        let t = tat.load(Ordering::Acquire).max(now_iv);
        let remaining = now_iv.saturating_add(self.tolerance + 1).saturating_sub(t);
        let full_after = if t == now_iv {
            Duration::ZERO
        } else {
            Duration::from_nanos(self.nanos_at(t).saturating_sub(now_ns))
        };
        (u32::try_from(remaining).unwrap_or(u32::MAX), full_after)
    }
}

/// One tier of rate cells (address or prefix): each slot holds its key's
/// arrival time.
struct RateTier {
    claims: Claims<AtomicU64>,
    pace: Pace,
    burst: u32,
}

/// One tier of concurrency counters: each slot holds its key's count.
struct ConcurrencyTier {
    claims: Claims<AtomicU32>,
    limit: u32,
}

/// Throttles: a factor and an end, per key.
struct Throttles {
    claims: Claims,
    /// factor (8) | until secs (32)
    cells: Box<[AtomicU64]>,
    /// The latest end of any throttle ever set: past it, nothing is
    /// throttled and lookups skip the table (one load instead of a probe).
    until_max: AtomicU64,
}

impl Throttles {
    fn new(capacity: u32) -> Throttles {
        let claims = Claims::new(capacity);
        let cells = (0..claims.len()).map(|_| AtomicU64::new(0)).collect();
        Throttles {
            claims,
            cells,
            until_max: AtomicU64::new(0),
        }
    }

    fn bytes(&self) -> u64 {
        self.claims.bytes() + (self.cells.len() * 8) as u64
    }

    /// The factor in force for a key now (1 when none).
    #[inline]
    fn factor(&self, key: u64, now_secs: u64) -> u32 {
        if self.until_max.load(Ordering::Relaxed) <= now_secs {
            return 1;
        }
        match self.claims.find(key) {
            Some(slot) => {
                let v = self.cells[slot].load(Ordering::Acquire);
                if (v & 0xffff_ffff) > now_secs {
                    (v >> 32) as u32 & 0xff
                } else {
                    1
                }
            }
            None => 1,
        }
        .max(1)
    }

    /// Sets a factor until `until_secs`. `false` when the table is full of
    /// throttles still in force.
    fn set(&self, key: u64, factor: u8, until_secs: u64, now_secs: u64) -> bool {
        let cells = &self.cells;
        let now_idle = |slot: usize| cells[slot].load(Ordering::Acquire) & 0xffff_ffff <= now_secs;
        let Some((slot, _)) = self
            .claims
            .find_or_claim(key, now_idle, |s| cells[s].store(0, Ordering::Release))
        else {
            return false;
        };
        let until = until_secs.min(u64::from(u32::MAX));
        // Raised before the cell is written: a reader that sees the cell's
        // end also sees a bound at least as late.
        self.until_max.fetch_max(until, Ordering::Release);
        cells[slot].store((u64::from(factor.max(1)) << 32) | until, Ordering::Release);
        true
    }
}

/// The door budgets of one bouncer.
pub(crate) struct DoorBudgets {
    key: HashKey,
    rate: Option<[RateTier; 2]>,
    /// The global cell, at the prefix rate: charged for every admission
    /// whose prefix found no slot in a full table (PLAN 7.9), so newcomers
    /// past a full table are limited together instead of not at all.
    overflow: Option<(Pace, AtomicU64)>,
    concurrency: Option<[ConcurrencyTier; 2]>,
    throttles: Throttles,
}

/// A budget refusal: how long until it recovers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OverBudget(pub(crate) Duration);

impl DoorBudgets {
    /// Allocates the tables. The configuration was validated by
    /// [`Budgets::validate`]; an invalid tier is left out. The concurrency
    /// tables hold at least twice `tickets` keys, so the keys of every live
    /// connection always fit (a held key is never reclaimed).
    pub(crate) fn new(cfg: &Budgets, key: HashKey, tickets: u32) -> DoorBudgets {
        let cap = cfg.capacity.clamp(1, 1 << 24);
        let conc_cap = cap.max(tickets.saturating_mul(2)).min(1 << 24);
        let rate = cfg.door_rate.and_then(|(addr, prefix)| {
            let tier = |r: Rate| -> Option<RateTier> {
                let q = r.quota("budgets").ok()?;
                Some(RateTier {
                    claims: Claims::new(cap),
                    pace: Pace::new(q),
                    burst: r.burst,
                })
            };
            Some([tier(addr)?, tier(prefix)?])
        });
        let overflow = rate.as_ref().and_then(|_| {
            let (_, prefix) = cfg.door_rate?;
            Some((Pace::new(prefix.quota("budgets").ok()?), AtomicU64::new(0)))
        });
        let concurrency = cfg
            .door_concurrency
            .filter(|&(a, p)| a > 0 && p > 0)
            .map(|(a, p)| {
                let tier = |limit: u32| ConcurrencyTier {
                    claims: Claims::new(conc_cap),
                    limit,
                };
                [tier(a), tier(p)]
            });
        DoorBudgets {
            key,
            rate,
            overflow,
            concurrency,
            throttles: Throttles::new(cap.min(16_384)),
        }
    }

    pub(crate) fn bytes(&self) -> u64 {
        let rate = self
            .rate
            .as_ref()
            .map_or(0, |t| t.iter().map(|r| r.claims.bytes()).sum());
        let conc = self
            .concurrency
            .as_ref()
            .map_or(0, |t| t.iter().map(|c| c.claims.bytes()).sum());
        rate + conc + self.throttles.bytes()
    }

    pub(crate) fn capacity(&self) -> u32 {
        self.rate
            .as_ref()
            .map(|t| t[0].claims.len() as u32)
            .or_else(|| self.concurrency.as_ref().map(|t| t[0].claims.len() as u32))
            .unwrap_or(0)
    }

    /// The two keys of an address: the client (IPv4 /32, IPv6 /64) and its
    /// prefix (IPv4 /24, IPv6 /48).
    fn keys(&self, addr: IpAddr) -> [u64; 2] {
        self.keys_hashed(&mut crate::bans::AddrHashes::new(addr))
    }

    /// The two keys of the door's address, under the budgets' own hash key
    /// (never the ban table's, which a reseed replaces: budgets must not
    /// reset with it).
    #[inline]
    fn keys_hashed(&self, hashes: &mut crate::bans::AddrHashes) -> [u64; 2] {
        let host = *hashes.host();
        let (client, prefix) = match host.family() {
            Family::V4 => (32, 24),
            Family::V6 => (64, 48),
        };
        let hash = |len: u8| {
            Claims::key(crate::bans::table::hash_key(
                &self.key,
                &crate::bans::BanMemory::key_at(&host, len),
            ))
        };
        [hash(client), hash(prefix)]
    }

    /// Whether admissions hold concurrency slots (returned on release).
    pub(crate) fn has_concurrency(&self) -> bool {
        self.concurrency.is_some()
    }

    /// The throttle factor in force for a key now (1 when none).
    fn factor(&self, key: u64, now_secs: u64) -> u32 {
        self.throttles.factor(key, now_secs)
    }

    /// The throttle factor in force on an address: the larger of its client
    /// and prefix throttles.
    pub(crate) fn source_factor(&self, addr: IpAddr, now_secs: u64) -> u32 {
        let [client, prefix] = self.keys(addr);
        self.factor(client, now_secs)
            .max(self.factor(prefix, now_secs))
    }

    /// Sets a throttle on the client or prefix key of `cidr`.
    pub(crate) fn throttle(&self, cidr: &Cidr, factor: u8, until_secs: u64, now_secs: u64) -> bool {
        let key = Claims::key(crate::bans::table::hash_key(
            &self.key,
            &crate::bans::BanMemory::prefix_key(cidr),
        ));
        self.throttles.set(key, factor, until_secs, now_secs)
    }

    /// The door's budget step for an admitted address: rate, then
    /// concurrency. On success the connection holds one concurrency slot per
    /// tier until [`release_connection`](Self::release_connection).
    /// `divisor` is 1, or the strict posture's divisor: each admission costs
    /// that many tokens and the concurrency limits shrink by it.
    #[inline]
    pub(crate) fn admit(&self, addr: IpAddr, now: Now, divisor: u32) -> Result<(), OverBudget> {
        self.admit_hashed(&mut crate::bans::AddrHashes::new(addr), now, divisor)
    }

    /// As [`admit`](Self::admit), through the door's hash cache. Nothing is
    /// hashed when no door budget is configured.
    #[inline]
    pub(crate) fn admit_hashed(
        &self,
        hashes: &mut crate::bans::AddrHashes,
        now: Now,
        divisor: u32,
    ) -> Result<(), OverBudget> {
        if self.rate.is_none() && self.concurrency.is_none() {
            return Ok(());
        }
        let keys = self.keys_hashed(hashes);
        let now_d = Duration::from_nanos(now.as_nanos());
        let now_secs = now.secs();
        if let Some(tiers) = &self.rate {
            for (i, (tier, &key)) in tiers.iter().zip(keys.iter()).enumerate() {
                let n = self.factor(key, now_secs).saturating_mul(divisor);
                // A full table charges the next tier instead (hierarchical
                // fallback), and past the prefix tier the global cell: a
                // flood of new keys cannot reset anyone's limit, and is
                // never unlimited.
                self.charge(tier, i + 1 == tiers.len(), key, n, now_d)?;
            }
        }
        if let Some(tiers) = &self.concurrency {
            let mut taken: [Option<usize>; 2] = [None, None];
            for (i, (tier, &key)) in tiers.iter().zip(keys.iter()).enumerate() {
                let claims = &tier.claims;
                let idle = |slot: usize| claims.val(slot).load(Ordering::Acquire) == 0;
                if let Some((slot, _)) = claims.find_or_claim(key, idle, |_| {}) {
                    let count = claims.val(slot);
                    let before = count.fetch_add(1, Ordering::AcqRel);
                    if before >= (tier.limit / divisor.max(1)).max(1) {
                        count.fetch_sub(1, Ordering::AcqRel);
                        for (j, s) in taken.iter().enumerate().take(i) {
                            if let Some(s) = s {
                                tiers[j].claims.val(*s).fetch_sub(1, Ordering::AcqRel);
                            }
                        }
                        return Err(OverBudget(Duration::ZERO));
                    }
                    taken[i] = Some(slot);
                }
            }
        }
        Ok(())
    }

    /// The datagram budget step: the rate tiers only (no concurrency). An
    /// unverified source is charged at its prefix only, and under a key of
    /// its own there, so forged datagrams cannot spend the budget of a real
    /// client or of its prefix (which would refuse that prefix's
    /// connections and verified datagrams).
    pub(crate) fn datagram(
        &self,
        addr: IpAddr,
        verified: bool,
        now: Now,
        divisor: u32,
    ) -> Result<(), OverBudget> {
        let Some(tiers) = &self.rate else {
            return Ok(());
        };
        let keys = self.keys(addr);
        let now_d = Duration::from_nanos(now.as_nanos());
        let now_secs = now.secs();
        let first = usize::from(!verified);
        for (i, (tier, &key)) in tiers.iter().zip(keys.iter()).enumerate().skip(first) {
            let n = self.factor(key, now_secs).saturating_mul(divisor);
            let key = if verified { key } else { unverified(key) };
            self.charge(tier, i + 1 == tiers.len(), key, n, now_d)?;
        }
        Ok(())
    }

    /// Charges `n` to `key`'s cell in `tier`; when the table has no slot for
    /// it and the tier is the last, to the global cell.
    #[inline]
    fn charge(
        &self,
        tier: &RateTier,
        last: bool,
        key: u64,
        n: u32,
        now: Duration,
    ) -> Result<(), OverBudget> {
        let claims = &tier.claims;
        let (pace, tat) = match claims.find_or_claim(
            key,
            |slot| tier.pace.peek(claims.val(slot), now).0 >= tier.burst,
            |slot| claims.val(slot).store(0, Ordering::Release),
        ) {
            Some((slot, _)) => (&tier.pace, claims.val(slot)),
            None => match (&self.overflow, last) {
                (Some((pace, tat)), true) => (pace, tat),
                _ => return Ok(()),
            },
        };
        pace.check_n_at(tat, n, now).map_err(OverBudget)
    }

    /// Returns a connection's concurrency slots.
    pub(crate) fn release_connection(&self, addr: Option<IpAddr>, _now: Now) {
        let (Some(addr), Some(tiers)) = (addr, &self.concurrency) else {
            return;
        };
        for (tier, key) in tiers.iter().zip(self.keys(addr)) {
            if let Some(slot) = tier.claims.find(key) {
                let count = tier.claims.val(slot);
                let mut c = count.load(Ordering::Acquire);
                while c > 0 {
                    match count.compare_exchange_weak(c, c - 1, Ordering::AcqRel, Ordering::Acquire)
                    {
                        Ok(_) => break,
                        Err(actual) => c = actual,
                    }
                }
            }
        }
    }

    /// The fullest table's load, 0 to 1: slots holding a key that has not
    /// recovered (recovered keys are reclaimed on demand). A full scan.
    pub(crate) fn load(&self, now: Now) -> f32 {
        let now_d = Duration::from_nanos(now.as_nanos());
        let rate = self.rate.iter().flatten().map(|t| {
            t.claims
                .active_load(|i| t.pace.peek(t.claims.val(i), now_d).0 < t.burst)
        });
        let conc = self.concurrency.iter().flatten().map(|t| {
            t.claims
                .active_load(|i| t.claims.val(i).load(Ordering::Relaxed) > 0)
        });
        rate.chain(conc).fold(0.0, f32::max)
    }

    /// The door budget states of an address, for `explain`.
    pub(crate) fn state(&self, addr: IpAddr, now: Now) -> Vec<crate::admin::BudgetState> {
        use crate::{admin::BudgetState, keys::BanKey};
        let host = Cidr::host(addr);
        let (client, prefix) = match host.family() {
            Family::V4 => (32, 24),
            Family::V6 => (64, 48),
        };
        let as_key = |len: u8| {
            let c = host.parent(len).unwrap_or(host);
            if c.len() == c.family().max_len() {
                BanKey::Address(c.network())
            } else {
                BanKey::Prefix(c)
            }
        };
        let names = [
            (
                "door.rate.client",
                "door.concurrency.client",
                as_key(client),
            ),
            (
                "door.rate.prefix",
                "door.concurrency.prefix",
                as_key(prefix),
            ),
        ];
        let keys = self.keys(addr);
        let now_d = Duration::from_nanos(now.as_nanos());
        let mut out = Vec::new();
        if let Some(tiers) = &self.rate {
            for ((tier, key), (rate, _, bk)) in tiers.iter().zip(keys).zip(names) {
                let (remaining, retry) = match tier.claims.find(key) {
                    Some(slot) => {
                        let (r, full_after) = tier.pace.peek(tier.claims.val(slot), now_d);
                        (r, (r == 0).then_some(full_after))
                    }
                    None => (tier.burst, None),
                };
                out.push(BudgetState {
                    class: rate,
                    key: bk,
                    remaining,
                    retry_after: retry,
                });
            }
        }
        if let Some(tiers) = &self.concurrency {
            for ((tier, key), (_, conc, bk)) in tiers.iter().zip(keys).zip(names) {
                let used = tier
                    .claims
                    .find(key)
                    .map_or(0, |s| tier.claims.val(s).load(Ordering::Acquire));
                out.push(BudgetState {
                    class: conc,
                    key: bk,
                    remaining: tier.limit.saturating_sub(used),
                    retry_after: None,
                });
            }
        }
        out
    }

    /// Live connections counted for an address (tests and `explain`).
    #[cfg(all(test, not(bouncer_loom)))]
    pub(crate) fn concurrent(&self, addr: IpAddr) -> u32 {
        let Some(tiers) = &self.concurrency else {
            return 0;
        };
        let key = self.keys(addr)[0];
        tiers[0]
            .claims
            .find(key)
            .map_or(0, |s| tiers[0].claims.val(s).load(Ordering::Acquire))
    }
}

/// Who a lane or throttle key belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IdentityKind {
    Session = 1,
    Account = 2,
    Tenant = 3,
    Fingerprint = 4,
    /// A client address: IPv4 /32 or IPv6 /64.
    Client = 5,
}

/// One identity key: its kind and two words.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct IdentityKey {
    pub(crate) kind: IdentityKind,
    pub(crate) k0: u64,
    pub(crate) k1: u64,
}

impl IdentityKey {
    /// The client key of an address (IPv4 /32, IPv6 /64).
    pub(crate) fn client(addr: IpAddr) -> IdentityKey {
        let host = Cidr::host(addr);
        let c = match host.family() {
            Family::V4 => host,
            Family::V6 => host.parent(64).unwrap_or(host),
        };
        IdentityKey {
            kind: IdentityKind::Client,
            k0: (c.bits() >> 64) as u64 | (u64::from(c.family() == Family::V6) << 63),
            k1: c.bits() as u64,
        }
    }
}

/// The tenant token buckets: planned tenants in their own sorted table,
/// every other tenant in the keyed table under the default rate.
struct TenantTier {
    claims: Claims,
    cells: Box<[BucketCore]>,
    capacity: u32,
    /// (tenant, bucket), sorted by tenant.
    plans: Box<[(u64, BucketCore)]>,
}

/// Lane, tenant, and identity-throttle budgets, checked at `bind_lane` and
/// `bind_tenant`. Charged once per call; a refusal is a `TooManyRequests`
/// denial of that ticket.
pub(crate) struct IdentityBudgets {
    key: HashKey,
    lanes: [Option<RateTier>; LaneClass::COUNT],
    tenant: Option<TenantTier>,
    in_flight: Option<ConcurrencyTier>,
    throttles: Throttles,
}

impl IdentityBudgets {
    /// Allocates the configured tables. `cfg` was validated.
    pub(crate) fn new(cfg: &Budgets, key: HashKey, now: Now) -> IdentityBudgets {
        let cap = cfg.capacity.clamp(1, 1 << 24);
        let now_d = Duration::from_nanos(now.as_nanos());
        let lanes = core::array::from_fn(|i| {
            let r = cfg.lanes[i]?;
            let q = r.quota("budgets").ok()?;
            Some(RateTier {
                claims: Claims::new(cap),
                pace: Pace::new(q),
                burst: r.burst,
            })
        });
        let plans = || -> Box<[(u64, BucketCore)]> {
            let mut v: Vec<(u64, BucketCore)> = cfg
                .tenant_plans
                .iter()
                .filter_map(|(t, r)| Some((t.0, BucketCore::new(r.bucket("budgets").ok()?, now_d))))
                .collect();
            v.sort_unstable_by_key(|(t, _)| *t);
            v.into_boxed_slice()
        };
        let tenant = match cfg.tenant_rate.and_then(|r| r.bucket("budgets").ok()) {
            Some(b) => {
                let claims = Claims::new(cap);
                let cells = (0..claims.len())
                    .map(|_| BucketCore::new(b, now_d))
                    .collect();
                Some(TenantTier {
                    claims,
                    cells,
                    capacity: b.capacity(),
                    plans: plans(),
                })
            }
            None if !cfg.tenant_plans.is_empty() => Some(TenantTier {
                claims: Claims::new(1),
                cells: Box::new([]),
                capacity: 0,
                plans: plans(),
            }),
            None => None,
        };
        let in_flight = cfg
            .tenant_in_flight
            .filter(|&n| n > 0)
            .map(|limit| ConcurrencyTier {
                claims: Claims::new(cap),
                limit,
            });
        IdentityBudgets {
            key,
            lanes,
            tenant,
            in_flight,
            throttles: Throttles::new(cap.min(16_384)),
        }
    }

    pub(crate) fn bytes(&self) -> u64 {
        let lanes: u64 = self.lanes.iter().flatten().map(|r| r.claims.bytes()).sum();
        let tenant = self.tenant.as_ref().map_or(0, |t| {
            t.claims.bytes()
                + ((t.cells.len() + t.plans.len()) * core::mem::size_of::<BucketCore>()) as u64
        });
        let flight = self.in_flight.as_ref().map_or(0, |c| c.claims.bytes());
        lanes + tenant + flight + self.throttles.bytes()
    }

    /// Whether any lane budget is configured.
    pub(crate) fn has_lanes(&self) -> bool {
        self.lanes.iter().any(Option::is_some)
    }

    /// Whether `bind_tenant` charges anything.
    pub(crate) fn has_tenant(&self) -> bool {
        self.tenant.is_some() || self.in_flight.is_some()
    }

    fn hashed(&self, tag: u64, id: IdentityKey) -> u64 {
        Claims::key(self.key.hash3((tag << 8) | id.kind as u64, id.k0, id.k1))
    }

    /// The identity throttle factor in force on a key now (1 when none).
    pub(crate) fn factor(&self, id: IdentityKey, now_secs: u64) -> u32 {
        self.throttles.factor(self.hashed(0, id), now_secs)
    }

    /// Throttles an identity key. `false` when the table is full of
    /// throttles still in force.
    pub(crate) fn throttle(
        &self,
        id: IdentityKey,
        factor: u8,
        until_secs: u64,
        now_secs: u64,
    ) -> bool {
        self.throttles
            .set(self.hashed(0, id), factor, until_secs, now_secs)
    }

    /// Charges one request to a lane under `who`, `factor` tokens at once.
    pub(crate) fn lane(
        &self,
        lane: LaneClass,
        who: IdentityKey,
        factor: u32,
        now: Now,
    ) -> Result<(), OverBudget> {
        let Some(tier) = &self.lanes[lane.index()] else {
            return Ok(());
        };
        let key = self.hashed(1 + lane.index() as u64, who);
        let now_d = Duration::from_nanos(now.as_nanos());
        let claims = &tier.claims;
        // A full table leaves the request unmetered by its lane; the door
        // budgets still hold. Nothing that has not recovered is ever reset.
        if let Some((slot, _)) = claims.find_or_claim(
            key,
            |slot| tier.pace.peek(claims.val(slot), now_d).0 >= tier.burst,
            |slot| claims.val(slot).store(0, Ordering::Release),
        ) {
            tier.pace
                .check_n_at(claims.val(slot), factor.max(1), now_d)
                .map_err(OverBudget)?;
        }
        Ok(())
    }

    /// Charges one request to a tenant: rate, then in flight. Returns
    /// whether an in-flight slot was taken (to return with
    /// [`release_tenant`](Self::release_tenant)).
    pub(crate) fn tenant(&self, tenant: u64, factor: u32, now: Now) -> Result<bool, OverBudget> {
        let now_d = Duration::from_nanos(now.as_nanos());
        let n = factor.max(1);
        if let Some(t) = &self.tenant {
            let bucket = match t.plans.binary_search_by_key(&tenant, |(k, _)| *k) {
                Ok(i) => Some(&t.plans[i].1),
                Err(_) if t.cells.is_empty() => None,
                Err(_) => {
                    let key = self.hashed(
                        0x40,
                        IdentityKey {
                            kind: IdentityKind::Tenant,
                            k0: 0,
                            k1: tenant,
                        },
                    );
                    let cells = &t.cells;
                    let full = t.capacity;
                    let idle = |slot: usize| cells[slot].available_at(now_d) >= full;
                    t.claims
                        .find_or_claim(key, idle, |s| cells[s].reset_at(now_d))
                        .map(|(slot, _)| &cells[slot])
                }
            };
            if let Some(b) = bucket {
                if let better_bucket::Decision::Denied { retry_after } = b.acquire_at(n, now_d) {
                    return Err(OverBudget(retry_after));
                }
            }
        }
        let Some(c) = &self.in_flight else {
            return Ok(false);
        };
        let key = self.flight_key(tenant);
        let claims = &c.claims;
        let idle = |slot: usize| claims.val(slot).load(Ordering::Acquire) == 0;
        let Some((slot, _)) = claims.find_or_claim(key, idle, |_| {}) else {
            return Ok(false);
        };
        let count = claims.val(slot);
        let before = count.fetch_add(1, Ordering::AcqRel);
        if before >= c.limit {
            count.fetch_sub(1, Ordering::AcqRel);
            return Err(OverBudget(Duration::ZERO));
        }
        Ok(true)
    }

    fn flight_key(&self, tenant: u64) -> u64 {
        self.hashed(
            0x41,
            IdentityKey {
                kind: IdentityKind::Tenant,
                k0: 0,
                k1: tenant,
            },
        )
    }

    /// Returns a tenant's in-flight slot.
    pub(crate) fn release_tenant(&self, tenant: u64) {
        let Some(c) = &self.in_flight else {
            return;
        };
        if let Some(slot) = c.claims.find(self.flight_key(tenant)) {
            let count = c.claims.val(slot);
            let mut v = count.load(Ordering::Acquire);
            while v > 0 {
                match count.compare_exchange_weak(v, v - 1, Ordering::AcqRel, Ordering::Acquire) {
                    Ok(_) => break,
                    Err(actual) => v = actual,
                }
            }
        }
    }

    /// The fullest table's load, 0 to 1: slots holding a key that has not
    /// recovered (recovered keys are reclaimed on demand). A full scan.
    pub(crate) fn load(&self, now: Now) -> f32 {
        let now_d = Duration::from_nanos(now.as_nanos());
        let lanes = self.lanes.iter().flatten().map(|t| {
            t.claims
                .active_load(|i| t.pace.peek(t.claims.val(i), now_d).0 < t.burst)
        });
        let tenant = self.tenant.iter().map(|t| {
            t.claims
                .active_load(|i| t.cells[i].available_at(now_d) < t.capacity)
        });
        let flight = self.in_flight.iter().map(|c| {
            c.claims
                .active_load(|i| c.claims.val(i).load(Ordering::Relaxed) > 0)
        });
        lanes.chain(tenant).chain(flight).fold(0.0, f32::max)
    }

    /// The tenant in-flight limit, when configured.
    pub(crate) fn tenant_limit(&self) -> Option<u32> {
        self.in_flight.as_ref().map(|c| c.limit)
    }

    /// Requests in flight counted for a tenant (`explain`, tests).
    pub(crate) fn tenant_in_flight(&self, tenant: u64) -> u32 {
        let Some(c) = &self.in_flight else {
            return 0;
        };
        c.claims
            .find(self.flight_key(tenant))
            .map_or(0, |s| c.claims.val(s).load(Ordering::Acquire))
    }
}

#[cfg(all(test, not(bouncer_loom)))]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn budgets(cfg: Budgets) -> DoorBudgets {
        cfg.validate().unwrap();
        DoorBudgets::new(&cfg, HashKey::new(1, 2), 1024)
    }

    #[test]
    fn test_pace_decides_as_rate_net_gcra() {
        use rate_net::{Decision, Gcra};
        let quotas = [
            Quota::per_second(10).with_burst(3),
            Quota::per_second(1000),
            Quota::rate(7, Duration::from_millis(1300))
                .unwrap()
                .with_burst(5),
            Quota::rate(1, Duration::from_secs(3600)).unwrap(),
            Quota::per_second(0),
            Quota::per_second(1).with_burst(0),
        ];
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        let mut rnd = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for q in quotas {
            let gcra = Gcra::new(q);
            let pace = Pace::new(q);
            let tat = AtomicU64::new(0);
            let mut now = Duration::from_millis(rnd() % 10_000);
            for _ in 0..20_000 {
                // Steps forward and, now and then, a late reading behind.
                now = match rnd() % 8 {
                    0 => now.saturating_sub(Duration::from_nanos(rnd() % 50_000_000)),
                    _ => now + Duration::from_nanos(rnd() % 400_000_000),
                };
                let n = (rnd() % 7) as u32;
                let want = match gcra.check_n_at(n, now) {
                    Decision::Deny { retry_after } => Err(retry_after),
                    _ => Ok(()),
                };
                assert_eq!(
                    pace.check_n_at(&tat, n, now),
                    want,
                    "{q:?} n {n} at {now:?}"
                );
                let snap = gcra.peek_at(now);
                let (remaining, full_after) = pace.peek(&tat, now);
                assert_eq!(remaining, snap.remaining(), "{q:?} at {now:?}");
                if q.burst() > 0 && q.limit() > 0 {
                    assert_eq!(full_after, snap.reset_after(), "{q:?} at {now:?}");
                }
            }
        }
    }

    #[test]
    fn test_rate_burst_then_refused_then_recovers() {
        let b = budgets(
            Budgets::off().door_rate(Rate::per_second(10).burst(3), Rate::per_second(1000)),
        );
        let t0 = Now::from_nanos(1_000_000_000);
        for _ in 0..3 {
            assert!(b.admit(ip("192.0.2.1"), t0, 1).is_ok());
        }
        assert!(
            matches!(b.admit(ip("192.0.2.1"), t0, 1), Err(OverBudget(d)) if d > Duration::ZERO)
        );
        assert!(
            b.admit(ip("192.0.2.2"), t0, 1).is_ok(),
            "another address has its own budget"
        );
        assert!(
            b.admit(ip("192.0.2.1"), Now::from_nanos(2_000_000_000), 1)
                .is_ok()
        );
    }

    #[test]
    fn test_prefix_rate_limits_rotation() {
        let b =
            budgets(Budgets::off().door_rate(Rate::per_second(100), Rate::per_second(5).burst(5)));
        let now = Now::from_nanos(1_000_000_000);
        let ok = (0..20u8)
            .filter(|i| b.admit(IpAddr::from([198, 51, 100, *i]), now, 1).is_ok())
            .count();
        assert_eq!(ok, 5, "rotating inside one /24 shares the prefix budget");
        let ok6 = (0..20u16)
            .filter(|i| {
                b.admit(IpAddr::from([0x2001, 0xdb8, 1, *i, 0, 0, 0, 1]), now, 1)
                    .is_ok()
            })
            .count();
        assert_eq!(
            ok6, 5,
            "rotating /64s inside one /48 shares the prefix budget"
        );
    }

    #[test]
    fn test_ipv6_client_is_its_64() {
        let b =
            budgets(Budgets::off().door_rate(Rate::per_second(2).burst(2), Rate::per_second(1000)));
        let now = Now::from_nanos(1_000_000_000);
        assert!(b.admit(ip("2001:db8::1"), now, 1).is_ok());
        assert!(b.admit(ip("2001:db8::ffff"), now, 1).is_ok());
        assert!(b.admit(ip("2001:db8::abcd"), now, 1).is_err(), "same /64");
    }

    #[test]
    fn test_concurrency_limit_and_release() {
        let b = budgets(Budgets::off().door_concurrency(2, 100));
        let now = Now::default();
        assert!(b.admit(ip("192.0.2.1"), now, 1).is_ok());
        assert!(b.admit(ip("192.0.2.1"), now, 1).is_ok());
        assert!(b.admit(ip("192.0.2.1"), now, 1).is_err());
        assert_eq!(b.concurrent(ip("192.0.2.1")), 2);
        b.release_connection(Some(ip("192.0.2.1")), now);
        assert!(b.admit(ip("192.0.2.1"), now, 1).is_ok());
        // Releases never go below zero.
        for _ in 0..5 {
            b.release_connection(Some(ip("192.0.2.1")), now);
        }
        assert_eq!(b.concurrent(ip("192.0.2.1")), 0);
    }

    #[test]
    fn test_prefix_concurrency_refusal_returns_address_slot() {
        let b = budgets(Budgets::off().door_concurrency(10, 1));
        let now = Now::default();
        assert!(b.admit(ip("192.0.2.1"), now, 1).is_ok());
        assert!(b.admit(ip("192.0.2.2"), now, 1).is_err());
        assert_eq!(
            b.concurrent(ip("192.0.2.2")),
            0,
            "the address slot was given back"
        );
    }

    #[test]
    fn test_throttle_divides_rate() {
        let b =
            budgets(Budgets::off().door_rate(Rate::per_second(8).burst(8), Rate::per_second(1000)));
        let now = Now::from_nanos(1_000_000_000);
        assert!(b.throttle(&Cidr::host(ip("192.0.2.7")), 4, 100, 1));
        let ok = (0..8)
            .filter(|_| b.admit(ip("192.0.2.7"), now, 1).is_ok())
            .count();
        assert_eq!(ok, 2, "factor 4 leaves a quarter");
    }

    #[test]
    fn test_rate_validation() {
        assert!(Rate::new(1, Duration::ZERO).is_err());
        assert!(Rate::per_second(0).quota("x").is_err());
        assert!(Budgets::off().capacity(0).validate().is_err());
        assert!(Budgets::off().door_concurrency(0, 1).validate().is_err());
        assert!(
            Budgets::off()
                .door_rate(Rate::per_second(0), Rate::per_second(1))
                .validate()
                .is_err()
        );
        assert!(budgets(Budgets::default()).bytes() > 0);
    }
}

/// The budget key of unverified datagrams from a prefix: derived from the
/// prefix's keyed hash, so it is as unpredictable as that hash, and equal to
/// a key a real source is charged under only by a keyed-hash collision.
#[inline]
fn unverified(key: u64) -> u64 {
    Claims::key(key.rotate_left(29) ^ 0x6a09_e667_f3bc_c908)
}
