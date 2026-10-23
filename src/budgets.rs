//! Budgets: "is this source over its allowance", one input to the door. Not
//! the purpose of the crate.
//!
//! The rate math is rate-net's GCRA (without default features, so it brings
//! no third-party crate); the keyed storage is bouncer's own bounded table.
//! Eviction never resets a limit: a cell is taken over only once it has
//! fully recovered and holds no connections.

use core::time::Duration;
use std::net::IpAddr;

use rate_net::{Decision, Gcra, Quota};

use crate::{
    claims::Claims,
    error::{BouncerError, ConfigError, ConfigProblem},
    hash::HashKey,
    keys::{Cidr, Family},
    sync::{AtomicU32, AtomicU64, Ordering},
    time::Now,
};

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
}

/// Budget configuration.
///
/// # Examples
///
/// ```
/// use bouncer_io::{Bouncer, Budgets, Rate};
/// let bouncer = Bouncer::builder()
///     .budgets(Budgets::default().door_rate(Rate::per_second(50).burst(100), Rate::per_second(500)).door_concurrency(32, 256))
///     .try_build()?;
/// # let _ = bouncer;
/// # Ok::<(), bouncer_io::BouncerError>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budgets {
    door_rate: Option<(Rate, Rate)>,
    door_concurrency: Option<(u32, u32)>,
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

    /// Keys the budget tables hold at most (default 65,536).
    #[must_use]
    pub fn capacity(mut self, keys: u32) -> Budgets {
        self.capacity = keys;
        self
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
        Ok(())
    }
}

/// One tier of rate cells (address or prefix).
struct RateTier {
    claims: Claims,
    cells: Box<[Gcra]>,
    burst: u32,
}

/// One tier of concurrency counters.
struct ConcurrencyTier {
    claims: Claims,
    counts: Box<[AtomicU32]>,
    limit: u32,
}

/// Throttles: a factor and an end, per key.
struct Throttles {
    claims: Claims,
    /// factor (8) | until secs (32)
    cells: Box<[AtomicU64]>,
}

/// The door budgets of one bouncer.
pub(crate) struct DoorBudgets {
    key: HashKey,
    rate: Option<[RateTier; 2]>,
    concurrency: Option<[ConcurrencyTier; 2]>,
    throttles: Throttles,
}

/// A budget refusal: how long until it recovers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OverBudget(pub(crate) Duration);

impl DoorBudgets {
    /// Allocates the tables. The configuration was validated by
    /// [`Budgets::validate`]; an invalid tier is left out.
    pub(crate) fn new(cfg: &Budgets, key: HashKey) -> DoorBudgets {
        let cap = cfg.capacity.clamp(1, 1 << 24);
        let rate = cfg.door_rate.and_then(|(addr, prefix)| {
            let tier = |r: Rate| -> Option<RateTier> {
                let q = r.quota("budgets").ok()?;
                let claims = Claims::new(cap);
                let cells = (0..claims.len()).map(|_| Gcra::new(q)).collect();
                Some(RateTier {
                    claims,
                    cells,
                    burst: r.burst,
                })
            };
            Some([tier(addr)?, tier(prefix)?])
        });
        let concurrency = cfg
            .door_concurrency
            .filter(|&(a, p)| a > 0 && p > 0)
            .map(|(a, p)| {
                let tier = |limit: u32| {
                    let claims = Claims::new(cap);
                    let counts = (0..claims.len()).map(|_| AtomicU32::new(0)).collect();
                    ConcurrencyTier {
                        claims,
                        counts,
                        limit,
                    }
                };
                [tier(a), tier(p)]
            });
        let claims = Claims::new(cap.min(16_384));
        let cells = (0..claims.len()).map(|_| AtomicU64::new(0)).collect();
        DoorBudgets {
            key,
            rate,
            concurrency,
            throttles: Throttles { claims, cells },
        }
    }

    pub(crate) fn bytes(&self) -> u64 {
        let rate = self.rate.as_ref().map_or(0, |t| {
            t.iter()
                .map(|r| r.claims.bytes() + (r.cells.len() * core::mem::size_of::<Gcra>()) as u64)
                .sum()
        });
        let conc = self.concurrency.as_ref().map_or(0, |t| {
            t.iter()
                .map(|c| c.claims.bytes() + (c.counts.len() * 4) as u64)
                .sum()
        });
        rate + conc + self.throttles.claims.bytes() + (self.throttles.cells.len() * 8) as u64
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
        let host = Cidr::host(addr);
        let (client, prefix) = match host.family() {
            Family::V4 => (32, 24),
            Family::V6 => (64, 48),
        };
        let k = |len: u8| {
            let p = host.parent(len).unwrap_or(host);
            let meta = u64::from(len) | (u64::from(host.family() == Family::V6) << 8);
            Claims::key(
                self.key
                    .hash3(meta, (p.bits() >> 64) as u64, p.bits() as u64),
            )
        };
        [k(client), k(prefix)]
    }

    /// The throttle factor in force for a key now (1 when none).
    fn factor(&self, key: u64, now_secs: u64) -> u32 {
        match self.throttles.claims.find(key) {
            Some(slot) => {
                let v = self.throttles.cells[slot].load(Ordering::Acquire);
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

    /// Sets a throttle on the client or prefix key of `cidr`.
    pub(crate) fn throttle(&self, cidr: &Cidr, factor: u8, until_secs: u64, now_secs: u64) -> bool {
        let meta = u64::from(cidr.len()) | (u64::from(cidr.family() == Family::V6) << 8);
        let key = Claims::key(
            self.key
                .hash3(meta, (cidr.bits() >> 64) as u64, cidr.bits() as u64),
        );
        let cells = &self.throttles.cells;
        let now_idle = |slot: usize| cells[slot].load(Ordering::Acquire) & 0xffff_ffff <= now_secs;
        let Some((slot, _)) = self
            .throttles
            .claims
            .find_or_claim(key, now_idle, |s| cells[s].store(0, Ordering::Release))
        else {
            return false;
        };
        let until = until_secs.min(u64::from(u32::MAX));
        cells[slot].store((u64::from(factor.max(1)) << 32) | until, Ordering::Release);
        true
    }

    /// The door's budget step for an admitted address: rate, then
    /// concurrency. On success the connection holds one concurrency slot per
    /// tier until [`release_connection`](Self::release_connection).
    #[inline]
    pub(crate) fn admit(&self, addr: IpAddr, now: Now) -> Result<(), OverBudget> {
        let keys = self.keys(addr);
        let now_d = Duration::from_nanos(now.as_nanos());
        let now_secs = now.secs();
        if let Some(tiers) = &self.rate {
            for (tier, &key) in tiers.iter().zip(keys.iter()) {
                let n = self.factor(key, now_secs);
                let cells = &tier.cells;
                let burst = tier.burst;
                let idle = |slot: usize| cells[slot].peek_at(now_d).remaining() >= burst;
                // A full table charges the next tier instead (hierarchical
                // fallback): a flood of new keys cannot reset anyone's limit.
                if let Some((slot, _)) = tier.claims.find_or_claim(key, idle, |s| cells[s].reset())
                {
                    if let Decision::Deny { retry_after } = cells[slot].check_n_at(n, now_d) {
                        return Err(OverBudget(retry_after));
                    }
                }
            }
        }
        if let Some(tiers) = &self.concurrency {
            let mut taken: [Option<usize>; 2] = [None, None];
            for (i, (tier, &key)) in tiers.iter().zip(keys.iter()).enumerate() {
                let counts = &tier.counts;
                let idle = |slot: usize| counts[slot].load(Ordering::Acquire) == 0;
                if let Some((slot, _)) = tier.claims.find_or_claim(key, idle, |_| {}) {
                    let before = counts[slot].fetch_add(1, Ordering::AcqRel);
                    if before >= tier.limit {
                        counts[slot].fetch_sub(1, Ordering::AcqRel);
                        for (j, s) in taken.iter().enumerate().take(i) {
                            if let Some(s) = s {
                                tiers[j].counts[*s].fetch_sub(1, Ordering::AcqRel);
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

    /// Returns a connection's concurrency slots.
    pub(crate) fn release_connection(&self, addr: Option<IpAddr>, _now: Now) {
        let (Some(addr), Some(tiers)) = (addr, &self.concurrency) else {
            return;
        };
        for (tier, key) in tiers.iter().zip(self.keys(addr)) {
            if let Some(slot) = tier.claims.find(key) {
                let count = &tier.counts[slot];
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
            .map_or(0, |s| tiers[0].counts[s].load(Ordering::Acquire))
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
        DoorBudgets::new(&cfg, HashKey::new(1, 2))
    }

    #[test]
    fn test_rate_burst_then_refused_then_recovers() {
        let b = budgets(
            Budgets::off().door_rate(Rate::per_second(10).burst(3), Rate::per_second(1000)),
        );
        let t0 = Now::from_nanos(1_000_000_000);
        for _ in 0..3 {
            assert!(b.admit(ip("192.0.2.1"), t0).is_ok());
        }
        assert!(matches!(b.admit(ip("192.0.2.1"), t0), Err(OverBudget(d)) if d > Duration::ZERO));
        assert!(
            b.admit(ip("192.0.2.2"), t0).is_ok(),
            "another address has its own budget"
        );
        assert!(
            b.admit(ip("192.0.2.1"), Now::from_nanos(2_000_000_000))
                .is_ok()
        );
    }

    #[test]
    fn test_prefix_rate_limits_rotation() {
        let b =
            budgets(Budgets::off().door_rate(Rate::per_second(100), Rate::per_second(5).burst(5)));
        let now = Now::from_nanos(1_000_000_000);
        let ok = (0..20u8)
            .filter(|i| b.admit(IpAddr::from([198, 51, 100, *i]), now).is_ok())
            .count();
        assert_eq!(ok, 5, "rotating inside one /24 shares the prefix budget");
        let ok6 = (0..20u16)
            .filter(|i| {
                b.admit(IpAddr::from([0x2001, 0xdb8, 1, *i, 0, 0, 0, 1]), now)
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
        assert!(b.admit(ip("2001:db8::1"), now).is_ok());
        assert!(b.admit(ip("2001:db8::ffff"), now).is_ok());
        assert!(b.admit(ip("2001:db8::abcd"), now).is_err(), "same /64");
    }

    #[test]
    fn test_concurrency_limit_and_release() {
        let b = budgets(Budgets::off().door_concurrency(2, 100));
        let now = Now::default();
        assert!(b.admit(ip("192.0.2.1"), now).is_ok());
        assert!(b.admit(ip("192.0.2.1"), now).is_ok());
        assert!(b.admit(ip("192.0.2.1"), now).is_err());
        assert_eq!(b.concurrent(ip("192.0.2.1")), 2);
        b.release_connection(Some(ip("192.0.2.1")), now);
        assert!(b.admit(ip("192.0.2.1"), now).is_ok());
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
        assert!(b.admit(ip("192.0.2.1"), now).is_ok());
        assert!(b.admit(ip("192.0.2.2"), now).is_err());
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
            .filter(|_| b.admit(ip("192.0.2.7"), now).is_ok())
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
