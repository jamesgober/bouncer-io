//! Strikes: misbehaviour reported by any layer, counted against the ticket's
//! keys in windowed counters. bouncer's own thresholds observe by default:
//! they report what they would ban and ban nothing until a project switches a
//! category to enforce. Explicit commands always act.

use core::time::Duration;
use std::net::IpAddr;

use crate::{
    bans::DurationPolicy,
    claims::Claims,
    error::{ConfigError, ConfigProblem},
    hash::HashKey,
    keys::{BanKey, Cidr, Family},
    sync::{AtomicU64, Ordering, update},
};

/// What a layer reports.
///
/// `DecoyTouched` (a decoy from sentinel-sec) is definitive: it revokes and
/// bans at once, whatever the enforcement mode.
///
/// # Examples
///
/// ```
/// use bouncer_io::StrikeKind;
/// assert_ne!(StrikeKind::Malformed, StrikeKind::Custom(1001));
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StrikeKind {
    /// A transport or TLS handshake failed.
    HandshakeFailed,
    /// A PROXY header was invalid or came from an untrusted peer.
    ProxyViolation,
    /// A TLS alert.
    TlsAlert,
    /// Malformed protocol traffic.
    Malformed,
    /// A contract violation found by inspection.
    ContractViolation,
    /// A slow peer was killed (slowloris, slow read).
    SlowPeer,
    /// A failed login.
    LoginFailed,
    /// An authorization denial.
    AuthzDenied,
    /// Reuse of a revoked (tombstoned) session token.
    TombstoneReuse,
    /// A decoy was touched: definitive.
    DecoyTouched,
    /// A project's own kind.
    Custom(u16),
}

const KINDS: usize = 11;

impl StrikeKind {
    const fn index(self) -> usize {
        match self {
            StrikeKind::HandshakeFailed => 0,
            StrikeKind::ProxyViolation => 1,
            StrikeKind::TlsAlert => 2,
            StrikeKind::Malformed => 3,
            StrikeKind::ContractViolation => 4,
            StrikeKind::SlowPeer => 5,
            StrikeKind::LoginFailed => 6,
            StrikeKind::AuthzDenied => 7,
            StrikeKind::TombstoneReuse => 8,
            StrikeKind::DecoyTouched => 9,
            StrikeKind::Custom(_) => 10,
        }
    }

    fn code(self) -> u64 {
        match self {
            StrikeKind::Custom(c) => 0x1_0000 | u64::from(c),
            k => k.index() as u64,
        }
    }
}

/// Why a strike was not counted.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IgnoredBecause {
    /// The ticket is a trusted proxy hop: the proxy is never a target.
    TrustedProxy,
    /// The source is allow-listed.
    AllowListed,
    /// The source is not verified (UDP).
    UnverifiedSource,
    /// The request's real client behind a proxy is not bound yet.
    PendingClient,
    /// The ticket was released.
    Released,
    /// The counter table had no room on this key's probe path.
    CounterTableFull,
}

/// What a strike did.
///
/// # Examples
///
/// ```
/// use bouncer_io::{Bouncer, StrikeKind, StrikeOutcome};
/// let bouncer = Bouncer::new();
/// let conn = bouncer.door("198.51.100.66".parse()?)?;
/// for _ in 0..4 {
///     assert_eq!(conn.strike(StrikeKind::Malformed), StrikeOutcome::Counted);
/// }
/// // The fifth reaches the default threshold: observed, not enforced.
/// assert!(matches!(conn.strike(StrikeKind::Malformed), StrikeOutcome::ThresholdObserved { .. }));
/// assert!(bouncer.door("198.51.100.66".parse()?).is_ok());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrikeOutcome {
    /// Counted; no threshold reached.
    Counted,
    /// A threshold was reached in observe mode: this ban would have been set.
    ThresholdObserved {
        /// The key that would have been banned.
        would_ban: BanKey,
    },
    /// A threshold was reached in enforce mode (or a decoy was touched): the
    /// key is banned and the ticket revoked.
    Banned(crate::bans::BanId),
    /// A threshold was reached on a source flagged as shared: throttled
    /// instead of banned (arrives with shared-address detection).
    Throttled,
    /// Not counted.
    Ignored(IgnoredBecause),
}

/// Observe or enforce.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Mode {
    /// Report what would be done; do nothing.
    Observe,
    /// Act.
    Enforce,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Rule {
    weight: u16,
    threshold: u16,
    window: Duration,
    durations: Option<DurationPolicy>,
}

impl Default for Rule {
    fn default() -> Self {
        Rule {
            weight: 1,
            threshold: 5,
            window: Duration::from_secs(600),
            durations: None,
        }
    }
}

/// Strike weights, thresholds, windows, and ban durations per kind.
///
/// # Examples
///
/// ```
/// use bouncer_io::{StrikeKind, StrikeRules};
/// use std::time::Duration;
/// let rules = StrikeRules::default().rule(StrikeKind::LoginFailed, 1, 10, Duration::from_secs(300));
/// # let _ = rules;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrikeRules {
    rules: [Rule; KINDS],
}

impl Default for StrikeRules {
    /// Weight 1 and 5 strikes within 10 minutes for every kind.
    fn default() -> Self {
        StrikeRules {
            rules: [Rule::default(); KINDS],
        }
    }
}

impl StrikeRules {
    /// Sets the weight, threshold, and window of one kind (`Custom` kinds
    /// share one rule).
    #[must_use]
    pub fn rule(
        mut self,
        kind: StrikeKind,
        weight: u16,
        threshold: u16,
        window: Duration,
    ) -> StrikeRules {
        let r = &mut self.rules[kind.index()];
        r.weight = weight;
        r.threshold = threshold;
        r.window = window;
        self
    }

    /// The duration policy of bans set by this kind's threshold (default:
    /// the bouncer's duration policy).
    #[must_use]
    pub fn duration(mut self, kind: StrikeKind, policy: DurationPolicy) -> StrikeRules {
        self.rules[kind.index()].durations = Some(policy);
        self
    }

    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        for r in &self.rules {
            if r.weight == 0 || r.threshold == 0 {
                return Err(ConfigError::new(
                    "strikes",
                    ConfigProblem::TooSmall { min: 1 },
                ));
            }
            if r.window.is_zero() {
                return Err(ConfigError::new("strikes", ConfigProblem::InvalidDuration));
            }
            if let Some(d) = r.durations {
                d.validate("strikes")?;
            }
        }
        Ok(())
    }

    pub(crate) fn durations(&self, kind: StrikeKind) -> Option<DurationPolicy> {
        self.rules[kind.index()].durations
    }
}

/// Observe or enforce, per strike kind, and which kinds the strict posture
/// switches to enforce.
///
/// # Examples
///
/// ```
/// use bouncer_io::{Enforcement, Mode, Posture, StrikeKind};
/// let e = Enforcement::observe_all().enforce(StrikeKind::ProxyViolation).strict(&[StrikeKind::Malformed]);
/// assert_eq!(e.mode(StrikeKind::ProxyViolation, Posture::Normal), Mode::Enforce);
/// assert_eq!(e.mode(StrikeKind::Malformed, Posture::Normal), Mode::Observe);
/// assert_eq!(e.mode(StrikeKind::Malformed, Posture::Strict), Mode::Enforce);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Enforcement {
    enforce: u16,
    strict: u16,
}

impl Enforcement {
    /// Every kind observes (the default).
    #[must_use]
    pub fn observe_all() -> Enforcement {
        Enforcement::default()
    }

    /// Every kind enforces.
    #[must_use]
    pub fn enforce_all() -> Enforcement {
        Enforcement {
            enforce: (1 << KINDS) - 1,
            strict: 0,
        }
    }

    /// One kind enforces.
    #[must_use]
    pub fn enforce(mut self, kind: StrikeKind) -> Enforcement {
        self.enforce |= 1 << kind.index();
        self
    }

    /// One kind observes.
    #[must_use]
    pub fn observe(mut self, kind: StrikeKind) -> Enforcement {
        self.enforce &= !(1 << kind.index());
        self
    }

    /// Kinds that enforce under the strict posture.
    #[must_use]
    pub fn strict(mut self, kinds: &[StrikeKind]) -> Enforcement {
        for k in kinds {
            self.strict |= 1 << k.index();
        }
        self
    }

    /// The mode of a kind under a posture.
    #[must_use]
    pub fn mode(&self, kind: StrikeKind, posture: Posture) -> Mode {
        let bit = 1 << kind.index();
        let on = self.enforce & bit != 0 || (posture == Posture::Strict && self.strict & bit != 0);
        if on { Mode::Enforce } else { Mode::Observe }
    }
}

/// The bouncer's posture: normal, or strict during a lockdown.
///
/// # Examples
///
/// ```
/// assert_eq!(bouncer_io::Posture::default(), bouncer_io::Posture::Normal);
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub enum Posture {
    /// Normal operation.
    #[default]
    Normal,
    /// Lockdown: tighter budgets, more categories enforced.
    Strict,
}

/// The windowed strike counters.
pub(crate) struct Counters {
    key: HashKey,
    claims: Claims,
    /// window start secs (32) | weighted count (32)
    cells: Box<[AtomicU64]>,
}

/// The key a strike is counted against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Counted {
    Below,
    Reached,
    Full,
}

impl Counters {
    pub(crate) fn new(capacity: u32, key: HashKey) -> Counters {
        let claims = Claims::new(capacity);
        let cells = (0..claims.len()).map(|_| AtomicU64::new(0)).collect();
        Counters { key, claims, cells }
    }

    pub(crate) fn bytes(&self) -> u64 {
        self.claims.bytes() + (self.cells.len() * 8) as u64
    }

    /// The counter key of a source: its IPv4 address or IPv6 /64.
    pub(crate) fn source_key(&self, kind: StrikeKind, addr: IpAddr) -> u64 {
        let host = Cidr::host(addr);
        let p = match host.family() {
            Family::V4 => host,
            Family::V6 => host.parent(64).unwrap_or(host),
        };
        Claims::key(self.key.hash3(
            (kind.code() << 8) | u64::from(p.len()),
            (p.bits() >> 64) as u64,
            p.bits() as u64,
        ))
    }

    /// The counter key of an identity (session, account) by its two words.
    pub(crate) fn identity_key(&self, kind: StrikeKind, tag: u64, k0: u64, k1: u64) -> u64 {
        Claims::key(self.key.hash3((kind.code() << 8) | (tag << 56), k0, k1))
    }

    /// Adds `weight` within the rule's window; reports whether the threshold
    /// is reached by this strike (exactly once per window).
    pub(crate) fn add(
        &self,
        rules: &StrikeRules,
        kind: StrikeKind,
        key: u64,
        now_secs: u64,
    ) -> Counted {
        let rule = rules.rules[kind.index()];
        let window = rule.window.as_secs().max(1);
        let cells = &self.cells;
        let idle = |slot: usize| {
            let v = cells[slot].load(Ordering::Acquire);
            (v >> 32) + window <= now_secs
        };
        let Some((slot, _)) = self
            .claims
            .find_or_claim(key, idle, |s| cells[s].store(0, Ordering::Release))
        else {
            return Counted::Full;
        };
        let now32 = now_secs.min(u64::from(u32::MAX));
        let mut reached = false;
        let _ = update(&cells[slot], Ordering::AcqRel, Ordering::Acquire, |v| {
            let (start, count) = (v >> 32, v & 0xffff_ffff);
            let (start, count) = if start + window <= now32 || v == 0 {
                (now32, 0)
            } else {
                (start, count)
            };
            let next = count
                .saturating_add(u64::from(rule.weight))
                .min(0xffff_ffff);
            reached = count < u64::from(rule.threshold) && next >= u64::from(rule.threshold);
            Some((start << 32) | next)
        });
        if reached {
            Counted::Reached
        } else {
            Counted::Below
        }
    }
}

/// Records a strike against a ticket's keys (`Ticket::strike`).
pub(crate) fn strike(
    shard: &crate::registry::Shard,
    index: u32,
    gen_: u32,
    kind: StrikeKind,
) -> StrikeOutcome {
    use crate::{
        bans::{BanDuration, BanSpec},
        directive::{Actor, Reason},
        events::{Emit, signals},
        registry::{F_CLIENT_BOUND, F_IMMUNE, F_LIVE, F_PENDING_CLIENT, F_PROXY_HOP, generation},
        ticket::{mark_revoked, subject_of},
        verdict::{DenialCode, Reference},
    };
    let shared = &shard.shared;
    let cell = shared.registry.cell(index);
    let st = cell.state.load(Ordering::Acquire);
    if generation(st) != gen_ || st & F_LIVE == 0 {
        return StrikeOutcome::Ignored(IgnoredBecause::Released);
    }
    if st & F_PROXY_HOP != 0
        && st & F_CLIENT_BOUND == 0
        && st & 0xff == crate::registry::KIND_CONNECTION
    {
        return StrikeOutcome::Ignored(IgnoredBecause::TrustedProxy);
    }
    if st & F_PENDING_CLIENT != 0 {
        return StrikeOutcome::Ignored(IgnoredBecause::PendingClient);
    }
    if st & F_IMMUNE != 0 {
        return StrikeOutcome::Ignored(IgnoredBecause::AllowListed);
    }
    let subject = subject_of(cell);
    let mode = shared.enforcement.mode(kind, shared.posture());
    if shared.sink.is_some() {
        Emit {
            actor: Actor::Local,
            reason: Reason::STRIKE_THRESHOLD,
            subject,
            mode,
            ..Emit::new(signals::STRIKE)
        }
        .send(shared);
    }
    // Revoking the ticket (and its connection) makes it fail its next
    // checkpoint; the epoch moves because nothing else would tell its fast path.
    let revoke_ticket = || {
        mark_revoked(cell, gen_, DenialCode::Forbidden);
        if st & 0xff == crate::registry::KIND_REQUEST {
            let link = cell.link.load(Ordering::Relaxed);
            mark_revoked(
                shared.registry.cell((link >> 32) as u32),
                link as u32,
                DenialCode::Forbidden,
            );
        }
        shard.epoch.bump();
    };
    let policy = shared.strikes.durations(kind);
    if kind == StrikeKind::DecoyTouched {
        // Definitive: revoke and ban the keys, whatever the mode.
        let mut first = None;
        let keys = [
            subject.source.map(BanKey::Address),
            subject.session.map(BanKey::Session),
            subject.account.map(BanKey::Account),
        ];
        for key in keys.into_iter().flatten() {
            let spec = BanSpec {
                duration: BanDuration::Policy,
                ..BanSpec::key(key).by(Actor::Local).because(Reason::DECOY)
            };
            if let Ok(id) = shared.ban(&spec, policy) {
                first.get_or_insert(id);
            }
        }
        revoke_ticket();
        return match first {
            Some(id) => StrikeOutcome::Banned(id),
            None => StrikeOutcome::Counted,
        };
    }
    let now = shared.now().secs();
    let counters = &shared.counters;
    let mut reached: Option<BanKey> = None;
    let mut full = false;
    let mut count = |key: u64, ban: BanKey| match counters.add(&shared.strikes, kind, key, now) {
        Counted::Reached => {
            reached.get_or_insert(ban);
        }
        Counted::Full => full = true,
        Counted::Below => {}
    };
    if let Some(src) = subject.source {
        count(counters.source_key(kind, src), BanKey::Address(src));
    }
    if let Some(s) = subject.session {
        let (k0, k1) = s.words();
        count(counters.identity_key(kind, 1, k0, k1), BanKey::Session(s));
    }
    if let Some(a) = subject.account {
        count(
            counters.identity_key(kind, 2, (a.0 >> 64) as u64, a.0 as u64),
            BanKey::Account(a),
        );
    }
    let Some(would_ban) = reached else {
        return if full {
            StrikeOutcome::Ignored(IgnoredBecause::CounterTableFull)
        } else {
            StrikeOutcome::Counted
        };
    };
    if shared.sink.is_some() {
        Emit {
            actor: Actor::Local,
            reason: Reason::STRIKE_THRESHOLD,
            subject: crate::bouncer::subject_of_key(&would_ban),
            mode,
            reference: Reference::new(0),
            ..Emit::new(signals::THRESHOLD_REACHED)
        }
        .send(shared);
    }
    if mode == Mode::Observe {
        return StrikeOutcome::ThresholdObserved { would_ban };
    }
    let spec = BanSpec::key(would_ban)
        .by(Actor::Local)
        .because(Reason::STRIKE_THRESHOLD);
    match shared.ban(&spec, policy) {
        Ok(id) => {
            revoke_ticket();
            StrikeOutcome::Banned(id)
        }
        // Allow-listed, a proxy, or a full table: nothing to ban.
        Err(_) => StrikeOutcome::Counted,
    }
}

#[cfg(all(test, not(bouncer_loom)))]
mod tests {
    use super::*;

    #[test]
    fn test_counter_reaches_threshold_once_per_window() {
        let c = Counters::new(64, HashKey::new(3, 4));
        let rules =
            StrikeRules::default().rule(StrikeKind::Malformed, 1, 3, Duration::from_secs(10));
        let k = c.source_key(StrikeKind::Malformed, "192.0.2.1".parse().unwrap());
        assert_eq!(c.add(&rules, StrikeKind::Malformed, k, 100), Counted::Below);
        assert_eq!(c.add(&rules, StrikeKind::Malformed, k, 101), Counted::Below);
        assert_eq!(
            c.add(&rules, StrikeKind::Malformed, k, 102),
            Counted::Reached
        );
        assert_eq!(
            c.add(&rules, StrikeKind::Malformed, k, 103),
            Counted::Below,
            "once per window"
        );
        // A new window starts the count again.
        assert_eq!(c.add(&rules, StrikeKind::Malformed, k, 115), Counted::Below);
    }

    #[test]
    fn test_counter_weight_and_kinds_separate() {
        let c = Counters::new(64, HashKey::new(3, 4));
        let rules =
            StrikeRules::default().rule(StrikeKind::LoginFailed, 3, 3, Duration::from_secs(60));
        let a: IpAddr = "192.0.2.9".parse().unwrap();
        let k1 = c.source_key(StrikeKind::LoginFailed, a);
        let k2 = c.source_key(StrikeKind::Malformed, a);
        assert_ne!(k1, k2);
        assert_eq!(
            c.add(&rules, StrikeKind::LoginFailed, k1, 1),
            Counted::Reached
        );
        assert_eq!(c.add(&rules, StrikeKind::Malformed, k2, 1), Counted::Below);
    }

    #[test]
    fn test_counter_ipv6_counts_per_64() {
        let c = Counters::new(64, HashKey::new(3, 4));
        let a = c.source_key(StrikeKind::Malformed, "2001:db8::1".parse().unwrap());
        let b = c.source_key(StrikeKind::Malformed, "2001:db8::2".parse().unwrap());
        assert_eq!(a, b);
    }

    #[test]
    fn test_rules_validation_and_enforcement_modes() {
        assert!(StrikeRules::default().validate().is_ok());
        assert!(
            StrikeRules::default()
                .rule(StrikeKind::Malformed, 0, 1, Duration::from_secs(1))
                .validate()
                .is_err()
        );
        assert!(
            StrikeRules::default()
                .rule(StrikeKind::Malformed, 1, 1, Duration::ZERO)
                .validate()
                .is_err()
        );
        let all = Enforcement::enforce_all();
        assert_eq!(
            all.mode(StrikeKind::Custom(5), Posture::Normal),
            Mode::Enforce
        );
        assert_eq!(
            all.observe(StrikeKind::SlowPeer)
                .mode(StrikeKind::SlowPeer, Posture::Normal),
            Mode::Observe
        );
        assert_eq!(
            Enforcement::default().mode(StrikeKind::DecoyTouched, Posture::Strict),
            Mode::Observe
        );
    }
}
