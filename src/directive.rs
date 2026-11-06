//! Who acted, why, and the evidence: recorded on every ban and event.

use core::{fmt, time::Duration};
use std::net::IpAddr;

/// Who acted. Recorded on every ban and event.
///
/// | Actor | May ban permanently | Enforcement |
/// |---|---|---|
/// | `App` (the application's own code; the Tier 1 calls) | yes | always |
/// | `Admin(id)` | yes | always |
/// | `Policy(rule)` | no | always |
/// | `Sentinel` | yes | always |
/// | `Gate` | no | always |
/// | `Channel(node)` | no | always, rate limited |
/// | `Local` (bouncer's own strike thresholds) | no | observe by default |
///
/// Automated actors (every one except `App` and `Admin`) never act on
/// allow-listed keys or trusted proxies, and ban only at the configured
/// automatic prefix lengths.
///
/// # Examples
///
/// ```
/// use bouncer_io::Actor;
/// assert!(Actor::Admin(17).may_ban_permanently());
/// assert!(!Actor::Policy(3).may_ban_permanently());
/// assert!(Actor::Local.is_automated());
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Actor {
    /// The application's own code.
    App,
    /// A named administrator.
    Admin(u64),
    /// A rule of the security signals policy.
    Policy(u32),
    /// sentinel-sec.
    Sentinel,
    /// The authentication and authorization gates.
    Gate,
    /// Another node or the back-channel.
    Channel(u64),
    /// bouncer's own strike thresholds.
    Local,
}

impl Actor {
    /// `true` for every actor except `App` and `Admin`.
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::Actor;
    /// assert!(Actor::Gate.is_automated());
    /// assert!(Actor::Policy(4).is_automated());
    /// assert!(!Actor::App.is_automated());
    /// assert!(!Actor::Admin(1).is_automated());
    /// ```
    #[must_use]
    pub const fn is_automated(&self) -> bool {
        !matches!(self, Actor::App | Actor::Admin(_))
    }

    /// `true` for `App`, `Admin`, and `Sentinel`.
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::Actor;
    /// assert!(Actor::Sentinel.may_ban_permanently());
    /// assert!(!Actor::Gate.may_ban_permanently());
    /// assert!(!Actor::Local.may_ban_permanently());
    /// ```
    #[must_use]
    pub const fn may_ban_permanently(&self) -> bool {
        matches!(self, Actor::App | Actor::Admin(_) | Actor::Sentinel)
    }

    /// The kind of actor, without its id.
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::{Actor, ActorKind};
    /// assert_eq!(Actor::Policy(12).kind(), ActorKind::Policy);
    /// assert_eq!(Actor::Channel(3).kind(), Actor::Channel(9).kind());
    /// ```
    #[must_use]
    pub const fn kind(&self) -> ActorKind {
        match self {
            Actor::App => ActorKind::App,
            Actor::Admin(_) => ActorKind::Admin,
            Actor::Policy(_) => ActorKind::Policy,
            Actor::Sentinel => ActorKind::Sentinel,
            Actor::Gate => ActorKind::Gate,
            Actor::Channel(_) => ActorKind::Channel,
            Actor::Local => ActorKind::Local,
        }
    }
}

impl fmt::Display for Actor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Actor::App => f.write_str("App"),
            Actor::Admin(id) => write!(f, "Admin({id})"),
            Actor::Policy(rule) => write!(f, "Policy({rule})"),
            Actor::Sentinel => f.write_str("Sentinel"),
            Actor::Gate => f.write_str("Gate"),
            Actor::Channel(node) => write!(f, "Channel({node})"),
            Actor::Local => f.write_str("Local"),
        }
    }
}

/// The kind of an [`Actor`], as stored in compact records.
///
/// # Examples
///
/// ```
/// use bouncer_io::{Actor, ActorKind};
/// assert_eq!(Actor::Admin(4).kind(), ActorKind::Admin);
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActorKind {
    /// See [`Actor::App`].
    App,
    /// See [`Actor::Admin`].
    Admin,
    /// See [`Actor::Policy`].
    Policy,
    /// See [`Actor::Sentinel`].
    Sentinel,
    /// See [`Actor::Gate`].
    Gate,
    /// See [`Actor::Channel`].
    Channel,
    /// See [`Actor::Local`].
    Local,
}

impl ActorKind {
    pub(crate) const fn code(self) -> u8 {
        match self {
            ActorKind::App => 0,
            ActorKind::Admin => 1,
            ActorKind::Policy => 2,
            ActorKind::Sentinel => 3,
            ActorKind::Gate => 4,
            ActorKind::Channel => 5,
            ActorKind::Local => 6,
        }
    }

    pub(crate) const fn from_code(code: u8) -> ActorKind {
        match code {
            1 => ActorKind::Admin,
            2 => ActorKind::Policy,
            3 => ActorKind::Sentinel,
            4 => ActorKind::Gate,
            5 => ActorKind::Channel,
            6 => ActorKind::Local,
            _ => ActorKind::App,
        }
    }
}

/// A catalog code for why something happened. It goes to events and audit,
/// never to the subject.
///
/// Codes below 1000 are bouncer's; projects use [`Reason::custom`].
///
/// # Examples
///
/// ```
/// use bouncer_io::Reason;
/// assert_eq!(Reason::custom(1042).code(), 1042);
/// assert_eq!(Reason::custom(5).code(), 1000);
/// assert_ne!(Reason::LOGOUT, Reason::ADMIN);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Reason(u16);

impl Reason {
    /// An administrator or the application decided.
    pub const ADMIN: Reason = Reason(1);
    /// The session logged out.
    pub const LOGOUT: Reason = Reason(2);
    /// Every session of the account logged out.
    pub const LOGOUT_EVERYWHERE: Reason = Reason(3);
    /// The account's password changed.
    pub const PASSWORD_CHANGED: Reason = Reason(4);
    /// The account's standing changed (suspended, closed, demoted).
    pub const STANDING_CHANGED: Reason = Reason(5);
    /// The security signals policy decided.
    pub const POLICY: Reason = Reason(6);
    /// A local strike threshold was reached.
    pub const STRIKE_THRESHOLD: Reason = Reason(7);
    /// A decoy was touched.
    pub const DECOY: Reason = Reason(8);
    /// The record was imported from another node.
    pub const IMPORTED: Reason = Reason(9);
    /// The connection closed while the request was live.
    pub const CONNECTION_CLOSED: Reason = Reason(10);
    /// The strict posture (a lockdown).
    pub const LOCKDOWN: Reason = Reason(11);
    /// Over a budget.
    pub const BUDGET: Reason = Reason(12);

    /// A project's own code; values below 1000 are raised to 1000.
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::Reason;
    /// assert_eq!(Reason::custom(4001).code(), 4001);
    /// assert_eq!(Reason::custom(12), Reason::custom(1000));
    /// assert_eq!(Reason::custom(4001).to_string(), "custom(4001)");
    /// ```
    #[must_use]
    pub const fn custom(code: u16) -> Reason {
        Reason(if code < 1000 { 1000 } else { code })
    }

    /// The numeric code.
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::Reason;
    /// assert_eq!(Reason::DECOY.code(), 8);
    /// assert_eq!(Reason::DECOY.to_string(), "decoy");
    /// ```
    #[must_use]
    pub const fn code(self) -> u16 {
        self.0
    }

    pub(crate) const fn from_code(code: u16) -> Reason {
        Reason(code)
    }
}

impl fmt::Display for Reason {
    /// The catalog name, or `custom(code)`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self.0 {
            1 => "admin",
            2 => "logout",
            3 => "logout_everywhere",
            4 => "password_changed",
            5 => "standing_changed",
            6 => "policy",
            7 => "strike_threshold",
            8 => "decoy",
            9 => "imported",
            10 => "connection_closed",
            11 => "lockdown",
            12 => "budget",
            code => return write!(f, "custom({code})"),
        };
        f.write_str(name)
    }
}

/// One evidence value. There is no variant for session or fingerprint
/// digests, so secrets cannot end up in evidence.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EvidenceValue<'a> {
    /// A count or measurement.
    Number(u64),
    /// Short text (cut at the evidence budget).
    Text(&'a str),
    /// An address.
    Address(IpAddr),
    /// A time span.
    Duration(Duration),
    /// A yes or no.
    Flag(bool),
}

/// Bounded key-value evidence, borrowed: at most
/// [`MAX_EVIDENCE_BYTES`](crate::MAX_EVIDENCE_BYTES) are kept.
///
/// # Examples
///
/// ```
/// use bouncer_io::{Evidence, EvidenceValue};
/// static PAIRS: [(&str, EvidenceValue<'static>); 2] =
///     [("failed_logins", EvidenceValue::Number(12)), ("window_s", EvidenceValue::Number(600))];
/// let evidence = Evidence::new(&PAIRS);
/// assert_eq!(evidence.pairs().len(), 2);
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct Evidence<'a> {
    pairs: &'a [(&'static str, EvidenceValue<'a>)],
}

impl<'a> Evidence<'a> {
    /// No evidence.
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::Evidence;
    /// assert!(Evidence::none().pairs().is_empty());
    /// ```
    #[must_use]
    pub const fn none() -> Evidence<'static> {
        Evidence { pairs: &[] }
    }

    /// Evidence from borrowed pairs.
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::{Evidence, EvidenceValue};
    /// static PAIRS: [(&str, EvidenceValue<'static>); 1] = [("probes", EvidenceValue::Number(40))];
    /// let evidence = Evidence::new(&PAIRS);
    /// assert_eq!(evidence.pairs()[0].0, "probes");
    /// ```
    #[must_use]
    pub const fn new(pairs: &'a [(&'static str, EvidenceValue<'a>)]) -> Evidence<'a> {
        Evidence { pairs }
    }

    /// The pairs.
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::{Evidence, EvidenceValue};
    /// static PAIRS: [(&str, EvidenceValue<'static>); 2] =
    ///     [("path", EvidenceValue::Text("/.env")), ("decoy", EvidenceValue::Flag(true))];
    /// let pairs = Evidence::new(&PAIRS).pairs();
    /// assert_eq!(pairs.len(), 2);
    /// assert_eq!(pairs[1], ("decoy", EvidenceValue::Flag(true)));
    /// ```
    #[must_use]
    pub const fn pairs(&self) -> &'a [(&'static str, EvidenceValue<'a>)] {
        self.pairs
    }
}

/// What a directive does.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Divides the key's budgets by `factor` (2 to 16) for the duration.
    Throttle {
        /// The divisor.
        factor: u8,
        /// How long.
        duration: Duration,
    },
    /// Bans the target's key.
    Ban(crate::bans::BanDuration),
    /// Revokes what is running.
    Revoke(crate::revoke::RevokeMode),
    /// Revokes what is running and bans for the future.
    RevokeAndBan(crate::revoke::RevokeMode, crate::bans::BanDuration),
    /// Lifts bans on the target's key.
    Lift,
}

/// Which of a ticket's keys a connection or request ban takes.
///
/// # Examples
///
/// ```
/// use bouncer_io::BanKeys;
/// let keys = BanKeys::SOURCE | BanKeys::ACCOUNT;
/// assert!(keys.contains(BanKeys::ACCOUNT));
/// assert!(!keys.contains(BanKeys::SESSION));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BanKeys(u8);

impl BanKeys {
    /// The source, at its automatic length (IPv4 address, IPv6 /64).
    pub const SOURCE: BanKeys = BanKeys(1);
    /// The fingerprint within the source's prefix.
    pub const FINGERPRINT_IN_PREFIX: BanKeys = BanKeys(2);
    /// The session.
    pub const SESSION: BanKeys = BanKeys(4);
    /// The account.
    pub const ACCOUNT: BanKeys = BanKeys(8);
    /// The tenant.
    pub const TENANT: BanKeys = BanKeys(16);

    /// `true` when every key of `other` is included.
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::BanKeys;
    /// let keys = BanKeys::SESSION | BanKeys::TENANT;
    /// assert!(keys.contains(BanKeys::SESSION | BanKeys::TENANT));
    /// assert!(!keys.contains(BanKeys::SESSION | BanKeys::ACCOUNT)); // every key must be in
    /// ```
    #[must_use]
    pub const fn contains(self, other: BanKeys) -> bool {
        self.0 & other.0 == other.0
    }
}

impl core::ops::BitOr for BanKeys {
    type Output = BanKeys;
    fn bitor(self, rhs: BanKeys) -> BanKeys {
        BanKeys(self.0 | rhs.0)
    }
}

/// A decision made elsewhere (the security signals policy, sentinel-sec, the
/// gates, an administrator, another node), carried to
/// [`Bouncer::apply`](crate::Bouncer::apply). Reads as a sentence.
///
/// # Examples
///
/// ```
/// use bouncer_io::{Actor, Bouncer, Directive, Reason, SessionKey};
///
/// let bouncer = Bouncer::new();
/// let session = SessionKey::from_digest([3u8; 16]);
/// let applied = bouncer.apply(
///     Directive::revoke_and_ban(session)
///         .by(Actor::Sentinel)
///         .because(Reason::DECOY)
///         .confidence(95)
///         .eject_now(),
/// )?;
/// assert!(applied.revocation.is_some() && applied.ban.is_some());
/// # Ok::<(), bouncer_io::BouncerError>(())
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Copy)]
pub struct Directive {
    /// What to do.
    pub action: Action,
    /// To whom.
    pub target: crate::revoke::Target,
    /// Who decided.
    pub actor: Actor,
    /// Why.
    pub reason: Reason,
    /// How sure, 0 to 100 (STIX); `None` when not judged.
    pub confidence: Option<u8>,
    pub(crate) keep_connection: bool,
    pub(crate) ban_keys: Option<BanKeys>,
    pub(crate) deny_with: Option<crate::verdict::DenialCode>,
    pub(crate) evidence: Evidence<'static>,
}

impl Directive {
    fn new(action: Action, target: crate::revoke::Target) -> Directive {
        Directive {
            action,
            target,
            actor: Actor::App,
            reason: Reason::ADMIN,
            confidence: None,
            keep_connection: false,
            ban_keys: None,
            deny_with: None,
            evidence: Evidence::none(),
        }
    }

    /// Bans the target's key for the future (the duration policy).
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::{Bouncer, Directive, RequestId};
    /// let bouncer = Bouncer::new();
    /// let addr: std::net::IpAddr = "203.0.113.30".parse()?;
    /// let conn = bouncer.door(addr)?;
    /// let applied = bouncer.apply(Directive::ban(addr))?;
    /// assert!(applied.ban.is_some());
    /// assert!(bouncer.door(addr).is_err());
    /// // A ban alone leaves running work alone.
    /// assert!(conn.request(RequestId(1))?.checkpoint().is_pass());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub fn ban(target: impl Into<crate::revoke::Target>) -> Directive {
        Directive::new(Action::Ban(crate::bans::BanDuration::Policy), target.into())
    }

    /// Revokes what is running.
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::{Bouncer, Directive, RequestId, SessionKey};
    /// let bouncer = Bouncer::new();
    /// let session = SessionKey::from_digest([7; 16]);
    /// let conn = bouncer.door("192.0.2.60".parse()?)?;
    /// let mut request = conn.request(RequestId(1))?;
    /// assert!(request.bind_session(session).is_pass());
    /// let applied = bouncer.apply(Directive::revoke(session))?;
    /// assert!(applied.revocation.is_some() && applied.ban.is_none());
    /// assert!(request.checkpoint().is_deny());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub fn revoke(target: impl Into<crate::revoke::Target>) -> Directive {
        Directive::new(
            Action::Revoke(crate::revoke::RevokeMode::AtCheckpoint),
            target.into(),
        )
    }

    /// Revokes what is running and bans for the future: wipe, eject, and
    /// remember.
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::{Bouncer, Directive, RequestId};
    /// let bouncer = Bouncer::new();
    /// let addr: std::net::IpAddr = "203.0.113.31".parse()?;
    /// let conn = bouncer.door(addr)?;
    /// let mut request = conn.request(RequestId(1))?;
    /// bouncer.apply(Directive::revoke_and_ban(addr))?;
    /// assert!(request.checkpoint().is_deny()); // running work stops
    /// assert!(bouncer.door(addr).is_err()); // and the source stays out
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub fn revoke_and_ban(target: impl Into<crate::revoke::Target>) -> Directive {
        Directive::new(
            Action::RevokeAndBan(
                crate::revoke::RevokeMode::AtCheckpoint,
                crate::bans::BanDuration::Policy,
            ),
            target.into(),
        )
    }

    /// Divides the key's budgets by `factor` (clamped to 2..=16) for `duration`.
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::{Bouncer, Budgets, Directive, Rate};
    /// use std::time::Duration;
    /// let bouncer = Bouncer::builder()
    ///     .budgets(Budgets::off().door_rate(Rate::per_minute(8), Rate::per_minute(1_000)))
    ///     .try_build()?;
    /// let addr: std::net::IpAddr = "198.51.100.40".parse()?;
    /// let applied = bouncer.apply(Directive::throttle(addr, 4, Duration::from_secs(600)))?;
    /// assert!(applied.throttled);
    /// // A quarter of the burst of 8 gets in.
    /// let admitted = (0..8).filter(|_| bouncer.door(addr).is_ok()).count();
    /// assert_eq!(admitted, 2);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub fn throttle(
        target: impl Into<crate::revoke::Target>,
        factor: u8,
        duration: Duration,
    ) -> Directive {
        Directive::new(
            Action::Throttle {
                factor: factor.clamp(2, 16),
                duration,
            },
            target.into(),
        )
    }

    /// Lifts bans on the target's key.
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::{Bouncer, Directive};
    /// let bouncer = Bouncer::new();
    /// let addr: std::net::IpAddr = "198.51.100.41".parse()?;
    /// bouncer.ban(addr)?;
    /// let applied = bouncer.apply(Directive::lift(addr))?;
    /// assert_eq!(applied.lifted.map(|l| l.removed), Some(1));
    /// assert!(bouncer.door(addr).is_ok());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub fn lift(target: impl Into<crate::revoke::Target>) -> Directive {
        Directive::new(Action::Lift, target.into())
    }

    /// Who decided.
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::{Actor, ActorKind, Bouncer, BouncerError, Directive};
    /// let bouncer = Bouncer::new();
    /// let addr: std::net::IpAddr = "198.51.100.42".parse()?;
    /// // A gate may not ban permanently; an administrator may.
    /// let refused = bouncer.apply(Directive::ban(addr).by(Actor::Gate).permanent());
    /// assert!(matches!(refused, Err(BouncerError::PermanentNotAllowed)));
    /// bouncer.apply(Directive::ban(addr).by(Actor::Admin(3)).permanent())?;
    /// assert_eq!(bouncer.explain(addr).bans[0].actor, ActorKind::Admin);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub fn by(mut self, actor: Actor) -> Directive {
        self.actor = actor;
        self
    }

    /// Why.
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::{Bouncer, Directive, Reason};
    /// let bouncer = Bouncer::new();
    /// let addr: std::net::IpAddr = "198.51.100.43".parse()?;
    /// bouncer.apply(Directive::ban(addr).because(Reason::DECOY))?;
    /// assert_eq!(bouncer.explain(addr).bans[0].reason, Reason::DECOY);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub fn because(mut self, reason: Reason) -> Directive {
        self.reason = reason;
        self
    }

    /// How sure, 0 to 100. Below 30 a directive cannot ban by itself; it is
    /// applied as a throttle.
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::{Actor, Bouncer, Directive};
    /// let bouncer = Bouncer::new();
    /// let unsure: std::net::IpAddr = "198.51.100.44".parse()?;
    /// let sure: std::net::IpAddr = "198.51.100.45".parse()?;
    /// let low = bouncer.apply(Directive::ban(unsure).by(Actor::Sentinel).confidence(10))?;
    /// assert!(low.downgraded && low.ban.is_none());
    /// let high = bouncer.apply(Directive::ban(sure).by(Actor::Sentinel).confidence(90))?;
    /// assert!(high.ban.is_some());
    /// assert_eq!(Directive::ban(sure).confidence(250).confidence, Some(100));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub fn confidence(mut self, value: u8) -> Directive {
        self.confidence = Some(value.min(100));
        self
    }

    /// The ban part lasts exactly `duration`.
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::{Bouncer, Directive};
    /// use clock_lib::ManualClock;
    /// use std::{sync::Arc, time::Duration};
    /// let clock = Arc::new(ManualClock::new());
    /// let bouncer = Bouncer::builder().clock(clock.clone()).try_build()?;
    /// let addr: std::net::IpAddr = "198.51.100.46".parse()?;
    /// bouncer.apply(Directive::ban(addr).for_duration(Duration::from_secs(300)))?;
    /// clock.advance(Duration::from_secs(299));
    /// assert!(bouncer.door(addr).is_err());
    /// clock.advance(Duration::from_secs(1));
    /// assert!(bouncer.door(addr).is_ok());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub fn for_duration(mut self, duration: Duration) -> Directive {
        self.set_duration(crate::bans::BanDuration::Fixed(duration));
        self
    }

    /// The ban part lasts until lifted.
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::{Bouncer, Directive};
    /// let bouncer = Bouncer::new();
    /// let addr: std::net::IpAddr = "198.51.100.47".parse()?;
    /// bouncer.apply(Directive::ban(addr).permanent())?;
    /// assert_eq!(bouncer.explain(addr).bans[0].until, None);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub fn permanent(mut self) -> Directive {
        self.set_duration(crate::bans::BanDuration::Permanent);
        self
    }

    fn set_duration(&mut self, d: crate::bans::BanDuration) {
        match &mut self.action {
            Action::Ban(b) | Action::RevokeAndBan(_, b) => *b = d,
            Action::Throttle { duration, .. } => {
                if let crate::bans::BanDuration::Fixed(f) = d {
                    *duration = f;
                }
            }
            _ => {}
        }
    }

    /// Revokes with `RevokeMode::EjectNow`: idle matching connections are
    /// closed too.
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::{Bouncer, Directive};
    /// // No maintainer thread, so the sweep runs inside `apply`.
    /// let bouncer = Bouncer::new();
    /// let idle = bouncer.door("192.0.2.61".parse()?)?;
    /// let applied = bouncer.apply(Directive::revoke(idle.conn()).eject_now())?;
    /// assert_eq!(applied.revocation.and_then(|r| r.matched_live), Some(1));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub fn eject_now(mut self) -> Directive {
        match &mut self.action {
            Action::Revoke(m) | Action::RevokeAndBan(m, _) => {
                *m = crate::revoke::RevokeMode::EjectNow
            }
            _ => {}
        }
        self
    }

    /// Revoking a request leaves its connection open (for an administrator
    /// ending one request on a multiplexed connection).
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::{Bouncer, Directive, RequestId};
    /// let bouncer = Bouncer::new();
    /// let mut conn = bouncer.door("192.0.2.62".parse()?)?;
    /// let mut request = conn.request(RequestId(5))?;
    /// bouncer.apply(Directive::revoke(RequestId(5)).keep_connection())?;
    /// assert!(request.checkpoint().is_deny());
    /// assert!(conn.checkpoint().is_pass()); // the connection carries on
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub fn keep_connection(mut self) -> Directive {
        self.keep_connection = true;
        self
    }

    /// Which of the ticket's keys a connection or request ban takes (default:
    /// the source; the ticket's session instead when the source is flagged
    /// as shared). A local heuristic, a peer node, or a policy below
    /// confidence 70 never bans a shared source this way: it is throttled and
    /// the receipt says `downgraded`.
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::{AccountKey, BanKeys, Bouncer, Directive, RequestId};
    /// let bouncer = Bouncer::new();
    /// let conn = bouncer.door("192.0.2.63".parse()?)?;
    /// let mut request = conn.request(RequestId(6))?;
    /// assert!(request.bind_account(AccountKey(77)).is_pass());
    /// let applied = bouncer.apply(Directive::ban(RequestId(6)).ban_keys(BanKeys::ACCOUNT))?;
    /// assert_eq!(applied.bans, 1);
    /// assert!(!bouncer.explain(AccountKey(77)).admitted);
    /// assert!(bouncer.door("192.0.2.63".parse()?).is_ok()); // the source is not banned
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub fn ban_keys(mut self, keys: BanKeys) -> Directive {
        self.ban_keys = Some(keys);
        self
    }

    /// The denial code revoked requests get (default `Forbidden`).
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::{Bouncer, DenialCode, Directive, RequestId};
    /// let bouncer = Bouncer::new();
    /// let conn = bouncer.door("192.0.2.64".parse()?)?;
    /// let mut request = conn.request(RequestId(7))?;
    /// bouncer.apply(Directive::revoke(RequestId(7)).deny_with(DenialCode::NotFound))?;
    /// assert_eq!(request.checkpoint().denial().map(|d| d.code), Some(DenialCode::NotFound));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub fn deny_with(mut self, code: crate::verdict::DenialCode) -> Directive {
        self.deny_with = Some(code);
        self
    }

    /// Supporting evidence, for events.
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::{signals, Bouncer, Directive, Event, EventSink, Evidence, EvidenceValue};
    /// use std::sync::{Arc, Mutex};
    ///
    /// #[derive(Default)]
    /// struct Kept(Mutex<Vec<u64>>);
    /// impl EventSink for Kept {
    ///     fn event(&self, e: &Event<'_>) {
    ///         if e.path == signals::BAN_ADDED.path() {
    ///             for (_, value) in e.evidence.pairs() {
    ///                 if let EvidenceValue::Number(n) = value {
    ///                     self.0.lock().unwrap().push(*n);
    ///                 }
    ///             }
    ///         }
    ///     }
    /// }
    /// static PAIRS: [(&str, EvidenceValue<'static>); 1] = [("failed_logins", EvidenceValue::Number(12))];
    /// let kept = Arc::new(Kept::default());
    /// let bouncer = Bouncer::builder().event_sink(kept.clone()).try_build()?;
    /// let addr: std::net::IpAddr = "198.51.100.48".parse()?;
    /// bouncer.apply(Directive::ban(addr).evidence(Evidence::new(&PAIRS)))?;
    /// assert_eq!(*kept.0.lock().unwrap(), [12]);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub fn evidence(mut self, evidence: Evidence<'static>) -> Directive {
        self.evidence = evidence;
        self
    }
}

/// What [`Bouncer::apply`](crate::Bouncer::apply) did.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Applied {
    /// The first ban set, if any.
    pub ban: Option<crate::bans::BanId>,
    /// Bans set in all (a connection ban can take several keys).
    pub bans: u32,
    /// The revocation, if any.
    pub revocation: Option<crate::revoke::Revocation>,
    /// The lift, if any.
    pub lifted: Option<crate::bans::Lifted>,
    /// `true` when a throttle was set.
    pub throttled: bool,
    /// `true` when a ban below the Medium confidence band was applied as a
    /// throttle instead.
    pub downgraded: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_actor_rights_table() {
        for (actor, automated, permanent) in [
            (Actor::App, false, true),
            (Actor::Admin(1), false, true),
            (Actor::Policy(1), true, false),
            (Actor::Sentinel, true, true),
            (Actor::Gate, true, false),
            (Actor::Channel(2), true, false),
            (Actor::Local, true, false),
        ] {
            assert_eq!(actor.is_automated(), automated, "{actor}");
            assert_eq!(actor.may_ban_permanently(), permanent, "{actor}");
            assert_eq!(ActorKind::from_code(actor.kind().code()), actor.kind());
        }
    }

    #[test]
    fn test_reason_custom_clamps() {
        assert_eq!(Reason::custom(0).code(), 1000);
        assert_eq!(Reason::custom(65_535).code(), 65_535);
        assert_eq!(Reason::from_code(7), Reason::STRIKE_THRESHOLD);
    }

    #[test]
    fn test_evidence_none_empty() {
        assert!(Evidence::none().pairs().is_empty());
    }
}
