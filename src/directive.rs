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
    #[must_use]
    pub const fn is_automated(&self) -> bool {
        !matches!(self, Actor::App | Actor::Admin(_))
    }

    /// `true` for `App`, `Admin`, and `Sentinel`.
    #[must_use]
    pub const fn may_ban_permanently(&self) -> bool {
        matches!(self, Actor::App | Actor::Admin(_) | Actor::Sentinel)
    }

    /// The kind of actor, without its id.
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

    /// A project's own code; values below 1000 are raised to 1000.
    #[must_use]
    pub const fn custom(code: u16) -> Reason {
        Reason(if code < 1000 { 1000 } else { code })
    }

    /// The numeric code.
    #[must_use]
    pub const fn code(self) -> u16 {
        self.0
    }

    pub(crate) const fn from_code(code: u16) -> Reason {
        Reason(code)
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
    #[must_use]
    pub const fn none() -> Evidence<'static> {
        Evidence { pairs: &[] }
    }

    /// Evidence from borrowed pairs.
    #[must_use]
    pub const fn new(pairs: &'a [(&'static str, EvidenceValue<'a>)]) -> Evidence<'a> {
        Evidence { pairs }
    }

    /// The pairs.
    #[must_use]
    pub const fn pairs(&self) -> &'a [(&'static str, EvidenceValue<'a>)] {
        self.pairs
    }
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
