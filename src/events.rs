//! Events: every action bouncer takes is reported, so the security signal
//! bridge, audit, and sentinel-sec hear about an attack the moment bouncer
//! sees it.
//!
//! Identity, categories, and the severity and confidence axes follow the
//! security signals vocabulary: the id says what was detected; how bad and how
//! sure live in the event.

use core::fmt;
use std::{net::IpAddr, time::SystemTime};

use crate::{
    bouncer::Shared,
    directive::{Actor, Evidence, Reason},
    keys::{AccountKey, Cidr, ConnId, FingerprintKey, RequestId, SessionKey, TenantKey},
    registry::Cell,
    strikes::Mode,
    time::Now,
    verdict::Reference,
};

/// bouncer's generator id in the signal catalog (platform generators are
/// below 1000).
pub const GENERATOR: u16 = 2;

/// Where events go: the security signal bridge, an audit trail, tests.
///
/// The sink is called on the thread that acted. It must not block: copy what
/// you keep (the event borrows its evidence) and hand it off.
///
/// # Examples
///
/// ```
/// use bouncer_io::{Bouncer, Event, EventSink, signals};
/// use std::sync::{Arc, Mutex};
///
/// #[derive(Default)]
/// struct Seen(Mutex<Vec<&'static str>>);
/// impl EventSink for Seen {
///     fn event(&self, e: &Event<'_>) {
///         self.0.lock().unwrap().push(e.path);
///     }
/// }
/// let seen = Arc::new(Seen::default());
/// let bouncer = Bouncer::builder().event_sink(seen.clone()).try_build()?;
/// bouncer.ban("198.51.100.9".parse::<std::net::IpAddr>()?)?;
/// assert!(seen.0.lock().unwrap().contains(&signals::BAN_ADDED.path()));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub trait EventSink: Send + Sync {
    /// Receives one event.
    fn event(&self, event: &Event<'_>);
}

/// A sink that drops every event.
///
/// # Examples
///
/// ```
/// use std::sync::Arc;
/// let bouncer = bouncer_io::Bouncer::builder().event_sink(Arc::new(bouncer_io::NoSink)).try_build()?;
/// # let _ = bouncer;
/// # Ok::<(), bouncer_io::BouncerError>(())
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct NoSink;

impl EventSink for NoSink {
    fn event(&self, _event: &Event<'_>) {}
}

/// The category of a signal (the security signals vocabulary).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Category {
    /// Not classified.
    Unknown,
    /// Reconnaissance: scanning, probing.
    Recon,
    /// Access control: who may connect or continue.
    Access,
    /// Authentication.
    Auth,
    /// Injection.
    Injection,
    /// Abuse: floods, exhaustion.
    Abuse,
    /// Privilege.
    Privilege,
    /// Data leaving.
    Exfil,
    /// Integrity of the system or its records.
    Integrity,
    /// Policy and administration.
    Policy,
    /// Unusual but not classified as an attack.
    Anomaly,
    /// Something else.
    Other,
}

/// A signal's identity: generator, id, revision. The id never changes
/// meaning; a changed detection bumps the revision.
///
/// # Examples
///
/// ```
/// use bouncer_io::signals;
/// assert_eq!(signals::DOOR_REFUSED_BAN.to_string(), "bouncer/1 r1");
/// assert_eq!(signals::DOOR_REFUSED_BAN.path(), "bouncer.door.refused.ban");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SignalId {
    /// The generator (bouncer is [`GENERATOR`]).
    pub generator: u16,
    /// The id within the generator.
    pub id: u32,
    /// The detection's revision.
    pub revision: u16,
}

impl SignalId {
    const fn new(id: u32) -> SignalId {
        SignalId {
            generator: GENERATOR,
            id,
            revision: 1,
        }
    }

    /// The readable path of the signal.
    #[must_use]
    pub const fn path(&self) -> &'static str {
        catalog(self.id).0
    }

    /// The signal's category.
    #[must_use]
    pub const fn category(&self) -> Category {
        catalog(self.id).1
    }

    /// The catalog's default severity, 0 to 10.
    #[must_use]
    pub const fn severity(&self) -> f32 {
        catalog(self.id).2
    }
}

impl fmt::Display for SignalId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "bouncer/{} r{}", self.id, self.revision)
    }
}

/// Path, category, default severity per id.
const fn catalog(id: u32) -> (&'static str, Category, f32) {
    match id {
        1 => ("bouncer.door.refused.ban", Category::Access, 3.0),
        2 => ("bouncer.door.refused.budget", Category::Abuse, 2.0),
        3 => ("bouncer.door.refused.registry_full", Category::Abuse, 4.0),
        4 => (
            "bouncer.door.proxy_hop_unresolved",
            Category::Integrity,
            5.0,
        ),
        5 => ("bouncer.budget.refused", Category::Abuse, 2.0),
        10 => ("bouncer.revoke.applied", Category::Access, 5.0),
        11 => ("bouncer.denial.wipe_eject", Category::Access, 5.0),
        12 => ("bouncer.commit.blocked", Category::Integrity, 6.0),
        13 => ("bouncer.egress.blocked", Category::Integrity, 6.0),
        14 => ("bouncer.checkpoint.missing", Category::Integrity, 5.0),
        15 => ("bouncer.posture.changed", Category::Policy, 4.0),
        20 => ("bouncer.ban.added", Category::Access, 4.0),
        21 => ("bouncer.ban.escalated", Category::Access, 5.0),
        22 => ("bouncer.ban.lifted", Category::Policy, 1.0),
        23 => ("bouncer.ban.expired", Category::Policy, 0.5),
        24 => ("bouncer.ban.evicted", Category::Abuse, 4.0),
        25 => ("bouncer.ban.table_full", Category::Abuse, 7.0),
        26 => ("bouncer.ban.refused_allowlisted", Category::Policy, 3.0),
        30 => ("bouncer.strike", Category::Abuse, 2.0),
        31 => ("bouncer.threshold.reached", Category::Abuse, 4.0),
        40 => ("bouncer.source.shared_suspected", Category::Anomaly, 1.0),
        50 => ("bouncer.persist.failed", Category::Integrity, 6.0),
        51 => ("bouncer.import.rejected", Category::Integrity, 5.0),
        60 => ("bouncer.table.reseeded", Category::Abuse, 6.0),
        _ => ("bouncer.unknown", Category::Unknown, 0.0),
    }
}

/// The signal catalog. Ids never change meaning.
///
/// # Examples
///
/// ```
/// use bouncer_io::signals;
/// assert_eq!(signals::REVOKE_APPLIED.id, 10);
/// ```
pub mod signals {
    use super::SignalId;

    /// A banned source tried to connect (sampled).
    pub const DOOR_REFUSED_BAN: SignalId = SignalId::new(1);
    /// Over the accept rate or concurrency budget (sampled).
    pub const DOOR_REFUSED_BUDGET: SignalId = SignalId::new(2);
    /// No free ticket (sampled).
    pub const DOOR_REFUSED_REGISTRY_FULL: SignalId = SignalId::new(3);
    /// A proxied connection never bound a real client.
    pub const DOOR_PROXY_HOP_UNRESOLVED: SignalId = SignalId::new(4);
    /// Over a lane, tenant rate, or tenant in-flight budget (sampled).
    pub const BUDGET_REFUSED: SignalId = SignalId::new(5);
    /// Any revocation.
    pub const REVOKE_APPLIED: SignalId = SignalId::new(10);
    /// A request was wiped, denied, and ejected.
    pub const DENIAL_WIPE_EJECT: SignalId = SignalId::new(11);
    /// A before-commit checkpoint denied.
    pub const COMMIT_BLOCKED: SignalId = SignalId::new(12);
    /// A transport egress check denied.
    pub const EGRESS_BLOCKED: SignalId = SignalId::new(13);
    /// A revoked ticket went without a checkpoint; the maintainer ejected it.
    pub const CHECKPOINT_MISSING: SignalId = SignalId::new(14);
    /// The posture changed (lockdown entered or left).
    pub const POSTURE_CHANGED: SignalId = SignalId::new(15);
    /// A ban was inserted.
    pub const BAN_ADDED: SignalId = SignalId::new(20);
    /// A prefix escalation.
    pub const BAN_ESCALATED: SignalId = SignalId::new(21);
    /// A ban was lifted.
    pub const BAN_LIFTED: SignalId = SignalId::new(22);
    /// An expiry was noticed (sampled).
    pub const BAN_EXPIRED: SignalId = SignalId::new(23);
    /// A ban was evicted from a full table.
    pub const BAN_EVICTED: SignalId = SignalId::new(24);
    /// A ban insert was refused: the table holds only entries never evicted.
    pub const BAN_TABLE_FULL: SignalId = SignalId::new(25);
    /// Automation tried to act on an allow-listed key.
    pub const BAN_REFUSED_ALLOWLISTED: SignalId = SignalId::new(26);
    /// A strike was received.
    pub const STRIKE: SignalId = SignalId::new(30);
    /// A local threshold was reached (observe or enforce).
    pub const THRESHOLD_REACHED: SignalId = SignalId::new(31);
    /// An address was flagged as shared.
    pub const SOURCE_SHARED_SUSPECTED: SignalId = SignalId::new(40);
    /// A persistence write or load failed.
    pub const PERSIST_FAILED: SignalId = SignalId::new(50);
    /// An import delta failed validation.
    pub const IMPORT_REJECTED: SignalId = SignalId::new(51);
    /// A table was rebuilt with a new seed.
    pub const TABLE_RESEEDED: SignalId = SignalId::new(60);
}

/// The keys an event is about. Digests print redacted.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Subject {
    /// The connection.
    pub conn: Option<ConnId>,
    /// The request.
    pub request: Option<RequestId>,
    /// The source address.
    pub source: Option<IpAddr>,
    /// A prefix (bans, source revocations).
    pub prefix: Option<Cidr>,
    /// The session.
    pub session: Option<SessionKey>,
    /// The account.
    pub account: Option<AccountKey>,
    /// The tenant.
    pub tenant: Option<TenantKey>,
    /// The fingerprint.
    pub fingerprint: Option<FingerprintKey>,
}

/// One event. Fixed size, no allocation; the evidence is borrowed.
#[non_exhaustive]
#[derive(Debug, Clone, Copy)]
pub struct Event<'a> {
    /// What was detected or done.
    pub signal: SignalId,
    /// The signal's readable path.
    pub path: &'static str,
    /// The signal's category.
    pub category: crate::events::Category,
    /// Severity, 0 to 10 (the catalog default unless the action carried one).
    pub severity: f32,
    /// Confidence, 0 to 100, when the actor judged it.
    pub confidence: Option<u8>,
    /// Monotonic time of the event.
    pub at: Now,
    /// Wall time of the event.
    pub wall: SystemTime,
    /// Who acted.
    pub actor: Actor,
    /// Why.
    pub reason: Reason,
    /// The keys involved.
    pub subject: Subject,
    /// The reference that finds this event (a denial's or a ban's).
    pub reference: Reference,
    /// For sampled events, how many occurrences this one stands for.
    pub count: u32,
    /// `Observe` for "would have" events.
    pub mode: Mode,
    /// Bounded evidence.
    pub evidence: Evidence<'a>,
    /// `true` when the evidence was cut at the budget.
    pub truncated: bool,
}

/// Builds and delivers an event when a sink is configured.
pub(crate) struct Emit<'a> {
    pub(crate) signal: SignalId,
    pub(crate) actor: Actor,
    pub(crate) reason: Reason,
    pub(crate) subject: Subject,
    pub(crate) reference: Reference,
    pub(crate) count: u32,
    pub(crate) mode: Mode,
    pub(crate) confidence: Option<u8>,
    pub(crate) evidence: Evidence<'a>,
}

impl Emit<'_> {
    pub(crate) fn new(signal: SignalId) -> Emit<'static> {
        Emit {
            signal,
            actor: Actor::App,
            reason: Reason::ADMIN,
            subject: Subject::default(),
            reference: Reference::new(0),
            count: 1,
            mode: Mode::Enforce,
            confidence: None,
            evidence: Evidence::none(),
        }
    }

    pub(crate) fn send(self, shared: &Shared) {
        let Some(sink) = shared.sink.as_ref() else {
            return;
        };
        let (evidence, truncated) = bounded(self.evidence);
        let event = Event {
            signal: self.signal,
            path: self.signal.path(),
            category: self.signal.category(),
            severity: self.signal.severity(),
            confidence: self.confidence,
            at: shared.now(),
            wall: shared.wall(),
            actor: self.actor,
            reason: self.reason,
            subject: self.subject,
            reference: self.reference,
            count: self.count,
            mode: self.mode,
            evidence,
            truncated,
        };
        sink.event(&event);
    }
}

/// Cuts evidence to the byte budget: keeps whole pairs while they fit.
fn bounded(evidence: Evidence<'_>) -> (Evidence<'_>, bool) {
    let pairs = evidence.pairs();
    let mut used = 0usize;
    for (i, (key, value)) in pairs.iter().enumerate() {
        let size = key.len()
            + match value {
                crate::directive::EvidenceValue::Text(t) => t.len(),
                _ => 16,
            };
        used += size;
        if used > crate::MAX_EVIDENCE_BYTES {
            return (Evidence::new(&pairs[..i]), true);
        }
    }
    (evidence, false)
}

/// An event about one ticket's cell.
pub(crate) fn emit_ticket(shared: &Shared, signal: SignalId, cell: &Cell, reference: Reference) {
    if shared.sink.is_none() {
        return;
    }
    Emit {
        subject: crate::ticket::subject_of(cell),
        reference,
        ..Emit::new(signal)
    }
    .send(shared);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directive::EvidenceValue;

    #[test]
    fn test_catalog_paths_and_unknown() {
        assert_eq!(signals::EGRESS_BLOCKED.path(), "bouncer.egress.blocked");
        assert_eq!(signals::EGRESS_BLOCKED.category(), Category::Integrity);
        assert!(signals::BAN_TABLE_FULL.severity() > 6.0);
        assert_eq!(SignalId::new(999).path(), "bouncer.unknown");
        for s in [
            signals::DOOR_REFUSED_BAN,
            signals::DOOR_REFUSED_BUDGET,
            signals::DOOR_REFUSED_REGISTRY_FULL,
            signals::DOOR_PROXY_HOP_UNRESOLVED,
            signals::REVOKE_APPLIED,
            signals::DENIAL_WIPE_EJECT,
            signals::COMMIT_BLOCKED,
            signals::CHECKPOINT_MISSING,
            signals::BAN_ADDED,
            signals::BAN_ESCALATED,
            signals::BAN_LIFTED,
            signals::BAN_EXPIRED,
            signals::BAN_EVICTED,
            signals::BAN_REFUSED_ALLOWLISTED,
            signals::STRIKE,
            signals::THRESHOLD_REACHED,
            signals::SOURCE_SHARED_SUSPECTED,
            signals::PERSIST_FAILED,
            signals::IMPORT_REJECTED,
            signals::TABLE_RESEEDED,
        ] {
            assert!(s.path().starts_with("bouncer."), "{s}");
            assert_ne!(s.path(), "bouncer.unknown", "{s}");
        }
    }

    #[test]
    fn test_evidence_cut_at_budget() {
        let long = "x".repeat(200);
        let pairs: Vec<(&'static str, EvidenceValue<'_>)> = vec![
            ("a", EvidenceValue::Text(&long)),
            ("b", EvidenceValue::Text(&long)),
        ];
        let (kept, cut) = bounded(Evidence::new(&pairs));
        assert!(cut);
        assert_eq!(kept.pairs().len(), 1);
        let (kept, cut) = bounded(Evidence::new(&pairs[..1]));
        assert!(!cut);
        assert_eq!(kept.pairs().len(), 1);
    }
}
