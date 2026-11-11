//! # bouncer_io
//!
//! The door guy for Rust services. bouncer-io refuses banned sources at
//! accept, before a byte is read, and revokes requests that are already
//! running: it is consulted at checkpoints, never flowed through, and a
//! checkpoint costs one atomic load until something is revoked.
//!
//! ```
//! use bouncer_io::{Bouncer, RequestId, Verdict};
//!
//! let bouncer = Bouncer::new();
//!
//! // Ban an address; it is refused at the door from now on.
//! bouncer.ban("198.51.100.9".parse::<std::net::IpAddr>()?)?;
//! assert!(bouncer.door("198.51.100.9".parse()?).is_err());
//!
//! // The door: before reading a byte. A refusal means close abortively.
//! let conn = bouncer.door("203.0.113.7".parse()?)?;
//!
//! // A request on that connection, checked between pipeline stages.
//! let mut request = conn.request(RequestId(1))?;
//! assert_eq!(request.checkpoint(), Verdict::Pass);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! Banning is one line, and so is a logout that stops the session's running
//! requests. Anything more than the key (who decided, why, for how long) is a
//! [`Directive`], the message every other layer of the stack sends:
//!
//! ```
//! use bouncer_io::{Actor, Bouncer, Directive, Reason, SessionKey};
//! use std::time::Duration;
//!
//! let bouncer = Bouncer::new();
//! bouncer.ban("2001:db8:7::/48".parse::<bouncer_io::Cidr>()?)?;
//! bouncer.revoke(SessionKey::from_digest([1; 16]), Reason::LOGOUT)?;
//! bouncer.apply(
//!     Directive::ban("198.51.100.20".parse::<std::net::IpAddr>()?)
//!         .for_duration(Duration::from_secs(3600))
//!         .by(Actor::Admin(17))
//!         .because(Reason::ADMIN),
//! )?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ## What is here
//!
//! - **The door**: [`Bouncer::door`] checks trusted proxies, the
//!   [`AllowList`], ban memory, and the door budgets before a byte is read,
//!   and issues a connection [`Ticket`]. A [`Refusal`] converts into
//!   [`BouncerError`], so `?` works.
//! - **Tickets and checkpoints**: [`Ticket::request`] issues a request
//!   ticket; [`Ticket::checkpoint`], [`Ticket::before_commit`], and the
//!   identity binds return a [`Verdict`]; [`Ticket::deny_and_eject`] wipes
//!   the response collected so far in a [`Collected`], replaces it with a
//!   generic denial, and closes the connection; `Directive::revoke_and_ban`
//!   also keeps the offender out at the door.
//! - **Revocation**: [`Bouncer::revoke`] and [`Directive`] reach requests
//!   already running, by connection, request, session, account, tenant,
//!   fingerprint, or source prefix.
//! - **Ban memory**: bans by address, prefix, and identity, timed by a growing
//!   [`DurationPolicy`], escalated to prefixes ([`EscalationPolicy`]), and fed
//!   by strikes from every layer ([`StrikeRules`], [`Enforcement`]).
//! - **Budgets**: accept rate and concurrency at the door, per lane and per
//!   tenant ([`Budgets`]).
//! - **Operations**: [`Bouncer::explain`], [`Bouncer::list`],
//!   [`Bouncer::health`], security [`Event`]s, persistence
//!   ([`FilePersistence`], [`VersionAnchor`]), and sharing across nodes
//!   ([`Delta`]).
//! - **net-io** (feature `net-io`): `Bouncer` is net-io's `Gate`.
//!
//! The configuration lives on [`Bouncer::builder`]. `docs/API.md` in the
//! [repository](https://github.com/jamesgober/bouncer-io) is the full
//! reference.

#![doc(html_root_url = "https://docs.rs/bouncer-io")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod admin;
mod allow;
mod bans;
mod bouncer;
mod budgets;
mod claims;
mod codec;
mod collected;
mod directive;
mod door;
mod error;
mod events;
mod format;
mod hash;
mod keys;
mod ledger;
#[cfg(all(test, bouncer_loom))]
mod loom_models;
mod maintain;
mod metrics;
#[cfg(feature = "net-io")]
mod net_io;
mod persist;
mod published;
mod registry;
mod revoke;
mod share;
mod sources;
mod state;
mod strikes;
mod sync;
mod ticket;
mod time;
mod verdict;

#[cfg(feature = "metrics")]
pub use crate::metrics::MetricsSnapshot;
#[cfg(feature = "net-io")]
pub use crate::net_io::{ConnectionGate, EJECTED, LOCAL_PEER, NetIoEjector, REFUSED};
pub use crate::{
    admin::{
        BanRecord, BudgetState, Explanation, Filter, Health, Listing, MaintainerState,
        OffenderRecord, Page, StrikeState,
    },
    allow::{AllowKind, AllowList},
    bans::{BanDuration, BanId, DurationPolicy, Lifted, escalate::EscalationPolicy},
    bouncer::{Bouncer, BouncerBuilder, Capacity},
    budgets::{Budgets, Rate},
    collected::Collected,
    directive::{
        Action, Actor, ActorKind, Applied, BanKeys, Directive, Evidence, EvidenceValue, Reason,
    },
    door::{DatagramVerdict, Provenance, Refusal},
    error::{BouncerError, ConfigError, ConfigProblem, ImportError, PersistError},
    events::{Category, Event, EventSink, GENERATOR, NoSink, SignalId, Subject, signals},
    format::{DenialFormat, Ejected, FormatError, NoFormat},
    keys::{
        AccountKey, BanKey, Cidr, ConnectionId, Family, FingerprintKey, RequestId, SessionKey,
        TenantKey, normalize, prefix_of,
    },
    maintain::{CloseKind, Ejector, MaintenanceReport},
    persist::{
        FileAnchor, FilePersistence, LoadFailure, Persistence, SNAPSHOT_FORMAT, SNAPSHOT_MAGIC,
        StoreVersion, VersionAnchor,
    },
    revoke::{Revocation, RevocationEpoch, RevokeMode, Target},
    share::{Delta, ImportReport, NodeId, Sequence},
    sources::SharedAddresses,
    strikes::{Enforcement, IgnoredBecause, Mode, Posture, StrikeKind, StrikeOutcome, StrikeRules},
    ticket::{LaneClass, Ticket, TicketId, TicketKind, TicketTag},
    time::Now,
    verdict::{Denial, DenialCode, DenialTable, Reference, Verdict},
};

/// Crate version string, populated by Cargo at build time.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default registry capacity: tickets for connections plus in-flight requests.
pub const DEFAULT_TICKETS: u32 = 65_536;

/// Default dynamic ban table capacity, in entries.
pub const DEFAULT_BAN_CAPACITY: u32 = 1_048_576;

/// Default revocation table capacity, in entries.
pub const DEFAULT_REVOCATION_CAPACITY: u32 = 65_536;

/// Default strike counter slots.
pub const DEFAULT_STRIKE_CAPACITY: u32 = 262_144;

/// Default automatic ban lengths for IPv4.
pub const DEFAULT_IPV4_LENGTHS: &[u8] = &[32, 24];

/// Default automatic ban lengths for IPv6: never /128, one host owns its /64.
pub const DEFAULT_IPV6_LENGTHS: &[u8] = &[64, 56, 48];

/// Most bytes a denial formatter may write.
pub const MAX_DENIAL_BYTES: usize = 1024;

/// Most bytes of evidence kept per event.
pub const MAX_EVIDENCE_BYTES: usize = 256;

/// Most slots a table probe visits.
pub const MAX_PROBE: u32 = 32;

#[cfg(test)]
mod tests {
    use super::VERSION;

    #[test]
    fn version_matches_manifest() {
        assert_eq!(VERSION, env!("CARGO_PKG_VERSION"));
        assert_eq!(VERSION.split('.').count(), 3, "expected MAJOR.MINOR.PATCH");
    }
}
