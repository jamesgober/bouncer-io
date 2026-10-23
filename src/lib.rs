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
//! ## What is here
//!
//! - **Keys**: [`Cidr`] (strict parsing, IPv4-mapped IPv6 normalized to IPv4),
//!   connection and request ids, and identity digests ([`SessionKey`],
//!   [`FingerprintKey`]) that compare in constant time and never print.
//! - **Ban memory**: bans by address, prefix, and identity, timed by a
//!   growing [`DurationPolicy`] with jitter, or permanent by administrators.
//!   IPv6 clients are keyed at /64. Readers never take a lock.
//! - **The door**: [`Bouncer::door`] checks trusted proxies, the
//!   [`AllowList`], and ban memory, and issues a [`Ticket`].
//! - **Tickets and checkpoints**: [`Ticket::request`],
//!   [`Ticket::checkpoint`], and [`Ticket::bind_client`] for the real client
//!   behind a trusted proxy.
//!
//! In-flight revocation, wipe-replace-eject, strikes, budgets, and events
//! arrive in 0.4; persistence, sharing across nodes, and administration in
//! 0.5. The full planned API is in `docs/API.md` in the
//! [repository](https://github.com/jamesgober/bouncer-io).

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
mod collected;
mod directive;
mod door;
mod error;
mod events;
mod format;
mod hash;
mod keys;
#[cfg(all(test, bouncer_loom))]
mod loom_models;
mod maintain;
mod metrics;
mod published;
mod registry;
mod revoke;
mod share;
mod sources;
mod strikes;
mod sync;
mod ticket;
mod time;
mod verdict;

#[cfg(feature = "metrics")]
pub use crate::metrics::MetricsSnapshot;
pub use crate::{
    admin::{
        BanRecord, BudgetState, Explanation, Filter, Health, Listing, MaintainerState,
        OffenderRecord, Page, StrikeState,
    },
    allow::{AllowKind, AllowList},
    bans::{
        BanDuration, BanId, BanSpec, DurationPolicy, LiftSpec, Lifted, escalate::EscalationPolicy,
    },
    bouncer::{Bouncer, BouncerBuilder, Capacity},
    budgets::{Budgets, Rate},
    collected::Collected,
    directive::{
        Action, Actor, ActorKind, Applied, BanKeys, Directive, Evidence, EvidenceValue, Reason,
    },
    door::{DatagramVerdict, Provenance, Refusal},
    error::{BouncerError, ConfigError, ConfigProblem},
    events::{Category, Event, EventSink, GENERATOR, NoSink, SignalId, Subject, signals},
    format::{DenialFormat, Ejected, FormatError, NoFormat},
    keys::{
        AccountKey, BanKey, Cidr, ConnId, Family, FingerprintKey, RequestId, SessionKey, TenantKey,
        normalize, prefix_of,
    },
    maintain::{CloseKind, Ejector, MaintenanceReport},
    revoke::{Revocation, RevocationEpoch, RevokeMode, Target},
    share::NodeId,
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
