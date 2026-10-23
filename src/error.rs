//! Errors. Every message says what to do, and none prints key bytes.

use core::fmt;

use crate::keys::{BanKey, Family};

/// Everything that can go wrong in bouncer-io.
///
/// Refusals at the door are not errors: [`Bouncer::door`](crate::Bouncer::door)
/// returns a [`Refusal`](crate::Refusal) for those.
///
/// # Examples
///
/// ```
/// use bouncer_io::{BouncerError, Cidr};
///
/// let err = Cidr::parse("10.0.0.0/33").unwrap_err();
/// assert!(matches!(err, BouncerError::InvalidPrefix { len: 33, .. }));
/// println!("{err}");
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BouncerError {
    /// No free ticket. Answer the request as unavailable; raise
    /// `BouncerBuilder::tickets` or shed load upstream.
    RegistryFull {
        /// The configured ticket capacity.
        capacity: u32,
    },
    /// The ban table holds only entries that are never evicted. Raise
    /// `BouncerBuilder::ban_capacity`.
    BanTableFull {
        /// The configured ban capacity.
        capacity: u32,
    },
    /// A prefix length out of range for its family, host bits set where they
    /// are refused, or a prefix too wide for an automated actor.
    InvalidPrefix {
        /// The length given.
        len: u8,
        /// The address family.
        family: Family,
        /// `true` when the address had bits set below the prefix length.
        host_bits_set: bool,
    },
    /// Prefix text that could not be parsed.
    ParseCidr {
        /// Byte offset of the first character that could not be accepted.
        position: u8,
    },
    /// The key is covered by an immune allow-list entry. Remove the allow
    /// entry first.
    AllowListed {
        /// The refused key.
        key: BanKey,
    },
    /// The key is a trusted proxy. Ban the real client address instead.
    TrustedProxyTarget,
    /// Only administrators, the application, sentinel, and definitive
    /// signals may ban permanently. Use a timed ban.
    PermanentNotAllowed,
    /// A ban duration of zero. Use a duration above zero.
    InvalidDuration,
    /// Nothing was banned under exactly this key. A wider prefix ban may
    /// still cover it.
    NotFound,
    /// Request tickets can only be issued from a connection ticket.
    NotAConnectionTicket,
    /// The action does not fit the target: an automated actor banning a bare
    /// fingerprint (use a fingerprint within a prefix), for example.
    InvalidTarget,
    /// The connection is revoked. Deny and eject the request.
    Revoked,
    /// The tag names a ticket that was released, or another bouncer's.
    /// Treat the connection as closed.
    Stale,
    /// The revocation table is full. The revocation still reached every live
    /// matching ticket through a direct sweep; check that maintenance runs
    /// and raise `revocation_capacity`.
    RevocationTableFull {
        /// The configured revocation capacity.
        capacity: u32,
    },
    /// The operating system refused to start the maintainer thread. Call
    /// `Bouncer::maintain` yourself instead.
    Spawn(std::io::ErrorKind),
    /// A `Collected` buffer would pass its limit. Raise the limit, or stream
    /// the response.
    CollectedFull {
        /// The buffer's limit.
        capacity: usize,
        /// The size the write needed.
        needed: usize,
    },
    /// `Collected::commit` claimed more bytes than `spare` gave.
    InvalidCommit,
    /// A configuration value out of range.
    Config(ConfigError),
}

impl fmt::Display for BouncerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RegistryFull { capacity } => write!(
                f,
                "no free ticket ({capacity} in use): answer as unavailable, raise `tickets`, or shed load upstream"
            ),
            Self::BanTableFull { capacity } => write!(
                f,
                "ban table full ({capacity} entries, none evictable): raise `ban_capacity`"
            ),
            Self::InvalidPrefix {
                len,
                family,
                host_bits_set,
            } => {
                if *host_bits_set {
                    write!(
                        f,
                        "prefix /{len} has host bits set: clear them or use `Cidr::parse`"
                    )
                } else {
                    write!(
                        f,
                        "prefix length /{len} is not allowed here for {family}: use 0 to {} (automation is limited to the configured lengths)",
                        family.max_len()
                    )
                }
            }
            Self::ParseCidr { position } => {
                write!(f, "invalid address or prefix text at byte {position}")
            }
            Self::AllowListed { key } => {
                write!(
                    f,
                    "{key} is allow-listed: remove the allow entry before banning it"
                )
            }
            Self::TrustedProxyTarget => {
                write!(
                    f,
                    "the target is a trusted proxy: act on the real client address instead"
                )
            }
            Self::PermanentNotAllowed => write!(
                f,
                "this actor may not ban permanently: use a timed ban, or act as an administrator"
            ),
            Self::InvalidDuration => write!(f, "a ban duration must be above zero"),
            Self::NotFound => write!(
                f,
                "nothing is banned under exactly this key (a wider prefix ban may still cover it; see `explain`)"
            ),
            Self::NotAConnectionTicket => {
                write!(f, "request tickets are issued from the connection ticket")
            }
            Self::InvalidTarget => write!(
                f,
                "the action does not fit this target (automation bans a fingerprint only within a prefix)"
            ),
            Self::Revoked => write!(f, "the connection is revoked: deny and eject the request"),
            Self::Stale => write!(f, "the ticket was released: treat the connection as closed"),
            Self::RevocationTableFull { capacity } => write!(
                f,
                "revocation table full ({capacity} entries): the revocation still reached live tickets; check maintenance runs and raise `revocation_capacity`"
            ),
            Self::CollectedFull { capacity, needed } => write!(
                f,
                "response buffer full ({needed} bytes needed, limit {capacity}): raise the limit or stream the response"
            ),
            Self::InvalidCommit => write!(f, "commit at most what `spare` gave"),
            Self::Spawn(kind) => write!(
                f,
                "could not start the maintainer thread ({kind:?}): call `maintain` yourself"
            ),
            Self::Config(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for BouncerError {}

impl From<ConfigError> for BouncerError {
    fn from(err: ConfigError) -> Self {
        Self::Config(err)
    }
}

/// A configuration value out of range: names the field and what it accepts.
///
/// # Examples
///
/// ```
/// use bouncer_io::{Bouncer, BouncerError, ConfigProblem};
///
/// let err = Bouncer::builder().tickets(0).try_build().unwrap_err();
/// match err {
///     BouncerError::Config(e) => {
///         assert_eq!(e.field, "tickets");
///         assert!(matches!(e.problem, ConfigProblem::TooSmall { min: 1 }));
///     }
///     other => panic!("{other}"),
/// }
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigError {
    /// The builder setter the value came from.
    pub field: &'static str,
    /// What is wrong with it.
    pub problem: ConfigProblem,
}

impl ConfigError {
    pub(crate) const fn new(field: &'static str, problem: ConfigProblem) -> Self {
        Self { field, problem }
    }
}

/// The kind of configuration problem.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigProblem {
    /// Below the smallest accepted value.
    TooSmall {
        /// The smallest accepted value.
        min: u64,
    },
    /// Above the largest accepted value.
    TooLarge {
        /// The largest accepted value.
        max: u64,
    },
    /// A prefix length list that is empty, out of range, or missing the host
    /// length (32) for IPv4.
    InvalidLength,
    /// IPv6 /128 as an automatic length: one host controls its whole /64.
    HostBansForbidden,
    /// A duration of zero, or a maximum below the base.
    InvalidDuration,
    /// A growth factor of zero.
    InvalidFactor,
    /// More allow-list entries than the limit.
    AllowListTooLarge,
    /// A denial message longer than 256 bytes.
    MessageTooLong,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let field = self.field;
        match self.problem {
            ConfigProblem::TooSmall { min } => write!(f, "`{field}` must be at least {min}"),
            ConfigProblem::TooLarge { max } => write!(f, "`{field}` must be at most {max}"),
            ConfigProblem::InvalidLength => write!(
                f,
                "`{field}` needs one or more lengths within the family's range (IPv4 must include 32)"
            ),
            ConfigProblem::HostBansForbidden => write!(
                f,
                "`{field}` may not include /128: one IPv6 host controls its whole /64, so automation keys at /64"
            ),
            ConfigProblem::InvalidDuration => write!(
                f,
                "`{field}` needs durations above zero and a maximum at or above the base"
            ),
            ConfigProblem::InvalidFactor => write!(f, "`{field}` needs a factor of at least 1"),
            ConfigProblem::MessageTooLong => {
                write!(f, "`{field}` has a message longer than 256 bytes")
            }
            ConfigProblem::AllowListTooLarge => write!(
                f,
                "`{field}` has more than {} entries",
                crate::allow::MAX_ALLOW_ENTRIES
            ),
        }
    }
}

impl std::error::Error for ConfigError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display_says_what_to_do() {
        let msgs = [
            BouncerError::RegistryFull { capacity: 4 }.to_string(),
            BouncerError::BanTableFull { capacity: 4 }.to_string(),
            BouncerError::TrustedProxyTarget.to_string(),
            BouncerError::PermanentNotAllowed.to_string(),
            BouncerError::NotFound.to_string(),
        ];
        assert!(msgs[0].contains("raise `tickets`"));
        assert!(msgs[1].contains("raise `ban_capacity`"));
        assert!(msgs[2].contains("real client"));
        assert!(msgs[3].contains("timed ban"));
        assert!(msgs[4].contains("explain"));
    }

    #[test]
    fn test_config_error_names_field() {
        let e = ConfigError::new("shards", ConfigProblem::TooLarge { max: 256 });
        assert_eq!(e.to_string(), "`shards` must be at most 256");
        let b: BouncerError = e.into();
        assert_eq!(b, BouncerError::Config(e));
    }

    #[test]
    fn test_invalid_prefix_display_host_bits() {
        let e = BouncerError::InvalidPrefix {
            len: 24,
            family: Family::V4,
            host_bits_set: true,
        };
        assert!(e.to_string().contains("host bits"));
        let e = BouncerError::InvalidPrefix {
            len: 33,
            family: Family::V4,
            host_bits_set: false,
        };
        assert!(e.to_string().contains("0 to 32"));
    }
}
