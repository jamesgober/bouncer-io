//! The door: the address-only check before a byte is read.

use core::{fmt, time::Duration};
use std::net::IpAddr;

use crate::{
    allow::{self, AllowKind},
    bans::Lookup,
    bouncer::Shared,
    time::Now,
    verdict::Reference,
};

/// Why the door refused, for the caller's logs and metrics.
///
/// It is never shown to the peer: every refusal is the same abortive close
/// with nothing read and nothing written.
///
/// # Examples
///
/// ```
/// use bouncer_io::{Bouncer, Refusal};
/// let bouncer = Bouncer::new();
/// bouncer.ban("192.0.2.44".parse::<std::net::IpAddr>()?)?;
/// match bouncer.door("192.0.2.44".parse()?) {
///     Err(Refusal::Banned { reference }) => println!("refused, ban {reference}"),
///     other => panic!("{other:?}"),
/// }
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// A ban covers the address. `reference` finds it in events and
    /// `explain`. A reference of zero means a ban slot was being rewritten for
    /// longer than the bound and the door failed closed.
    Banned {
        /// The ban's reference.
        reference: Reference,
    },
    /// Over the accept rate or concurrency budget.
    OverBudget {
        /// When the budget recovers (for events; the peer sees only a close).
        retry_after: Duration,
    },
    /// No free ticket: bouncer cannot track the connection, so it refuses.
    /// Never a ban.
    RegistryFull,
    /// The strict posture refuses this source.
    Posture,
}

/// The answer of [`Bouncer::datagram`](crate::Bouncer::datagram).
///
/// # Examples
///
/// ```
/// use bouncer_io::{Bouncer, DatagramVerdict};
/// let bouncer = Bouncer::new();
/// bouncer.ban("198.51.100.20".parse::<std::net::IpAddr>()?)?;
/// let v = bouncer.datagram("198.51.100.20".parse()?, true, bouncer.now());
/// assert_eq!(v, DatagramVerdict::Drop);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[must_use]
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatagramVerdict {
    /// Process the datagram.
    Accept,
    /// Drop it silently.
    Drop,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::Banned { reference } => write!(f, "banned (reference {reference})"),
            Refusal::OverBudget { retry_after } => {
                write!(
                    f,
                    "over budget (recovers in {} ms)",
                    retry_after.as_millis()
                )
            }
            Refusal::RegistryFull => {
                f.write_str("registry full: raise `tickets` or shed load upstream")
            }
            Refusal::Posture => f.write_str("refused by the strict posture"),
        }
    }
}

impl std::error::Error for Refusal {}

/// How a source address was learned.
///
/// `ProxyProtocol` and `ForwardedHeader` are believed only from a trusted
/// proxy; `FastCgi` is an address passed by a trusted front end; `Local` is an
/// in-process or Unix-socket peer. Automation acts only on addresses whose
/// provenance is trusted.
///
/// # Examples
///
/// ```
/// use bouncer_io::{Bouncer, Provenance};
/// let bouncer = Bouncer::new();
/// let conn = bouncer.door("192.0.2.1".parse()?)?;
/// assert_eq!(conn.provenance(), Provenance::Socket);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Provenance {
    /// The TCP peer.
    #[default]
    Socket,
    /// A PROXY protocol header from a trusted proxy.
    ProxyProtocol,
    /// A forwarded header (`Forwarded`, `X-Forwarded-For`) from a trusted proxy.
    ForwardedHeader,
    /// An address passed by a trusted FastCGI front end.
    FastCgi,
    /// An in-process or Unix-socket peer.
    Local,
}

impl Provenance {
    pub(crate) const fn code(self) -> u64 {
        match self {
            Provenance::Socket => 0,
            Provenance::ProxyProtocol => 1,
            Provenance::ForwardedHeader => 2,
            Provenance::FastCgi => 3,
            Provenance::Local => 4,
        }
    }

    pub(crate) const fn from_code(code: u64) -> Provenance {
        match code {
            1 => Provenance::ProxyProtocol,
            2 => Provenance::ForwardedHeader,
            3 => Provenance::FastCgi,
            4 => Provenance::Local,
            _ => Provenance::Socket,
        }
    }

    /// `true` for the provenances that name a client behind a trusted hop.
    pub(crate) const fn is_trusted_hop(self) -> bool {
        matches!(
            self,
            Provenance::ProxyProtocol | Provenance::ForwardedHeader | Provenance::FastCgi
        )
    }
}

/// What the door decided about one address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Judgement {
    Admit {
        immune: bool,
        exempt: bool,
    },
    /// The peer is a trusted proxy: admit the hop, judge the client later.
    ProxyHop,
    Refuse(Refusal),
}

impl Shared {
    /// The door's steps for one normalized address: trusted proxy (when it is
    /// the socket peer), allow list, ban memory.
    #[inline]
    pub(crate) fn judge(&self, peer: IpAddr, provenance: Provenance, now: Now) -> Judgement {
        let mut hashes = crate::bans::AddrHashes::new(self.bans.hasher(), peer);
        self.judge_hashed(peer, provenance, now, &mut hashes)
    }

    /// As [`judge`](Self::judge), leaving the prefix hashes it computed in
    /// `hashes` for the budget step.
    #[inline]
    pub(crate) fn judge_hashed(
        &self,
        peer: IpAddr,
        provenance: Provenance,
        now: Now,
        hashes: &mut crate::bans::AddrHashes,
    ) -> Judgement {
        if !self.proxies.is_empty() && self.proxies.contains_addr(peer) {
            return if provenance == Provenance::Socket {
                Judgement::ProxyHop
            } else {
                // A trusted proxy named as the client: the adapter picked the
                // wrong hop. Fail closed.
                Judgement::Refuse(Refusal::Banned {
                    reference: Reference::new(0),
                })
            };
        }
        let allowed = self.allow.with(|set| allow::lookup(set, peer));
        if allowed == Some(AllowKind::Immune) {
            return Judgement::Admit {
                immune: true,
                exempt: true,
            };
        }
        match self.bans.lookup_hashed(hashes, now.secs()) {
            Lookup::Clear => Judgement::Admit {
                immune: false,
                exempt: allowed == Some(AllowKind::ExemptBudgets),
            },
            Lookup::Banned(id) => Judgement::Refuse(Refusal::Banned {
                reference: self.reference(id),
            }),
            Lookup::Busy => Judgement::Refuse(Refusal::Banned {
                reference: Reference::new(0),
            }),
        }
    }

    /// The stable reference of a ban.
    pub(crate) fn reference(&self, id: u64) -> Reference {
        Reference::new(self.references.hash3(id, 0, 0) | 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provenance_codes_round_trip() {
        for p in [
            Provenance::Socket,
            Provenance::ProxyProtocol,
            Provenance::ForwardedHeader,
            Provenance::FastCgi,
            Provenance::Local,
        ] {
            assert_eq!(Provenance::from_code(p.code()), p);
        }
        assert!(!Provenance::Socket.is_trusted_hop());
        assert!(!Provenance::Local.is_trusted_hop());
        assert!(Provenance::ForwardedHeader.is_trusted_hop());
    }

    #[test]
    fn test_refusal_display() {
        assert!(Refusal::RegistryFull.to_string().contains("tickets"));
        assert!(
            Refusal::OverBudget {
                retry_after: Duration::from_millis(5)
            }
            .to_string()
            .contains("5 ms")
        );
        assert!(Refusal::Posture.to_string().contains("strict"));
    }
}
