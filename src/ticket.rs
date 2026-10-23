//! Tickets: the handle every connection and request carries.

use core::fmt;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use crate::{
    door::{Judgement, Provenance, Refusal},
    error::BouncerError,
    keys::{ConnId, RequestId, normalize},
    registry::{
        CODE_SHIFT, F_CLIENT_BOUND, F_IMMUNE, F_LIVE, F_PENDING_CLIENT, F_PROXY_HOP, F_REVOKED,
        K_REQUEST, K_SOURCE, KIND_CONNECTION, KIND_REQUEST, P_REQUEST, P_SOURCE, P_SOURCE_V6,
        PRESENT_SHIFT, PROVENANCE_MASK, PROVENANCE_SHIFT, Shard, generation,
    },
    sync::{Ordering, update},
    verdict::{Denial, DenialCode, Reference, Verdict},
};

/// `seen` value of a ticket that must take the slow path at every checkpoint
/// (a request under a proxy hop with no client yet). No real epoch reaches it.
const SEEN_ALWAYS_CHECK: u64 = u64::MAX;

/// Whether a ticket stands for a connection or a request.
///
/// # Examples
///
/// ```
/// use bouncer_io::{Bouncer, RequestId, TicketKind};
/// let bouncer = Bouncer::new();
/// let conn = bouncer.door("192.0.2.1".parse()?)?;
/// assert_eq!(conn.kind(), TicketKind::Connection);
/// assert_eq!(conn.request(RequestId(1))?.kind(), TicketKind::Request);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TicketKind {
    /// A connection ticket, from the door.
    Connection,
    /// A request ticket, from a connection ticket.
    Request,
}

/// A ticket's identity for logs: shard, cell, and generation.
///
/// # Examples
///
/// ```
/// let bouncer = bouncer_io::Bouncer::new();
/// let a = bouncer.door("192.0.2.1".parse()?)?;
/// let b = bouncer.door("192.0.2.1".parse()?)?;
/// assert_ne!(a.id(), b.id());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TicketId(u64);

impl TicketId {
    /// The raw value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for TicketId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}

/// A ticket named as a plain 64-bit value (shard, cell, generation), for
/// transports that store one number per connection. A stale or unknown tag
/// never reaches a reused cell: the generation must match.
///
/// # Examples
///
/// ```
/// use bouncer_io::TicketTag;
/// let bouncer = bouncer_io::Bouncer::new();
/// let conn = bouncer.door("192.0.2.1".parse()?)?;
/// let tag = conn.tag();
/// assert_eq!(TicketTag::from_raw(tag.get()), tag);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TicketTag(u64);

impl TicketTag {
    /// The raw value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// A tag from a raw value. Any value is accepted; an unknown one is
    /// denied by every check that takes it.
    #[must_use]
    pub const fn from_raw(raw: u64) -> TicketTag {
        TicketTag(raw)
    }
}

/// The handle a connection or request carries through the pipeline.
///
/// A connection ticket comes from [`Bouncer::door`](crate::Bouncer::door); a
/// request ticket from [`Ticket::request`]. Dropping a ticket releases it;
/// dropping a connection ticket while its requests are live denies them.
///
/// # Examples
///
/// ```
/// use bouncer_io::{Bouncer, RequestId};
///
/// let bouncer = Bouncer::new();
/// let conn = bouncer.door("203.0.113.7".parse()?)?;
/// let mut request = conn.request(RequestId(1))?;
/// assert!(request.checkpoint().is_pass());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[must_use = "dropping a ticket releases it; keep it for the life of the connection or request"]
pub struct Ticket {
    shard: Arc<Shard>,
    index: u32,
    generation: u32,
    seen: u64,
    kind: TicketKind,
}

/// What a new cell starts with.
pub(crate) struct Issue {
    pub(crate) kind: TicketKind,
    pub(crate) flags: u64,
    pub(crate) conn: u64,
    pub(crate) source: Option<IpAddr>,
    pub(crate) request: Option<RequestId>,
    pub(crate) parent: Option<(u32, u32)>,
}

impl Ticket {
    /// Takes a free cell (from `first_shard`, then any other), or `None` when
    /// the registry is full.
    pub(crate) fn issue(shard: &Arc<Shard>, first_shard: usize, issue: Issue) -> Option<Ticket> {
        let index = shard.shared.registry.pop_from(first_shard)?;
        let cell = shard.cell(index);
        let gen_ = generation(cell.state.load(Ordering::Relaxed));
        cell.conn.store(issue.conn, Ordering::Relaxed);
        let mut present = 0u64;
        if let Some(src) = issue.source {
            present |= write_source(cell, src);
        }
        if let Some(r) = issue.request {
            cell.keys[K_REQUEST].store((r.0 >> 64) as u64, Ordering::Relaxed);
            cell.keys[K_REQUEST + 1].store(r.0 as u64, Ordering::Relaxed);
            present |= P_REQUEST;
        }
        let (kind_bits, link) = match (issue.kind, issue.parent) {
            (TicketKind::Request, Some((pi, pg))) => {
                (KIND_REQUEST, (u64::from(pi) << 32) | u64::from(pg))
            }
            _ => (KIND_CONNECTION, u64::from(gen_) << 32),
        };
        cell.link.store(link, Ordering::Relaxed);
        let epoch = shard.epoch.load();
        cell.born_present.store(
            (present << PRESENT_SHIFT) | (epoch & ((1u64 << PRESENT_SHIFT) - 1)),
            Ordering::Relaxed,
        );
        let seen = if issue.flags & F_PENDING_CLIENT != 0 {
            SEEN_ALWAYS_CHECK
        } else {
            epoch
        };
        cell.seen.store(seen, Ordering::Relaxed);
        cell.state.store(
            (u64::from(gen_) << 32) | issue.flags | F_LIVE | kind_bits,
            Ordering::Release,
        );
        Some(Ticket {
            shard: Arc::clone(shard),
            index,
            generation: gen_,
            seen,
            kind: issue.kind,
        })
    }

    #[inline]
    fn cell(&self) -> &crate::registry::Cell {
        self.shard.cell(self.index)
    }

    /// The ticket's identity, for logs.
    #[must_use]
    pub fn id(&self) -> TicketId {
        TicketId(self.raw_id())
    }

    fn raw_id(&self) -> u64 {
        (u64::from(self.index) << 32) | u64::from(self.generation)
    }

    /// Connection or request.
    #[must_use]
    pub fn kind(&self) -> TicketKind {
        self.kind
    }

    /// The connection id (a request ticket carries its connection's).
    #[must_use]
    pub fn conn(&self) -> ConnId {
        ConnId(self.cell().conn.load(Ordering::Relaxed))
    }

    /// The source address; `None` on a trusted proxy hop until the real
    /// client is bound.
    #[must_use]
    pub fn source(&self) -> Option<IpAddr> {
        let cell = self.cell();
        let present = cell.present();
        if present & P_SOURCE == 0 {
            return None;
        }
        let hi = cell.keys[K_SOURCE].load(Ordering::Relaxed);
        let lo = cell.keys[K_SOURCE + 1].load(Ordering::Relaxed);
        Some(if present & P_SOURCE_V6 != 0 {
            IpAddr::V6(Ipv6Addr::from((u128::from(hi) << 64) | u128::from(lo)))
        } else {
            IpAddr::V4(Ipv4Addr::from(lo as u32))
        })
    }

    /// How the source address was learned.
    #[must_use]
    pub fn provenance(&self) -> Provenance {
        let st = self.cell().state.load(Ordering::Acquire);
        Provenance::from_code((st & PROVENANCE_MASK) >> PROVENANCE_SHIFT)
    }

    /// The tag naming this ticket as a number, without giving it up.
    #[must_use]
    pub fn tag(&self) -> TicketTag {
        TicketTag(self.raw_id())
    }

    /// Issues a request ticket under this connection ticket. Takes `&self`,
    /// so multiplexed protocols can open several requests at once.
    ///
    /// # Errors
    ///
    /// [`BouncerError::NotAConnectionTicket`] on a request ticket;
    /// [`BouncerError::Revoked`] when the connection is revoked;
    /// [`BouncerError::RegistryFull`] when no ticket is free (answer the
    /// request as unavailable).
    ///
    /// # Examples
    ///
    /// ```
    /// let bouncer = bouncer_io::Bouncer::new();
    /// let conn = bouncer.door("192.0.2.30".parse()?)?;
    /// let first = conn.request(bouncer_io::RequestId(1))?;
    /// let second = conn.request(bouncer_io::RequestId(2))?;   // both live at once
    /// assert!(first.request(bouncer_io::RequestId(3)).is_err());
    /// # drop((first, second));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn request(&self, id: RequestId) -> Result<Ticket, BouncerError> {
        if self.kind != TicketKind::Connection {
            return Err(BouncerError::NotAConnectionTicket);
        }
        let parent = self.cell();
        let st = parent.state.load(Ordering::Acquire);
        if generation(st) != self.generation || st & F_LIVE == 0 || st & F_REVOKED != 0 {
            return Err(BouncerError::Revoked);
        }
        let inherited = st & (F_IMMUNE | PROVENANCE_MASK);
        let (flags, source) = if st & F_PROXY_HOP != 0 && st & F_CLIENT_BOUND == 0 {
            (F_PENDING_CLIENT | inherited, None)
        } else {
            (inherited, self.source())
        };
        // Count the child before it exists, so a concurrent release of the
        // parent cannot miss it. The parent is borrowed, so it is live.
        let counted = update(&parent.link, Ordering::AcqRel, Ordering::Acquire, |link| {
            (generation(link) == self.generation).then(|| link.wrapping_add(1))
        })
        .is_ok();
        if !counted {
            return Err(BouncerError::Revoked);
        }
        let first = self.shard.shared.registry.shard_of(self.index);
        let issued = Ticket::issue(
            &self.shard,
            first,
            Issue {
                kind: TicketKind::Request,
                flags,
                conn: parent.conn.load(Ordering::Relaxed),
                source,
                request: Some(id),
                parent: Some((self.index, self.generation)),
            },
        );
        match issued {
            Some(t) => Ok(t),
            None => {
                uncount_child(&self.shard.shared.registry, self.index, self.generation);
                Err(BouncerError::RegistryFull {
                    capacity: self.shard.shared.tickets_capacity,
                })
            }
        }
    }

    /// Checkpoints B4 and B6a: between pipeline stages and before encoding
    /// the response.
    ///
    /// One atomic load and one compare while nothing has been revoked. After
    /// a revocation anywhere, it checks the ticket's own state and its
    /// connection's; a released or reused cell is denied (fail closed).
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::{Bouncer, RequestId, Verdict};
    /// let bouncer = Bouncer::new();
    /// let conn = bouncer.door("192.0.2.31".parse()?)?;
    /// let mut request = conn.request(RequestId(1))?;
    /// for _stage in ["route", "load", "render"] {
    ///     if let Verdict::Deny(_) = request.checkpoint() {
    ///         break;
    ///     }
    /// }
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[inline]
    pub fn checkpoint(&mut self) -> Verdict {
        let now = self.shard.epoch.load();
        if now == self.seen {
            return Verdict::Pass;
        }
        self.slow_path(now)
    }

    #[cold]
    #[inline(never)]
    fn slow_path(&mut self, now: u64) -> Verdict {
        let cell = self.cell();
        let st = cell.state.load(Ordering::Acquire);
        if generation(st) != self.generation || st & F_LIVE == 0 {
            return self.deny(DenialCode::Unavailable);
        }
        if st & F_REVOKED != 0 {
            return self.deny(code_of(st));
        }
        if st & F_PENDING_CLIENT != 0 {
            return self.deny(DenialCode::Unavailable);
        }
        if self.kind == TicketKind::Request {
            let link = cell.link.load(Ordering::Relaxed);
            let (pi, pg) = ((link >> 32) as u32, link as u32);
            let pst = self.shard.cell(pi).state.load(Ordering::Acquire);
            if generation(pst) != pg || pst & F_LIVE == 0 {
                // The connection is gone: a request cannot outlive it.
                self.mark_revoked(DenialCode::Unavailable);
                self.seen = SEEN_ALWAYS_CHECK;
                return self.deny(DenialCode::Unavailable);
            }
            if pst & F_REVOKED != 0 {
                let code = code_of(pst);
                self.mark_revoked(code);
                self.seen = SEEN_ALWAYS_CHECK;
                return self.deny(code);
            }
        }
        cell.seen.store(now, Ordering::Release);
        self.seen = now;
        Verdict::Pass
    }

    fn deny(&self, code: DenialCode) -> Verdict {
        let r = self
            .shard
            .shared
            .references
            .hash3(self.raw_id(), u64::from(code.number()), 1);
        Verdict::Deny(Denial::new(code, Reference::new(r | 1)))
    }

    /// Sets the revoked flag and denial code on this ticket's cell. The
    /// stronger code is kept when it is already revoked.
    fn mark_revoked(&self, code: DenialCode) {
        let cell = self.cell();
        let _ = update(&cell.state, Ordering::AcqRel, Ordering::Acquire, |st| {
            if generation(st) != self.generation {
                return None;
            }
            let keep = if st & F_REVOKED != 0 {
                code_of(st).max(code)
            } else {
                code
            };
            Some(
                (st & !(0xff << CODE_SHIFT)) | F_REVOKED | (u64::from(keep.number()) << CODE_SHIFT),
            )
        });
    }

    /// Checkpoint B1': sets the real client learned from a trusted proxy and
    /// runs the door's allow and ban steps on it.
    ///
    /// With the PROXY protocol, the transport calls it on the connection
    /// ticket; with forwarded headers, the protocol adapter calls it on each
    /// request ticket (a proxy may carry many clients over one connection).
    /// Until a client is bound, a request under a proxy hop is denied at
    /// every checkpoint. Binding is allowed once, only from a trusted
    /// provenance, and only on a proxy hop; anything else is a `Deny` with
    /// `DenialCode::Unavailable`.
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::{Bouncer, Cidr, Provenance, RequestId};
    ///
    /// let bouncer = Bouncer::builder().trusted_proxies(&["10.0.0.0/8".parse::<Cidr>()?]).try_build()?;
    /// let hop = bouncer.door("10.1.2.3".parse()?)?;          // our load balancer
    /// assert_eq!(hop.source(), None);
    /// let mut request = hop.request(RequestId(1))?;
    /// assert!(request.checkpoint().is_deny());                // no client yet
    /// assert!(request.bind_client("198.51.100.4".parse()?, Provenance::ForwardedHeader).is_pass());
    /// assert_eq!(request.source(), Some("198.51.100.4".parse()?));
    /// assert!(request.checkpoint().is_pass());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn bind_client(&mut self, addr: IpAddr, provenance: Provenance) -> Verdict {
        if !provenance.is_trusted_hop() {
            return self.deny(DenialCode::Unavailable);
        }
        let cell = self.cell();
        let st = cell.state.load(Ordering::Acquire);
        if generation(st) != self.generation || st & F_LIVE == 0 || st & F_REVOKED != 0 {
            return self.deny(DenialCode::Unavailable);
        }
        let eligible = st & F_CLIENT_BOUND == 0
            && match self.kind {
                TicketKind::Connection => st & F_PROXY_HOP != 0,
                TicketKind::Request => st & F_PENDING_CLIENT != 0,
            };
        if !eligible {
            return self.deny(DenialCode::Unavailable);
        }
        let addr = normalize(addr);
        let shared = &self.shard.shared;
        let immune = match shared.judge(addr, provenance, shared.now()) {
            Judgement::Admit { immune } => immune,
            Judgement::ProxyHop => return self.deny(DenialCode::Unavailable),
            Judgement::Refuse(Refusal::Banned { .. }) => {
                self.mark_revoked(DenialCode::Forbidden);
                // The epoch did not move, so this ticket checks itself from now on.
                self.seen = SEEN_ALWAYS_CHECK;
                return self.deny(DenialCode::Forbidden);
            }
            Judgement::Refuse(_) => return self.deny(DenialCode::Unavailable),
        };
        let present = write_source(cell, addr);
        cell.born_present
            .fetch_or(present << PRESENT_SHIFT, Ordering::AcqRel);
        let generation_now = self.generation;
        let updated = update(&cell.state, Ordering::AcqRel, Ordering::Acquire, |st| {
            if generation(st) != generation_now || st & F_CLIENT_BOUND != 0 {
                return None;
            }
            let mut next = (st & !(F_PENDING_CLIENT | PROVENANCE_MASK)) | F_CLIENT_BOUND;
            next |= provenance.code() << PROVENANCE_SHIFT;
            if immune {
                next |= F_IMMUNE;
            }
            Some(next)
        });
        if updated.is_err() {
            return self.deny(DenialCode::Unavailable);
        }
        let now = self.shard.epoch.load();
        cell.seen.store(now, Ordering::Release);
        self.seen = now;
        Verdict::Pass
    }
}

/// Writes the source key words; returns the present bits for them.
fn write_source(cell: &crate::registry::Cell, src: IpAddr) -> u64 {
    match normalize(src) {
        IpAddr::V4(v4) => {
            cell.keys[K_SOURCE].store(0, Ordering::Relaxed);
            cell.keys[K_SOURCE + 1].store(u64::from(u32::from(v4)), Ordering::Relaxed);
            P_SOURCE
        }
        IpAddr::V6(v6) => {
            let bits = u128::from(v6);
            cell.keys[K_SOURCE].store((bits >> 64) as u64, Ordering::Relaxed);
            cell.keys[K_SOURCE + 1].store(bits as u64, Ordering::Relaxed);
            P_SOURCE | P_SOURCE_V6
        }
    }
}

fn code_of(state: u64) -> DenialCode {
    DenialCode::from_number((state >> CODE_SHIFT) as u8)
}

/// Takes one live-request count from a connection cell, if it is still the
/// same generation.
fn uncount_child(registry: &crate::registry::Registry, parent: u32, parent_gen: u32) {
    let _ = update(
        &registry.cell(parent).link,
        Ordering::AcqRel,
        Ordering::Acquire,
        |link| (generation(link) == parent_gen && link as u32 > 0).then(|| link - 1),
    );
}

impl Drop for Ticket {
    fn drop(&mut self) {
        let shard = &self.shard;
        let cell = shard.cell(self.index);
        let next_gen = self.generation.wrapping_add(1);
        let retire = next_gen == u32::MAX || next_gen == 0;
        cell.born_present.store(0, Ordering::Relaxed);
        // The new generation goes out first, so a request that sees the epoch
        // move below also sees its connection is gone.
        cell.state
            .store(u64::from(next_gen) << 32, Ordering::Release);
        match self.kind {
            TicketKind::Connection => {
                let old = cell.link.swap(u64::from(next_gen) << 32, Ordering::AcqRel);
                if generation(old) == self.generation && old as u32 > 0 {
                    shard.epoch.bump();
                }
            }
            TicketKind::Request => {
                let link = cell.link.load(Ordering::Relaxed);
                uncount_child(&shard.shared.registry, (link >> 32) as u32, link as u32);
            }
        }
        if !retire {
            shard.shared.registry.push(self.index);
        }
    }
}

impl fmt::Debug for Ticket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ticket")
            .field("id", &self.id())
            .field("kind", &self.kind)
            .field("conn", &self.conn())
            .finish_non_exhaustive()
    }
}

#[cfg(all(test, not(bouncer_loom)))]
impl Ticket {
    /// Forces this ticket's cell to the last generation, for the retire test.
    pub(crate) fn force_generation(&mut self, gen_: u32) {
        let cell = self.cell();
        let st = cell.state.load(Ordering::Relaxed);
        cell.state.store(
            (st & 0xffff_ffff) | (u64::from(gen_) << 32),
            Ordering::Relaxed,
        );
        if self.kind == TicketKind::Connection {
            cell.link.store(u64::from(gen_) << 32, Ordering::Relaxed);
        }
        self.generation = gen_;
    }

    pub(crate) fn index(&self) -> u32 {
        self.index
    }
}

#[cfg(all(test, not(bouncer_loom)))]
mod tests {
    use super::*;
    use crate::Bouncer;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn test_ticket_stale_generation_denied() {
        // Threat T-10, edge case 25: a handle whose cell was released and
        // reissued is denied, never mistaken for the new ticket.
        let b = Bouncer::builder().tickets(1).try_build().unwrap();
        let first = b.door(ip("192.0.2.1")).unwrap();
        let (shard, index, old_gen) = (Arc::clone(&first.shard), first.index, first.generation);
        drop(first);
        let second = b.door(ip("192.0.2.2")).unwrap();
        assert_eq!(second.index, index, "the only cell is reused");
        assert_ne!(second.generation, old_gen);
        let mut stale = Ticket {
            shard,
            index,
            generation: old_gen,
            seen: SEEN_ALWAYS_CHECK,
            kind: TicketKind::Connection,
        };
        assert!(
            matches!(stale.checkpoint(), Verdict::Deny(d) if d.code == DenialCode::Unavailable)
        );
        assert!(stale.request(RequestId(1)).is_err());
        assert!(
            stale
                .bind_client(ip("192.0.2.3"), Provenance::ProxyProtocol)
                .is_deny()
        );
        // The stale handle must not release the live cell.
        std::mem::forget(stale);
        let mut live = second;
        assert!(live.checkpoint().is_pass());
    }

    #[test]
    fn test_ticket_generation_at_max_retires_cell() {
        // Edge case 26.
        let b = Bouncer::builder().tickets(1).try_build().unwrap();
        let mut t = b.door(ip("192.0.2.1")).unwrap();
        t.force_generation(u32::MAX - 1);
        drop(t);
        assert_eq!(b.door(ip("192.0.2.1")).err(), Some(Refusal::RegistryFull));
    }

    #[test]
    fn test_ticket_accessors_and_ids() {
        let b = Bouncer::new();
        let conn = b.door(ip("2001:db8::7")).unwrap();
        assert_eq!(conn.source(), Some(ip("2001:db8::7")));
        assert_eq!(conn.provenance(), Provenance::Socket);
        assert_eq!(conn.kind(), TicketKind::Connection);
        assert_eq!(conn.tag().get(), conn.id().get());
        assert!(conn.id().to_string().len() == 16);
        let r = conn.request(RequestId(5)).unwrap();
        assert_eq!(r.conn(), conn.conn());
        assert_eq!(r.source(), conn.source());
        assert_ne!(r.index(), conn.index());
    }
}
