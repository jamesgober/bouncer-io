//! Tickets: the handle every connection and request carries.
//!
//! The work on a cell (issue, check, bind, release) lives in free functions
//! so a [`Ticket`] handle, a [`TicketTag`] held by a transport, and the
//! maintainer checking idle tickets all run the same code.

use core::fmt;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use crate::{
    bans::table::{self, Probe, TableKey},
    bouncer::Shared,
    budgets::{IdentityKey, IdentityKind},
    collected::Collected,
    door::{Judgement, Provenance, Refusal},
    error::BouncerError,
    events::{self, Subject},
    format::{DenialFormat, Ejected},
    keys::{AccountKey, ConnId, FingerprintKey, RequestId, SessionKey, TenantKey, normalize},
    maintain::CloseKind,
    metrics::meter,
    registry::{
        CHILD_MASK, CODE_SHIFT, Cell, F_CANCELLED, F_CHARGED, F_CLIENT_BOUND, F_DETACHED, F_IMMUNE,
        F_KEEP_CONNECTION, F_LIVE, F_PENDING_CLIENT, F_PROXY_HOP, F_REVOKED, F_TENANT_CHARGED,
        K_ACCOUNT, K_FINGERPRINT, K_LATEST, K_REQUEST, K_SESSION, K_SOURCE, K_TENANT,
        KIND_CONNECTION, KIND_REQUEST, NIL, P_ACCOUNT, P_FINGERPRINT, P_REQUEST, P_SESSION,
        P_SOURCE, P_SOURCE_V6, P_TENANT, PRESENT_SHIFT, PROVENANCE_MASK, PROVENANCE_SHIFT, Shard,
        generation,
    },
    sync::{Ordering, fence, update},
    verdict::{Denial, DenialCode, Reference, Verdict},
};

/// `seen` value of a ticket that must take the slow path at every checkpoint
/// (a request under a proxy hop with no client yet, or a ticket that revoked
/// itself). No real epoch reaches it.
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

impl TicketKind {
    fn from_state(st: u64) -> TicketKind {
        if st & 0xff == KIND_REQUEST {
            TicketKind::Request
        } else {
            TicketKind::Connection
        }
    }
}

/// The lane a request is charged against: mirrors the gateway's lanes.
///
/// # Examples
///
/// ```
/// use bouncer_io::{Bouncer, Budgets, LaneClass, Rate, RequestId};
/// let bouncer = Bouncer::builder()
///     .budgets(Budgets::off().lane_rate(LaneClass::Auth, Rate::per_minute(2)))
///     .try_build()?;
/// let conn = bouncer.door("192.0.2.1".parse()?)?;
/// for id in 0..2 {
///     assert!(conn.request(RequestId(id))?.bind_lane(LaneClass::Auth).is_pass());
/// }
/// assert!(conn.request(RequestId(2))?.bind_lane(LaneClass::Auth).is_deny());   // 429
/// assert!(conn.request(RequestId(3))?.bind_lane(LaneClass::Normal).is_pass()); // no budget on that lane
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LaneClass {
    /// Health checks and other traffic that must always get through.
    Critical,
    /// Administration.
    Admin,
    /// Logins, token refresh, password resets.
    Auth,
    /// Writes.
    Write,
    /// Ordinary reads.
    Normal,
    /// Exports, reports, bulk jobs.
    Bulk,
}

impl LaneClass {
    pub(crate) const COUNT: usize = 6;

    pub(crate) const fn index(self) -> usize {
        match self {
            LaneClass::Critical => 0,
            LaneClass::Admin => 1,
            LaneClass::Auth => 2,
            LaneClass::Write => 3,
            LaneClass::Normal => 4,
            LaneClass::Bulk => 5,
        }
    }
}

/// A ticket's identity for logs: cell index and generation.
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

/// A ticket named as a plain 64-bit value (cell index and generation), for
/// transports that store one number per connection. A stale or unknown tag
/// never reaches a reused cell: the generation must match.
///
/// # Examples
///
/// ```
/// use bouncer_io::{Bouncer, RequestId};
/// let bouncer = Bouncer::new();
/// let tag = bouncer.door("192.0.2.8".parse()?)?.into_tag();   // the transport keeps only this u64
/// let request = bouncer.request(tag, RequestId(9))?;
/// assert!(bouncer.egress(tag).is_pass());
/// drop(request);
/// assert!(bouncer.release(tag));
/// assert!(!bouncer.release(tag));
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

    pub(crate) const fn new(index: u32, generation: u32) -> TicketTag {
        TicketTag(((index as u64) << 32) | generation as u64)
    }

    pub(crate) const fn index(self) -> u32 {
        (self.0 >> 32) as u32
    }

    pub(crate) const fn generation(self) -> u32 {
        self.0 as u32
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
/// use bouncer_io::{Bouncer, Reason, RequestId};
///
/// let bouncer = Bouncer::new();
/// let conn = bouncer.door("203.0.113.7".parse()?)?;
/// let mut request = conn.request(RequestId(1))?;
/// assert!(request.checkpoint().is_pass());
/// bouncer.revoke(conn.conn(), Reason::ADMIN)?;
/// assert!(request.checkpoint().is_deny());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[must_use = "dropping a ticket releases it; keep it for the life of the connection or request"]
pub struct Ticket {
    shard: Arc<Shard>,
    index: u32,
    generation: u32,
    seen: u64,
    kind: TicketKind,
    detached: bool,
    /// Fast checkpoints not yet added to the shard's counter.
    #[cfg(feature = "metrics")]
    fast: u32,
}

/// What the shared half of a bind found.
enum Bound {
    /// Stale, or the kind is already bound.
    Invalid,
    /// Banned or revoked: the cell is revoked with this code.
    Refused(DenialCode),
    /// Bound; the checkpoint decides.
    Written,
}

/// What a new cell starts with.
pub(crate) struct Issue {
    pub(crate) kind: TicketKind,
    pub(crate) flags: u64,
    /// The connection id; `None` lets the cell's index and generation make
    /// one (unique without a shared counter).
    pub(crate) conn: Option<u64>,
    pub(crate) source: Option<IpAddr>,
    pub(crate) request: Option<RequestId>,
    pub(crate) parent: Option<(u32, u32)>,
}

impl Ticket {
    /// Takes a free cell (from `first_shard`, then any other), or `None` when
    /// the registry is full.
    pub(crate) fn issue(shard: &Arc<Shard>, first_shard: usize, issue: Issue) -> Option<Ticket> {
        let shared = &shard.shared;
        let index = shared.registry.pop_from(first_shard)?;
        let cell = shared.registry.cell(index);
        let gen_ = generation(cell.state.load(Ordering::Relaxed));
        let conn = issue
            .conn
            .unwrap_or((1u64 << 63) | (u64::from(gen_) << 24) | u64::from(index));
        cell.conn.store(conn, Ordering::Relaxed);
        let mut present = 0u64;
        if let Some(src) = issue.source {
            present |= write_source(cell, src);
        }
        match issue.request {
            Some(r) => {
                cell.keys[K_REQUEST].store((r.0 >> 64) as u64, Ordering::Relaxed);
                cell.keys[K_REQUEST + 1].store(r.0 as u64, Ordering::Relaxed);
                present |= P_REQUEST;
            }
            None => cell.keys[K_LATEST].store(u64::from(NIL), Ordering::Relaxed),
        }
        let (kind_bits, link) = match (issue.kind, issue.parent) {
            (TicketKind::Request, Some((pi, pg))) => {
                (KIND_REQUEST, (u64::from(pi) << 32) | u64::from(pg))
            }
            _ => (KIND_CONNECTION, u64::from(gen_) << 32),
        };
        cell.link.store(link, Ordering::Relaxed);
        cell.present_child
            .store((present << PRESENT_SHIFT) | CHILD_MASK, Ordering::Relaxed);
        let epoch = shard.epoch.load();
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
        let mut t = Ticket {
            shard: Arc::clone(shard),
            index,
            generation: gen_,
            seen,
            kind: issue.kind,
            detached: false,
            #[cfg(feature = "metrics")]
            fast: 0,
        };
        // A revocation that landed while the cell was being filled is caught
        // here rather than at the next epoch move.
        if !shared.revocations.is_empty() && seen != SEEN_ALWAYS_CHECK {
            fence(Ordering::SeqCst);
            if check_cell(shared, index, gen_, shard.epoch.load()).is_err() {
                t.seen = SEEN_ALWAYS_CHECK;
            }
        }
        Some(t)
    }

    #[inline]
    fn cell(&self) -> &Cell {
        self.shard.cell(self.index)
    }

    #[inline]
    fn shared(&self) -> &Shared {
        &self.shard.shared
    }

    /// The ticket's identity, for logs.
    #[must_use]
    pub fn id(&self) -> TicketId {
        TicketId(self.tag().0)
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
        source_of(self.cell())
    }

    /// How the source address was learned.
    #[must_use]
    pub fn provenance(&self) -> Provenance {
        let st = self.cell().state.load(Ordering::Acquire);
        Provenance::from_code((st & PROVENANCE_MASK) >> PROVENANCE_SHIFT)
    }

    /// The tag naming this ticket as a number, without giving it up. A
    /// protocol engine passes a request's tag to the transport so the egress
    /// check judges exactly that request.
    #[must_use]
    pub fn tag(&self) -> TicketTag {
        TicketTag::new(self.index, self.generation)
    }

    /// Gives up the handle and keeps the connection ticket live under its
    /// tag, for transports that store one number per connection. Release it
    /// with [`Bouncer::release`](crate::Bouncer::release) when the connection
    /// closes.
    ///
    /// # Examples
    ///
    /// ```
    /// let bouncer = bouncer_io::Bouncer::new();
    /// let tag = bouncer.door("192.0.2.12".parse()?)?.into_tag();
    /// assert!(bouncer.release(tag));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn into_tag(mut self) -> TicketTag {
        let tag = self.tag();
        let generation_now = self.generation;
        let detached = update(
            &self.cell().state,
            Ordering::AcqRel,
            Ordering::Acquire,
            |st| (generation(st) == generation_now && st & F_LIVE != 0).then_some(st | F_DETACHED),
        );
        if detached.is_ok() {
            self.detached = true;
        }
        tag
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
        issue_request(&self.shard, self.index, self.generation, id)
    }

    /// Checkpoints B4 and B6a: between pipeline stages and before encoding
    /// the response.
    ///
    /// One atomic load and one compare while nothing has been revoked. After
    /// a revocation anywhere, it checks the ticket's own state, its
    /// connection's, and the revocation tables for every key it carries; a
    /// released or reused cell is denied (fail closed).
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::{Bouncer, Reason, RequestId, Verdict};
    /// let bouncer = Bouncer::new();
    /// let conn = bouncer.door("192.0.2.31".parse()?)?;
    /// let mut request = conn.request(RequestId(1))?;
    /// for stage in ["route", "load", "render"] {
    ///     if stage == "load" {
    ///         bouncer.revoke(RequestId(1), Reason::ADMIN)?;   // another thread, in real life
    ///     }
    ///     if let Verdict::Deny(_) = request.checkpoint() {
    ///         break;                                          // deny and eject
    ///     }
    /// }
    /// assert!(request.checkpoint().is_deny());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[inline]
    pub fn checkpoint(&mut self) -> Verdict {
        let now = self.shard.epoch.load();
        if now == self.seen {
            #[cfg(feature = "metrics")]
            {
                self.fast = self.fast.wrapping_add(1);
            }
            return Verdict::Pass;
        }
        self.slow_path(now)
    }

    /// Adds this handle's fast checkpoints to its shard's counter.
    #[cfg(feature = "metrics")]
    fn flush_meters(&mut self) {
        let n = core::mem::take(&mut self.fast);
        meter!(self.shard.meters, checkpoints_fast, n);
    }

    #[cold]
    #[inline(never)]
    fn slow_path(&mut self, now: u64) -> Verdict {
        #[cfg(feature = "metrics")]
        self.flush_meters();
        meter!(self.shard.meters, checkpoints_slow);
        match check_cell(self.shared(), self.index, self.generation, now) {
            Ok(()) => {
                self.seen = now;
                Verdict::Pass
            }
            Err(code) => {
                self.seen = SEEN_ALWAYS_CHECK;
                self.deny(code)
            }
        }
    }

    /// Checkpoint B5, right before a database commit or any other side
    /// effect that cannot be undone.
    ///
    /// Uses a sequentially consistent load, paired with the fence in
    /// `revoke`, so a commit that starts after `revoke` returned cannot pass.
    /// Fails closed: a stale or unknown ticket is denied.
    ///
    /// # Examples
    ///
    /// ```
    /// # let bouncer = bouncer_io::Bouncer::new();
    /// # let conn = bouncer.door("192.0.2.32".parse()?)?;
    /// # let mut request = conn.request(bouncer_io::RequestId(1))?;
    /// if request.before_commit().is_pass() {
    ///     // tx.commit()?;
    /// } else {
    ///     // tx.rollback(); the request leaves no side effects
    /// }
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[inline]
    pub fn before_commit(&mut self) -> Verdict {
        let now = self.shard.epoch.load_seq_cst();
        let verdict = if now == self.seen {
            Verdict::Pass
        } else {
            self.slow_path(now)
        };
        if let Verdict::Deny(d) = verdict {
            meter!(self.shard.meters, commits_blocked);
            events::emit_ticket(
                self.shared(),
                events::signals::COMMIT_BLOCKED,
                self.cell(),
                d.reference,
            );
        }
        verdict
    }

    /// `true` when a checkpoint now would deny. For loops inside long
    /// handlers, so a revoked request stops doing work, not only stops being
    /// answered.
    ///
    /// # Examples
    ///
    /// ```
    /// # let bouncer = bouncer_io::Bouncer::new();
    /// # let conn = bouncer.door("192.0.2.33".parse()?)?;
    /// # let mut request = conn.request(bouncer_io::RequestId(1))?;
    /// for row in 0..100_000u32 {
    ///     if row % 1024 == 0 && request.is_cancelled() { break; }
    ///     // ... process the row ...
    /// }
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn is_cancelled(&mut self) -> bool {
        if self.cell().state.load(Ordering::Acquire) & F_CANCELLED != 0 {
            return true;
        }
        self.checkpoint().is_deny()
    }

    pub(crate) fn deny(&self, code: DenialCode) -> Verdict {
        Verdict::Deny(denial(self.shared(), self.index, self.generation, code))
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
        let shard = Arc::clone(&self.shard);
        let shared = &shard.shared;
        let cell = shared.registry.cell(self.index);
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
        let now = shared.now();
        let (immune, exempt) = match shared.judge(addr, provenance, now) {
            Judgement::Admit { immune, exempt } => (immune, exempt),
            Judgement::ProxyHop => return self.deny(DenialCode::Unavailable),
            Judgement::Refuse(Refusal::Banned { .. }) => {
                mark_revoked(cell, self.generation, DenialCode::Forbidden);
                self.seen = SEEN_ALWAYS_CHECK;
                return self.deny(DenialCode::Forbidden);
            }
            Judgement::Refuse(_) => return self.deny(DenialCode::Unavailable),
        };
        // A PROXY-protocol client is a connection: it is charged the door
        // budgets the proxy hop was not.
        let charge = self.kind == TicketKind::Connection && !exempt;
        if charge
            && shared
                .budgets
                .admit(addr, now, shared.door_divisor())
                .is_err()
        {
            return self.deny(DenialCode::TooManyRequests);
        }
        let present = write_source(cell, addr);
        cell.present_child
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
            if charge {
                next |= F_CHARGED;
            }
            Some(next)
        });
        if updated.is_err() {
            if charge {
                shared.budgets.release_connection(Some(addr), now);
            }
            return self.deny(DenialCode::Unavailable);
        }
        // The client may fall under a source revocation: run the full check.
        fence(Ordering::SeqCst);
        let now = shard.epoch.load();
        self.slow_path(now)
    }

    /// Checkpoint B2: binds the client fingerprint digest from the TLS
    /// ClientHello. Checks fingerprint bans (bare, and within the source's
    /// automatic prefixes) and revocations.
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::{BanSpec, Bouncer, FingerprintKey};
    /// let bouncer = Bouncer::new();
    /// let fp = FingerprintKey::from_digest([3; 16]);
    /// bouncer.ban(BanSpec::key(fp))?;                         // an administrator's bare fingerprint ban
    /// let mut conn = bouncer.door("192.0.2.1".parse()?)?;
    /// assert!(conn.bind_fingerprint(fp).is_deny());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn bind_fingerprint(&mut self, key: FingerprintKey) -> Verdict {
        let (k0, k1) = key.words();
        let source = self.source();
        self.bind(
            P_FINGERPRINT,
            K_FINGERPRINT,
            Some(k0),
            k1,
            table::KIND_FINGERPRINT,
            |shared, now| shared.bans.lookup_fingerprint(&key, source, now),
        )
    }

    /// Checkpoint B3: binds the session (a keyed digest of the token) right
    /// after authentication, and checks session bans and revocations. Binds
    /// once; a second bind is denied.
    ///
    /// A key bound at the same moment as it is revoked on another thread is
    /// never missed by both sides (paired fences; loom model L-4).
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::{AccountKey, Bouncer, RequestId, SessionKey, TenantKey, Verdict};
    ///
    /// let bouncer = Bouncer::new();
    /// let conn = bouncer.door("192.0.2.40".parse()?)?;
    /// let mut request = conn.request(RequestId(1))?;
    /// let checks = [
    ///     request.bind_session(SessionKey::from_digest([1; 16])),
    ///     request.bind_account(AccountKey(42)),
    ///     request.bind_tenant(TenantKey(7)),
    /// ];
    /// assert!(checks.iter().all(Verdict::is_pass));
    /// assert!(request.bind_session(SessionKey::from_digest([2; 16])).is_deny());  // binds once
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn bind_session(&mut self, key: SessionKey) -> Verdict {
        let (k0, k1) = key.words();
        self.bind(
            P_SESSION,
            K_SESSION,
            Some(k0),
            k1,
            table::KIND_SESSION,
            move |shared, now| {
                shared.bans.lookup_key(
                    &TableKey {
                        kind: table::KIND_SESSION,
                        len: 0,
                        k0,
                        k1,
                    },
                    now,
                )
            },
        )
    }

    /// Checkpoint B3: binds the account. As [`bind_session`](Self::bind_session).
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::{AccountKey, BanSpec, Bouncer, RequestId};
    /// let bouncer = Bouncer::new();
    /// bouncer.ban(BanSpec::key(AccountKey(13)))?;
    /// let conn = bouncer.door("192.0.2.41".parse()?)?;
    /// let mut request = conn.request(RequestId(1))?;
    /// assert!(request.bind_account(AccountKey(13)).is_deny());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn bind_account(&mut self, key: AccountKey) -> Verdict {
        let (k0, k1) = ((key.0 >> 64) as u64, key.0 as u64);
        self.bind(
            P_ACCOUNT,
            K_ACCOUNT,
            Some(k0),
            k1,
            table::KIND_ACCOUNT,
            move |shared, now| {
                shared.bans.lookup_key(
                    &TableKey {
                        kind: table::KIND_ACCOUNT,
                        len: 0,
                        k0,
                        k1,
                    },
                    now,
                )
            },
        )
    }

    /// Checkpoint B3: binds the tenant. As [`bind_session`](Self::bind_session).
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::{Bouncer, Reason, RequestId, TenantKey};
    /// let bouncer = Bouncer::new();
    /// let conn = bouncer.door("192.0.2.42".parse()?)?;
    /// let mut request = conn.request(RequestId(1))?;
    /// assert!(request.bind_tenant(TenantKey(7)).is_pass());
    /// bouncer.revoke(TenantKey(7), Reason::ADMIN)?;
    /// assert!(request.checkpoint().is_deny());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn bind_tenant(&mut self, key: TenantKey) -> Verdict {
        let k1 = key.0;
        let verdict = self.bind(
            P_TENANT,
            K_TENANT,
            None,
            k1,
            table::KIND_TENANT,
            move |shared, now| {
                shared.bans.lookup_key(
                    &TableKey {
                        kind: table::KIND_TENANT,
                        len: 0,
                        k0: 0,
                        k1,
                    },
                    now,
                )
            },
        );
        if verdict.is_deny() {
            return verdict;
        }
        let shard = Arc::clone(&self.shard);
        let shared = &shard.shared;
        if !shared.identity.has_tenant() || self.exempt(shared) {
            return verdict;
        }
        let now = shared.now();
        let tenant = IdentityKey {
            kind: IdentityKind::Tenant,
            k0: 0,
            k1,
        };
        let factor = shared.identity.factor(tenant, now.secs());
        match shared.identity.tenant(k1, factor, now) {
            Ok(false) => verdict,
            Ok(true) => {
                let cell = shared.registry.cell(self.index);
                let generation_now = self.generation;
                let set = update(&cell.state, Ordering::AcqRel, Ordering::Acquire, |st| {
                    (generation(st) == generation_now && st & F_LIVE != 0)
                        .then_some(st | F_TENANT_CHARGED)
                });
                if set.is_err() {
                    shared.identity.release_tenant(k1);
                    return self.deny(DenialCode::Unavailable);
                }
                verdict
            }
            Err(_) => self.over_budget(shared),
        }
    }

    /// Selects the lane budget ([`Budgets::lane_rate`](crate::Budgets::lane_rate))
    /// this ticket is charged against, keyed by the session when one is
    /// bound, else by the client (IPv4 address, IPv6 /64).
    ///
    /// Throttles on the source, session, account, tenant, or fingerprint
    /// multiply the cost. Over budget, the ticket is denied with
    /// `TooManyRequests`; a request keeps its connection, so the denial is an
    /// ordinary 429. Allow-listed sources and lanes with no budget pass.
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::{Bouncer, Budgets, DenialCode, LaneClass, Rate, RequestId, SessionKey, Verdict};
    /// let bouncer = Bouncer::builder()
    ///     .budgets(Budgets::off().lane_rate(LaneClass::Write, Rate::per_second(1)))
    ///     .try_build()?;
    /// let conn = bouncer.door("192.0.2.70".parse()?)?;
    /// let session = SessionKey::from_digest([9; 16]);
    /// let mut first = conn.request(RequestId(1))?;
    /// assert!(first.bind_session(session).is_pass());
    /// assert!(first.bind_lane(LaneClass::Write).is_pass());
    /// let mut second = conn.request(RequestId(2))?;
    /// assert!(second.bind_session(session).is_pass());
    /// let Verdict::Deny(denial) = second.bind_lane(LaneClass::Write) else { unreachable!() };
    /// assert_eq!(denial.code, DenialCode::TooManyRequests);
    /// assert!(conn.request(RequestId(3)).is_ok(), "the connection stays");
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn bind_lane(&mut self, lane: LaneClass) -> Verdict {
        let verdict = self.checkpoint();
        if verdict.is_deny() {
            return verdict;
        }
        let shard = Arc::clone(&self.shard);
        let shared = &shard.shared;
        if !shared.identity.has_lanes() || self.exempt(shared) {
            return verdict;
        }
        let cell = shared.registry.cell(self.index);
        let present = cell.present();
        let now = shared.now();
        let secs = now.secs();
        let word = |i: usize| cell.keys[i].load(Ordering::Relaxed);
        let id = |kind: IdentityKind, k0: u64, k1: u64| IdentityKey { kind, k0, k1 };
        let source = source_of(cell);
        let who = if present & P_SESSION != 0 {
            id(IdentityKind::Session, word(K_SESSION), word(K_SESSION + 1))
        } else if let Some(a) = source {
            IdentityKey::client(a)
        } else {
            return verdict;
        };
        let mut factor = shared.identity.factor(who, secs);
        if let Some(a) = source {
            factor = factor.max(shared.budgets.source_factor(a, secs));
        }
        let others = [
            (
                P_ACCOUNT,
                id(IdentityKind::Account, word(K_ACCOUNT), word(K_ACCOUNT + 1)),
            ),
            (P_TENANT, id(IdentityKind::Tenant, 0, word(K_TENANT))),
            (
                P_FINGERPRINT,
                id(
                    IdentityKind::Fingerprint,
                    word(K_FINGERPRINT),
                    word(K_FINGERPRINT + 1),
                ),
            ),
        ];
        for (bit, key) in others {
            if present & bit != 0 {
                factor = factor.max(shared.identity.factor(key, secs));
            }
        }
        match shared.identity.lane(lane, who, factor, now) {
            Ok(()) => verdict,
            Err(_) => self.over_budget(shared),
        }
    }

    /// Whether this ticket's source is allow-listed (immune or exempt from
    /// budgets).
    fn exempt(&self, shared: &Shared) -> bool {
        let cell = shared.registry.cell(self.index);
        if cell.state.load(Ordering::Acquire) & F_IMMUNE != 0 {
            return true;
        }
        source_of(cell).is_some_and(|a| {
            shared
                .allow
                .with(|set| crate::allow::lookup(set, a).is_some())
        })
    }

    /// Denies this ticket for an identity budget: `TooManyRequests`, and a
    /// request keeps its connection.
    fn over_budget(&mut self, shared: &Shared) -> Verdict {
        let cell = shared.registry.cell(self.index);
        let generation_now = self.generation;
        mark_revoked(cell, generation_now, DenialCode::TooManyRequests);
        if self.kind == TicketKind::Request {
            let _ = update(&cell.state, Ordering::AcqRel, Ordering::Acquire, |st| {
                (generation(st) == generation_now).then_some(st | F_KEEP_CONNECTION)
            });
        }
        self.seen = SEEN_ALWAYS_CHECK;
        meter!(self.shard.meters, budget_refused);
        let verdict = self.deny(DenialCode::TooManyRequests);
        if let Verdict::Deny(d) = &verdict {
            events::emit_ticket(shared, events::signals::BUDGET_REFUSED, cell, d.reference);
        }
        verdict
    }

    /// Writes a key, publishes it, then checks it (the binder's half of the
    /// paired fences: write, publish, fence, check).
    fn bind(
        &mut self,
        bit: u64,
        at: usize,
        hi: Option<u64>,
        lo: u64,
        kind: u8,
        banned: impl FnOnce(&Shared, u64) -> Probe,
    ) -> Verdict {
        match self.bind_key(bit, at, hi, lo, kind, banned) {
            Bound::Invalid => self.deny(DenialCode::Unavailable),
            Bound::Refused(code) => {
                self.seen = SEEN_ALWAYS_CHECK;
                self.deny(code)
            }
            Bound::Written => {
                let verdict = self.checkpoint();
                if verdict.is_pass() && (kind == table::KIND_SESSION || kind == table::KIND_ACCOUNT)
                {
                    self.note_identity(hi.unwrap_or(0), lo);
                }
                verdict
            }
        }
    }

    /// The shared-state half of [`bind`](Self::bind): it only reads `self`,
    /// so no reference to the shard is cloned.
    fn bind_key(
        &self,
        bit: u64,
        at: usize,
        hi: Option<u64>,
        lo: u64,
        kind: u8,
        banned: impl FnOnce(&Shared, u64) -> Probe,
    ) -> Bound {
        let shared = &*self.shard.shared;
        let cell = shared.registry.cell(self.index);
        let st = cell.state.load(Ordering::Acquire);
        if generation(st) != self.generation || st & F_LIVE == 0 {
            return Bound::Invalid;
        }
        if cell.present() & bit != 0 {
            return Bound::Invalid;
        }
        match hi {
            Some(hi) => {
                cell.keys[at].store(hi, Ordering::Relaxed);
                cell.keys[at + 1].store(lo, Ordering::Relaxed);
            }
            None => cell.keys[at].store(lo, Ordering::Relaxed),
        }
        let before = cell
            .present_child
            .fetch_or(bit << PRESENT_SHIFT, Ordering::AcqRel);
        if (before >> PRESENT_SHIFT) & bit != 0 {
            // Another thread bound the same kind first.
            return Bound::Invalid;
        }
        fence(Ordering::SeqCst);
        // The clock is read only when a ban of this kind exists to expire.
        if shared.bans.may_hold(kind) {
            match banned(shared, shared.now().secs()) {
                Probe::Hit(_) | Probe::Busy => {
                    mark_revoked(cell, self.generation, DenialCode::Forbidden);
                    return Bound::Refused(DenialCode::Forbidden);
                }
                Probe::Miss => {}
            }
        }
        let key = TableKey {
            kind,
            len: 0,
            k0: hi.unwrap_or(0),
            k1: lo,
        };
        if let Some(hit) = shared.revocations.matches_key(&key) {
            mark_revoked(cell, self.generation, hit.code);
            if self.kind == TicketKind::Request && !hit.keep_connection {
                revoke_parent(shared, cell, hit.code);
            }
            if hit.keep_connection {
                let generation_now = self.generation;
                let _ = update(&cell.state, Ordering::AcqRel, Ordering::Acquire, |st| {
                    (generation(st) == generation_now).then_some(st | F_KEEP_CONNECTION)
                });
            }
            return Bound::Refused(hit.code);
        }
        Bound::Written
    }

    /// Counts a session or account toward shared-address detection.
    fn note_identity(&self, k0: u64, k1: u64) {
        let shared = &*self.shard.shared;
        let cell = shared.registry.cell(self.index);
        if let Some(src) = source_of(cell) {
            if shared.sources.note(src, k0, k1, shared.recent_secs()) {
                let subject = Subject {
                    source: Some(src),
                    ..Subject::default()
                };
                events::Emit {
                    subject,
                    ..events::Emit::new(events::signals::SOURCE_SHARED_SUSPECTED)
                }
                .send(shared);
            }
        }
    }

    /// Reports misbehaviour seen by any layer (a failed handshake, malformed
    /// traffic, a contract violation, a failed login) against this ticket's
    /// keys. The strike is counted in a windowed counter and reported. When a
    /// threshold is reached, the outcome is `ThresholdObserved` in observe
    /// mode (the default: nothing is banned) or `Banned` in enforce mode,
    /// which also revokes this ticket. Strikes against a trusted proxy hop,
    /// an allow-listed source, or an unbound proxied request are `Ignored`.
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::{Bouncer, Enforcement, StrikeKind, StrikeOutcome};
    /// let bouncer = Bouncer::builder().enforcement(Enforcement::enforce_all()).try_build()?;
    /// let mut conn = bouncer.door("198.51.100.66".parse()?)?;
    /// let mut last = StrikeOutcome::Counted;
    /// for _ in 0..5 {
    ///     last = conn.strike(StrikeKind::Malformed);
    /// }
    /// assert!(matches!(last, StrikeOutcome::Banned(_)));
    /// assert!(conn.checkpoint().is_deny());                      // thrown out now
    /// assert!(bouncer.door("198.51.100.66".parse()?).is_err());  // and remembered
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn strike(&self, kind: crate::strikes::StrikeKind) -> crate::strikes::StrikeOutcome {
        crate::strikes::strike(&self.shard, self.index, self.generation, kind)
    }

    /// Wipe, replace, eject, remember, in this order and with no early
    /// return:
    ///
    /// 1. **cancel**: the ticket is marked cancelled (and revoked with
    ///    `DenialCode::Forbidden` if it was not revoked already);
    /// 2. **wipe**: the whole capacity of `collected` is overwritten with
    ///    zeroes through crypt-io's guaranteed wipe;
    /// 3. **replace**: the builder's `denial_format` writes the protocol's
    ///    denial into `collected`;
    /// 4. **eject**: the configured `Ejector` closes the connection
    ///    abortively, after the denial is flushed or 100 ms, whichever is
    ///    first (not when the revocation kept the connection open);
    /// 5. **remember**: reports whether the source is in ban memory (bans
    ///    attached to a revocation or set by an enforced strike are already
    ///    there);
    /// 6. **report**: a `denial.wipe_eject` event with the denial's reference.
    ///
    /// The denial carries nothing about why. A second call on the same
    /// ticket wipes again and reports, but formats and ejects nothing.
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::{Bouncer, Collected, Reason, RequestId};
    ///
    /// let bouncer = Bouncer::new();
    /// let conn = bouncer.door("192.0.2.50".parse()?)?;
    /// let mut request = conn.request(RequestId(1))?;
    /// let mut reply = Collected::new();
    /// reply.extend_from_slice(b"secret report")?;
    /// bouncer.revoke(RequestId(1), Reason::ADMIN)?;
    /// if request.checkpoint().is_deny() {
    ///     let out = request.deny_and_eject(&mut reply);
    ///     assert!(out.wiped && !out.formatted);          // the default formatter writes nothing
    ///     assert!(reply.is_empty());
    /// }
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn deny_and_eject(&mut self, collected: &mut Collected) -> Ejected {
        let shard = Arc::clone(&self.shard);
        self.deny_and_eject_with(collected, &*shard.shared.format)
    }

    /// As [`deny_and_eject`](Self::deny_and_eject), with a formatter for a
    /// protocol other than the builder's.
    pub fn deny_and_eject_with(
        &mut self,
        collected: &mut Collected,
        format: &dyn DenialFormat,
    ) -> Ejected {
        let shard = Arc::clone(&self.shard);
        let shared = &shard.shared;
        meter!(shard.meters, denials);
        let cell = shared.registry.cell(self.index);
        let generation_now = self.generation;
        // 1. Cancel, and revoke if nothing revoked it yet.
        let prev = update(&cell.state, Ordering::AcqRel, Ordering::Acquire, |st| {
            (generation(st) == generation_now && st & F_LIVE != 0).then_some(st | F_CANCELLED)
        });
        let first = prev.is_ok_and(|st| st & F_CANCELLED == 0);
        if prev.is_ok_and(|st| st & F_REVOKED == 0) {
            mark_revoked(cell, generation_now, DenialCode::Forbidden);
            if self.kind == TicketKind::Request {
                revoke_parent(shared, cell, DenialCode::Forbidden);
            }
            // The connection's other requests must notice.
            shard.epoch.bump();
        }
        self.seen = SEEN_ALWAYS_CHECK;
        let st = cell.state.load(Ordering::Acquire);
        let code = if st & F_REVOKED != 0 && generation(st) == generation_now {
            code_of(st)
        } else {
            DenialCode::Forbidden
        };
        let d = denial(shared, self.index, generation_now, code);
        // 2. Wipe the whole capacity.
        collected.wipe();
        let mut out = Ejected {
            wiped: true,
            formatted: false,
            ejected: false,
            remembered: false,
            reference: d.reference,
        };
        if !first {
            events::emit_ticket(
                shared,
                events::signals::DENIAL_WIPE_EJECT,
                cell,
                d.reference,
            );
            return out;
        }
        // 3. Replace.
        match format.format(&d, collected) {
            Ok(()) if collected.len() <= crate::MAX_DENIAL_BYTES => {
                out.formatted = !collected.is_empty()
            }
            _ => collected.wipe(),
        }
        // 4. Eject, unless the revocation keeps the connection.
        let keep = st & F_KEEP_CONNECTION != 0;
        if !keep {
            if let Some(ejector) = shared.ejector.as_ref() {
                let conn = ConnId(cell.conn.load(Ordering::Relaxed));
                let kind = if out.formatted {
                    CloseKind::AfterFlush {
                        deadline: core::time::Duration::from_millis(100),
                    }
                } else {
                    CloseKind::Abort
                };
                ejector.eject(conn, kind);
                out.ejected = true;
                meter!(shared.meters, ejections);
            }
        }
        // 5. Remember.
        if let Some(src) = source_of(cell) {
            out.remembered = matches!(
                shared.bans.lookup_addr(src, shared.now().secs()),
                crate::bans::Lookup::Banned(_)
            );
        }
        // 6. Report.
        events::emit_ticket(
            shared,
            events::signals::DENIAL_WIPE_EJECT,
            cell,
            d.reference,
        );
        out
    }

    /// The registry index, for tests.
    #[cfg(all(test, not(bouncer_loom)))]
    pub(crate) fn index(&self) -> u32 {
        self.index
    }
}

/// The denial for a ticket: the code, the fixed message and application code
/// from the denial table, and a reference derived from the ticket.
pub(crate) fn denial(shared: &Shared, index: u32, generation: u32, code: DenialCode) -> Denial {
    let tag = TicketTag::new(index, generation).get();
    let r = shared.references.hash3(tag, u64::from(code.number()), 1) | 1;
    shared.denials.denial(code, Reference::new(r))
}

/// Issues a request ticket under the connection at `(parent, parent_gen)`.
pub(crate) fn issue_request(
    shard: &Arc<Shard>,
    parent: u32,
    parent_gen: u32,
    id: RequestId,
) -> Result<Ticket, BouncerError> {
    let shared = &shard.shared;
    if parent as usize >= shared.registry.cells.len() {
        return Err(BouncerError::Stale);
    }
    let pcell = shared.registry.cell(parent);
    let st = pcell.state.load(Ordering::Acquire);
    if generation(st) != parent_gen || st & F_LIVE == 0 {
        return Err(BouncerError::Stale);
    }
    if st & 0xff != KIND_CONNECTION {
        return Err(BouncerError::NotAConnectionTicket);
    }
    if st & F_REVOKED != 0 {
        return Err(BouncerError::Revoked);
    }
    let inherited = st & (F_IMMUNE | PROVENANCE_MASK);
    let (flags, source) = if st & F_PROXY_HOP != 0 && st & F_CLIENT_BOUND == 0 {
        (F_PENDING_CLIENT | inherited, None)
    } else {
        (inherited, source_of(pcell))
    };
    // Count the child before it exists, so a concurrent release of the
    // parent cannot miss it.
    let counted = update(&pcell.link, Ordering::AcqRel, Ordering::Acquire, |link| {
        (generation(link) == parent_gen).then(|| link.wrapping_add(1))
    })
    .is_ok();
    if !counted {
        return Err(BouncerError::Stale);
    }
    let first = shared.registry.shard_of(parent);
    let issued = Ticket::issue(
        shard,
        first,
        Issue {
            kind: TicketKind::Request,
            flags,
            conn: Some(pcell.conn.load(Ordering::Relaxed)),
            source,
            request: Some(id),
            parent: Some((parent, parent_gen)),
        },
    );
    match issued {
        Some(t) => {
            // The connection's latest request, followed by the egress check:
            // a plain store, published after the child's state.
            pcell.keys[K_LATEST].store(u64::from(t.index), Ordering::Release);
            Ok(t)
        }
        None => {
            uncount_child(shared, parent, parent_gen);
            Err(BouncerError::RegistryFull {
                capacity: shared.tickets_capacity,
            })
        }
    }
}

/// The full check of one cell after the epoch moved: its state, its
/// connection's (for a request), and the revocation tables for every key it
/// and its connection carry. Marks the cell revoked on a match. On `Ok`, the
/// cell is recorded as checked at `epoch`.
pub(crate) fn check_cell(
    shared: &Shared,
    index: u32,
    gen_: u32,
    epoch: u64,
) -> Result<(), DenialCode> {
    let cell = shared.registry.cell(index);
    let st = cell.state.load(Ordering::Acquire);
    if generation(st) != gen_ || st & F_LIVE == 0 {
        return Err(DenialCode::Unavailable);
    }
    if st & F_REVOKED != 0 {
        return Err(code_of(st));
    }
    if st & F_PENDING_CLIENT != 0 {
        return Err(DenialCode::Unavailable);
    }
    let request = TicketKind::from_state(st) == TicketKind::Request;
    let mut parent_cell = None;
    if request {
        let link = cell.link.load(Ordering::Relaxed);
        let (pi, pg) = ((link >> 32) as u32, link as u32);
        let pcell = shared.registry.cell(pi);
        let pst = pcell.state.load(Ordering::Acquire);
        if generation(pst) != pg || pst & F_LIVE == 0 {
            // The connection is gone: a request cannot outlive it.
            mark_revoked(cell, gen_, DenialCode::Unavailable);
            return Err(DenialCode::Unavailable);
        }
        if pst & F_REVOKED != 0 {
            let code = code_of(pst);
            mark_revoked(cell, gen_, code);
            return Err(code);
        }
        parent_cell = Some((pcell, pg));
    }
    if !shared.revocations.is_empty() {
        let hit = shared
            .revocations
            .matches(cell)
            .or_else(|| parent_cell.and_then(|(p, _)| shared.revocations.matches(p)));
        if let Some(hit) = hit {
            mark_revoked(cell, gen_, hit.code);
            if request && hit.keep_connection {
                let _ = update(&cell.state, Ordering::AcqRel, Ordering::Acquire, |st| {
                    (generation(st) == gen_).then_some(st | F_KEEP_CONNECTION)
                });
            }
            if request && !hit.keep_connection {
                if let Some((p, pg)) = parent_cell {
                    mark_revoked(p, pg, hit.code);
                }
            }
            return Err(hit.code);
        }
    }
    cell.seen.store(epoch, Ordering::Release);
    Ok(())
}

/// Revokes the connection a request cell belongs to.
fn revoke_parent(shared: &Shared, cell: &Cell, code: DenialCode) {
    let link = cell.link.load(Ordering::Relaxed);
    let (pi, pg) = ((link >> 32) as u32, link as u32);
    mark_revoked(shared.registry.cell(pi), pg, code);
}

/// Sets the revoked flag and denial code on a cell of generation `gen_`. The
/// stronger code is kept when it is already revoked. Returns `true` when this
/// call revoked it.
pub(crate) fn mark_revoked(cell: &Cell, gen_: u32, code: DenialCode) -> bool {
    update(&cell.state, Ordering::AcqRel, Ordering::Acquire, |st| {
        if generation(st) != gen_ || st & F_LIVE == 0 {
            return None;
        }
        let keep = if st & F_REVOKED != 0 {
            code_of(st).max(code)
        } else {
            code
        };
        let next =
            (st & !(0xff << CODE_SHIFT)) | F_REVOKED | (u64::from(keep.number()) << CODE_SHIFT);
        (next != st).then_some(next)
    })
    .is_ok_and(|prev| prev & F_REVOKED == 0)
}

/// The egress check by tag (checkpoint B6b): the cell, and for a connection
/// its latest live request.
pub(crate) fn egress(
    shared: &Shared,
    epoch_word: &crate::revoke::RevocationEpoch,
    tag: TicketTag,
) -> Verdict {
    let (index, gen_) = (tag.index(), tag.generation());
    if index as usize >= shared.registry.cells.len() {
        return Verdict::Deny(denial(shared, index, gen_, DenialCode::Unavailable));
    }
    let cell = shared.registry.cell(index);
    let epoch = epoch_word.load();
    let st = cell.state.load(Ordering::Acquire);
    let clean = |st: u64| st & (F_REVOKED | F_PENDING_CLIENT) == 0 && st & F_LIVE != 0;
    if generation(st) == gen_ && clean(st) && cell.seen.load(Ordering::Acquire) == epoch {
        match latest_child(shared, cell, index, gen_, st) {
            None => return Verdict::Pass,
            Some((ci, _, cst)) => {
                if clean(cst) && shared.registry.cell(ci).seen.load(Ordering::Acquire) == epoch {
                    return Verdict::Pass;
                }
            }
        }
    }
    egress_slow(shared, index, gen_, epoch)
}

#[cold]
#[inline(never)]
fn egress_slow(shared: &Shared, index: u32, gen_: u32, epoch: u64) -> Verdict {
    let mut result = check_cell(shared, index, gen_, epoch);
    let cell = shared.registry.cell(index);
    if result.is_ok() {
        let st = cell.state.load(Ordering::Acquire);
        if let Some((ci, cg, _)) = latest_child(shared, cell, index, gen_, st) {
            // A request denied here takes its connection with it (check_cell
            // already marked it, unless the revocation keeps it).
            if let Err(code) = check_cell(shared, ci, cg, epoch) {
                result = Err(code);
            }
        }
    }
    match result {
        Ok(()) => Verdict::Pass,
        Err(code) => {
            let d = denial(shared, index, gen_, code);
            meter!(shared.meters, egress_blocked);
            events::emit_ticket(shared, events::signals::EGRESS_BLOCKED, cell, d.reference);
            Verdict::Deny(d)
        }
    }
}

/// A connection cell's latest live request: index, generation, state.
fn latest_child(
    shared: &Shared,
    cell: &Cell,
    index: u32,
    gen_: u32,
    st: u64,
) -> Option<(u32, u32, u64)> {
    if st & 0xff != KIND_CONNECTION {
        return None;
    }
    // A stale index is harmless: the child must be a live request of this
    // connection's generation.
    let ci = cell.keys[K_LATEST].load(Ordering::Acquire) as u32;
    if ci == NIL || ci as usize >= shared.registry.cells.len() {
        return None;
    }
    let child = shared.registry.cell(ci);
    let cst = child.state.load(Ordering::Acquire);
    let link = child.link.load(Ordering::Relaxed);
    let belongs = cst & F_LIVE != 0
        && cst & 0xff == KIND_REQUEST
        && link == ((u64::from(index) << 32) | u64::from(gen_));
    belongs.then_some((ci, generation(cst), cst))
}

/// Releases the cell of a ticket of generation `gen_`. Returns `false` when
/// the cell was already released.
pub(crate) fn release_cell(shard: &Shard, index: u32, gen_: u32) -> bool {
    let shared = &shard.shared;
    let cell = shared.registry.cell(index);
    let next_gen = gen_.wrapping_add(1);
    let retire = next_gen == u32::MAX || next_gen == 0;
    // Take the cell: exactly one releaser wins.
    let taken = update(&cell.state, Ordering::AcqRel, Ordering::Acquire, |st| {
        (generation(st) == gen_ && st & F_LIVE != 0).then_some(u64::from(next_gen) << 32)
    });
    let Ok(st) = taken else {
        return false;
    };
    // The cell is ours now; the next issue overwrites this word.
    let present_child = cell.present_child.load(Ordering::Acquire);
    match TicketKind::from_state(st) {
        TicketKind::Connection => {
            let old = cell.link.swap(u64::from(next_gen) << 32, Ordering::AcqRel);
            if generation(old) == gen_ && old as u32 > 0 {
                // Live requests remain: they must see their connection is gone.
                shard.epoch.bump();
            }
            if st & F_CHARGED != 0 {
                shared
                    .budgets
                    .release_connection(source_present(cell, present_child), shared.now());
            }
        }
        TicketKind::Request => {
            let link = cell.link.load(Ordering::Relaxed);
            let (pi, pg) = ((link >> 32) as u32, link as u32);
            if st & F_PENDING_CLIENT != 0 && shared.sink.is_some() {
                // A proxied request ended without its real client: the
                // adapter never called `bind_client`.
                events::Emit {
                    subject: Subject {
                        conn: Some(ConnId(cell.conn.load(Ordering::Relaxed))),
                        ..Subject::default()
                    },
                    ..events::Emit::new(events::signals::DOOR_PROXY_HOP_UNRESOLVED)
                }
                .send(shared);
            }
            // The connection may still name it as its latest request; the
            // egress check sees it is no longer live.
            uncount_child(shared, pi, pg);
        }
    }
    if st & F_TENANT_CHARGED != 0 {
        shared
            .identity
            .release_tenant(cell.keys[K_TENANT].load(Ordering::Relaxed));
    }
    if !retire {
        shared.registry.push(index);
    }
    true
}

/// The source of a cell being released, from its saved present bits.
fn source_present(cell: &Cell, present_child: u64) -> Option<IpAddr> {
    let present = present_child >> PRESENT_SHIFT;
    (present & P_SOURCE != 0).then(|| read_source(cell, present))
}

fn read_source(cell: &Cell, present: u64) -> IpAddr {
    let hi = cell.keys[K_SOURCE].load(Ordering::Relaxed);
    let lo = cell.keys[K_SOURCE + 1].load(Ordering::Relaxed);
    if present & P_SOURCE_V6 != 0 {
        IpAddr::V6(Ipv6Addr::from((u128::from(hi) << 64) | u128::from(lo)))
    } else {
        IpAddr::V4(Ipv4Addr::from(lo as u32))
    }
}

/// The source address bound on a cell.
pub(crate) fn source_of(cell: &Cell) -> Option<IpAddr> {
    let present = cell.present();
    (present & P_SOURCE != 0).then(|| read_source(cell, present))
}

/// The keys of a cell, for events.
pub(crate) fn subject_of(cell: &Cell) -> Subject {
    let present = cell.present();
    let word = |i: usize| cell.keys[i].load(Ordering::Relaxed);
    let two = |i: usize| (u128::from(word(i)) << 64) | u128::from(word(i + 1));
    let digest = |i: usize| {
        let mut b = [0u8; 16];
        b[..8].copy_from_slice(&word(i).to_be_bytes());
        b[8..].copy_from_slice(&word(i + 1).to_be_bytes());
        b
    };
    Subject {
        conn: Some(ConnId(cell.conn.load(Ordering::Relaxed))),
        request: (present & P_REQUEST != 0).then(|| RequestId(two(K_REQUEST))),
        source: source_of(cell),
        prefix: None,
        session: (present & P_SESSION != 0).then(|| SessionKey::from_digest(digest(K_SESSION))),
        account: (present & P_ACCOUNT != 0).then(|| AccountKey(two(K_ACCOUNT))),
        tenant: (present & P_TENANT != 0).then(|| TenantKey(word(K_TENANT))),
        fingerprint: (present & P_FINGERPRINT != 0)
            .then(|| FingerprintKey::from_digest(digest(K_FINGERPRINT))),
    }
}

/// Writes the source key words; returns the present bits for them.
fn write_source(cell: &Cell, src: IpAddr) -> u64 {
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

pub(crate) fn code_of(state: u64) -> DenialCode {
    DenialCode::from_number((state >> CODE_SHIFT) as u8)
}

/// Takes one live-request count from a connection cell, if it is still the
/// same generation.
fn uncount_child(shared: &Shared, parent: u32, parent_gen: u32) {
    let _ = update(
        &shared.registry.cell(parent).link,
        Ordering::AcqRel,
        Ordering::Acquire,
        |link| (generation(link) == parent_gen && link as u32 > 0).then(|| link - 1),
    );
}

impl Drop for Ticket {
    fn drop(&mut self) {
        #[cfg(feature = "metrics")]
        self.flush_meters();
        if !self.detached {
            release_cell(&self.shard, self.index, self.generation);
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
}

#[cfg(all(test, not(bouncer_loom)))]
mod tests {
    use super::*;
    use crate::{Bouncer, Budgets};

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn one_ticket() -> Bouncer {
        Bouncer::builder()
            .tickets(1)
            .budgets(Budgets::off())
            .try_build()
            .unwrap()
    }

    #[test]
    fn test_ticket_stale_generation_denied() {
        // Threat T-10, edge case 25: a handle whose cell was released and
        // reissued is denied, never mistaken for the new ticket.
        let b = one_ticket();
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
            detached: false,
            #[cfg(feature = "metrics")]
            fast: 0,
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
        // Dropping the stale handle must not release the live cell.
        drop(stale);
        let mut live = second;
        assert!(live.checkpoint().is_pass());
        assert!(
            b.door(ip("192.0.2.4")).is_err(),
            "the live cell is still held"
        );
    }

    #[test]
    fn test_ticket_generation_at_max_retires_cell() {
        // Edge case 26.
        let b = one_ticket();
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
        assert_eq!(conn.id().to_string().len(), 16);
        let r = conn.request(RequestId(5)).unwrap();
        assert_eq!(r.conn(), conn.conn());
        assert_eq!(r.source(), conn.source());
        assert_ne!(r.index(), conn.index());
        let subject = subject_of(r.cell());
        assert_eq!(subject.request, Some(RequestId(5)));
        assert_eq!(subject.source, Some(ip("2001:db8::7")));
    }

    #[test]
    fn test_latest_child_followed_and_forgotten() {
        let b = Bouncer::new();
        let conn = b.door(ip("192.0.2.9")).unwrap();
        let shared = &conn.shard.shared;
        let cell = conn.cell();
        let st = cell.state.load(Ordering::Acquire);
        assert!(latest_child(shared, cell, conn.index, conn.generation, st).is_none());
        let r = conn.request(RequestId(1)).unwrap();
        let got = latest_child(shared, cell, conn.index, conn.generation, st).map(|c| c.0);
        assert_eq!(got, Some(r.index));
        drop(r);
        assert!(latest_child(shared, cell, conn.index, conn.generation, st).is_none());
    }
}
