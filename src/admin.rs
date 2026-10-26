//! Administration: what is banned and why, filtered listings, the allow list
//! swap, and health. Cold paths: they take locks and allocate.

use core::{fmt, time::Duration};
use std::time::SystemTime;

use crate::{
    allow::{self, AllowKind, AllowList},
    bans::{BanId, view::Held},
    bouncer::{Bouncer, Shared, subject_of_key},
    directive::{Actor, ActorKind, Reason},
    door::{Judgement, Provenance},
    error::BouncerError,
    events::{Emit, signals},
    keys::{BanKey, Cidr, Family},
    maintain,
    registry::{F_DETACHED, F_LIVE},
    revoke::Target,
    share::NodeId,
    strikes::{Mode, Posture, StrikeKind},
};

/// Most items one page returns.
const MAX_PAGE: u16 = 1_000;

/// One ban, as `list` and `explain` report it.
///
/// # Examples
///
/// ```
/// use bouncer_io::{Bouncer, Filter, Page};
/// let bouncer = Bouncer::new();
/// bouncer.ban("198.51.100.9".parse::<std::net::IpAddr>()?)?;
/// let listing = bouncer.list(&Filter::all(), Page::first(10));
/// let record = &listing.items[0];
/// assert_eq!(record.key.to_string(), "198.51.100.9");
/// assert!(record.until.is_some());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BanRecord {
    /// The ban's id.
    pub id: BanId,
    /// What is banned.
    pub key: BanKey,
    /// When it ends; `None` for a permanent ban.
    pub until: Option<SystemTime>,
    /// When it was issued (or last renewed).
    pub issued: SystemTime,
    /// Who issued it.
    pub actor: ActorKind,
    /// Why.
    pub reason: Reason,
    /// Earlier bans of the same key that this one follows.
    pub offences: u16,
    /// The node that issued it, when it came from another node.
    pub origin: Option<NodeId>,
}

impl fmt::Display for BanRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} banned ", self.key)?;
        match self.until {
            Some(t) => write!(f, "until {}", clock_lib::Wall::from(t))?,
            None => f.write_str("permanently")?,
        }
        write!(f, " by {:?}, reason {}", self.actor, self.reason)?;
        if self.offences > 0 {
            write!(f, ", offence {}", u32::from(self.offences) + 1)?;
        }
        Ok(())
    }
}

/// A key's offence history (arrives with offender memory).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct OffenderRecord {
    /// Offences, decayed by the half-life.
    pub offences: f32,
    /// The last offence.
    pub last: SystemTime,
}

/// One budget's state for a key.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BudgetState {
    /// Which budget: `door.rate.client`, `door.rate.prefix`,
    /// `door.concurrency.client`, `door.concurrency.prefix`,
    /// `tenant.in_flight`.
    pub class: &'static str,
    /// The key the budget is kept under.
    pub key: BanKey,
    /// What is left now.
    pub remaining: u32,
    /// When a spent rate budget allows the next one.
    pub retry_after: Option<Duration>,
}

/// One strike counter's state for a key.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StrikeState {
    /// The strike kind.
    pub kind: StrikeKind,
    /// Weighted strikes in the current window.
    pub count: u16,
    /// The threshold of the kind.
    pub threshold: u16,
    /// Whether reaching it bans (enforce) or reports (observe).
    pub mode: Mode,
}

/// Everything bouncer knows about one key. `Display` prints plain sentences.
///
/// # Examples
///
/// ```
/// let bouncer = bouncer_io::Bouncer::new();
/// bouncer.ban("203.0.113.0/24".parse::<bouncer_io::Cidr>()?)?;
/// let why = bouncer.explain("203.0.113.7".parse::<std::net::IpAddr>()?);
/// assert!(!why.admitted);
/// assert_eq!(why.bans.len(), 1);
/// assert!(why.to_string().starts_with("203.0.113.7 is refused: 203.0.113.0/24 banned until "));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct Explanation {
    /// The key asked about.
    pub key: BanKey,
    /// Whether the door (or the bind for an identity key) would let it in now.
    pub admitted: bool,
    /// The allow-list entry covering it.
    pub allow: Option<AllowKind>,
    /// Every ban that applies, wider prefixes included.
    pub bans: Vec<BanRecord>,
    /// Its offence history.
    pub offender: Option<OffenderRecord>,
    /// Budget states.
    pub budgets: Vec<BudgetState>,
    /// Strike counters with strikes in their window.
    pub strikes: Vec<StrikeState>,
    /// Whether the address is flagged as shared (likely NAT).
    pub shared_source: bool,
    /// Live tickets carrying the key.
    pub live_tickets: u32,
}

impl fmt::Display for Explanation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} is {}",
            self.key,
            if self.admitted { "admitted" } else { "refused" }
        )?;
        let mut sep = ": ";
        let mut part = |f: &mut fmt::Formatter<'_>, text: fmt::Arguments<'_>| {
            let r = write!(f, "{sep}{text}");
            sep = "; ";
            r
        };
        match self.allow {
            Some(AllowKind::Immune) => part(f, format_args!("allow-listed as immune"))?,
            Some(_) => part(f, format_args!("allow-listed as exempt from budgets"))?,
            None => {}
        }
        for ban in &self.bans {
            part(f, format_args!("{ban}"))?;
        }
        if let Some(o) = &self.offender {
            part(f, format_args!("{:.1} recent offences", o.offences))?;
        }
        for s in &self.strikes {
            part(
                f,
                format_args!(
                    "{} {:?} strikes of {} ({:?})",
                    s.count, s.kind, s.threshold, s.mode
                ),
            )?;
        }
        for b in &self.budgets {
            if b.remaining == 0 {
                part(f, format_args!("{} spent", b.class))?;
            }
        }
        if self.shared_source {
            part(f, format_args!("shared address"))?;
        }
        if self.live_tickets > 0 {
            part(f, format_args!("{} live tickets", self.live_tickets))?;
        }
        Ok(())
    }
}

/// Which bans a listing returns.
///
/// # Examples
///
/// ```
/// use bouncer_io::{Actor, Family, Filter, Reason};
/// let f = Filter::all().family(Family::V6).by(Actor::Admin(1)).because(Reason::ADMIN).permanent_only();
/// # let _ = f;
/// ```
#[derive(Debug, Clone, Default)]
pub struct Filter {
    family: Option<Family>,
    within: Option<Cidr>,
    actor: Option<ActorKind>,
    reason: Option<Reason>,
    expiring_before: Option<SystemTime>,
    permanent_only: bool,
}

impl Filter {
    /// Every ban.
    #[must_use]
    pub fn all() -> Filter {
        Filter::default()
    }

    /// Address and prefix bans of one family.
    #[must_use]
    pub fn family(mut self, family: Family) -> Filter {
        self.family = Some(family);
        self
    }

    /// Address and prefix bans inside `prefix`.
    #[must_use]
    pub fn within(mut self, prefix: Cidr) -> Filter {
        self.within = Some(prefix);
        self
    }

    /// Bans issued by this kind of actor.
    #[must_use]
    pub fn by(mut self, actor: Actor) -> Filter {
        self.actor = Some(actor.kind());
        self
    }

    /// Bans with this reason.
    #[must_use]
    pub fn because(mut self, reason: Reason) -> Filter {
        self.reason = Some(reason);
        self
    }

    /// Timed bans ending before `at`.
    #[must_use]
    pub fn expiring_before(mut self, at: SystemTime) -> Filter {
        self.expiring_before = Some(at);
        self
    }

    /// Permanent bans only.
    #[must_use]
    pub fn permanent_only(mut self) -> Filter {
        self.permanent_only = true;
        self
    }

    fn matches(&self, r: &BanRecord) -> bool {
        let cidr = match r.key {
            BanKey::Address(a) => Some(Cidr::host(a)),
            BanKey::Prefix(c) | BanKey::FingerprintIn(_, c) => Some(c),
            _ => None,
        };
        if let Some(fam) = self.family {
            if cidr.is_none_or(|c| c.family() != fam) {
                return false;
            }
        }
        if let Some(w) = &self.within {
            if cidr.is_none_or(|c| !w.covers(&c)) {
                return false;
            }
        }
        if self.actor.is_some_and(|a| a != r.actor) || self.reason.is_some_and(|x| x != r.reason) {
            return false;
        }
        if self.permanent_only && r.until.is_some() {
            return false;
        }
        if let Some(at) = self.expiring_before {
            if r.until.is_none_or(|u| u >= at) {
                return false;
            }
        }
        true
    }
}

/// A page of a listing: up to `limit` bans after a position.
///
/// # Examples
///
/// ```
/// let page = bouncer_io::Page::first(5_000);
/// assert_eq!(page.limit(), 1_000);   // capped
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Page {
    after: u64,
    limit: u16,
}

impl Page {
    /// The first page, `limit` items (1 to 1,000).
    #[must_use]
    pub fn first(limit: u16) -> Page {
        Page {
            after: 0,
            limit: limit.clamp(1, MAX_PAGE),
        }
    }

    /// Items per page.
    #[must_use]
    pub const fn limit(&self) -> u16 {
        self.limit
    }
}

/// One page of bans, ordered by id.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct Listing {
    /// The bans on this page.
    pub items: Vec<BanRecord>,
    /// The next page, when more match.
    pub next: Option<Page>,
    /// How many bans match in total.
    pub total: u64,
}

/// The maintainer thread's state.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaintainerState {
    /// No thread was asked for; maintenance runs from `maintain`.
    NotStarted,
    /// Waiting for work.
    Parked,
    /// Working.
    Running,
    /// The thread ended (it panicked, or the bouncer is closing).
    Stopped,
}

/// Table loads, registry use, and the maintainer's state, for health
/// endpoints and alerts.
///
/// # Examples
///
/// ```
/// let health = bouncer_io::Bouncer::new().health();
/// assert!(health.is_ok());
/// assert_eq!(health.tickets_live, 0);
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Health {
    /// Live tickets.
    pub tickets_live: u32,
    /// Ticket capacity.
    pub tickets_capacity: u32,
    /// Connection tickets held by a tag that was never released.
    pub tickets_detached: u32,
    /// Dynamic ban table load, 0 to 1.
    pub ban_load: f32,
    /// Revocation table load, 0 to 1.
    pub revocation_load: f32,
    /// The fullest budget table's load, 0 to 1.
    pub budget_load: f32,
    /// Persistence records queued and not yet written.
    pub journal_backlog: u32,
    /// The last persistence failure, when the last write failed.
    pub last_persist_error: Option<std::io::ErrorKind>,
    /// The maintainer thread.
    pub maintainer: MaintainerState,
    /// The posture.
    pub posture: Posture,
}

impl Health {
    /// `false` when a table is above 90% load, the maintainer stopped, or the
    /// last persistence write failed.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        let tickets = if self.tickets_capacity == 0 {
            0.0
        } else {
            self.tickets_live as f32 / self.tickets_capacity as f32
        };
        tickets <= 0.9
            && self.ban_load <= 0.9
            && self.revocation_load <= 0.9
            && self.budget_load <= 0.9
            && self.maintainer != MaintainerState::Stopped
            && self.last_persist_error.is_none()
    }
}

impl Shared {
    /// Wall time of a time in whole seconds since the bouncer started.
    pub(crate) fn wall_at(&self, secs: u32) -> SystemTime {
        self.start_wall + Duration::from_secs(u64::from(secs))
    }

    pub(crate) fn record(&self, h: &Held) -> BanRecord {
        BanRecord {
            id: BanId::from_raw(h.id),
            key: h.key,
            until: (h.until != 0).then(|| self.wall_at(h.until)),
            issued: self.wall_at(h.issued),
            actor: h.actor,
            reason: h.reason,
            offences: h.offences,
            origin: self.origin_of(h.id),
        }
    }

    /// The node a ban id came from, when it is not this one.
    pub(crate) fn origin_of(&self, id: u64) -> Option<NodeId> {
        let node = (id >> 48) as u16;
        (node != 0 && Some(NodeId(node)) != self.node).then_some(NodeId(node))
    }
}

impl Bouncer {
    /// Counter totals, summed over every shard.
    ///
    /// With the `metrics` feature only.
    #[cfg(feature = "metrics")]
    #[must_use]
    pub fn metrics(&self) -> crate::metrics::MetricsSnapshot {
        let shared = self.shared();
        let mut m = crate::metrics::MetricsSnapshot::default();
        m.add(&shared.meters);
        for shard in self.shards() {
            m.add(&shard.meters);
        }
        let (bans, admin) = shared.bans.counts();
        m.bans_active = u64::from(bans) + u64::from(admin);
        m.bans_expired += shared.bans.expired_total();
        m.bans_evicted += shared.bans.evicted_total();
        m.journal_queue = u64::from(shared.journal_backlog());
        m
    }

    /// Everything bouncer knows about one key: whether the door (or the
    /// bind, for an identity key) would let it in now, every ban that
    /// covers it including wider prefixes, the allow entry, budget and strike
    /// state, offender history, the shared-address flag, and live tickets.
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::{BanSpec, Bouncer, SessionKey};
    /// let bouncer = Bouncer::new();
    /// let session = SessionKey::from_digest([5; 16]);
    /// assert!(bouncer.explain(session).admitted);
    /// bouncer.ban(BanSpec::key(session))?;
    /// let why = bouncer.explain(session);
    /// assert!(!why.admitted);
    /// assert_eq!(why.bans[0].key, bouncer_io::BanKey::Session(session));
    /// # Ok::<(), bouncer_io::BouncerError>(())
    /// ```
    #[must_use]
    pub fn explain(&self, key: impl Into<BanKey>) -> Explanation {
        let shared = self.shared();
        let key = key.into().normalized();
        let now = shared.now();
        let secs = now.secs();
        let mut bans: Vec<BanRecord> = shared
            .bans
            .held_covering(&key, secs)
            .iter()
            .map(|h| shared.record(h))
            .collect();
        bans.sort_by_key(|b| b.id);
        let addr = match key {
            BanKey::Address(a) => Some(a),
            _ => None,
        };
        let allow = match key {
            BanKey::Address(a) => shared.allow.with(|s| allow::lookup(s, a)),
            BanKey::Prefix(c) | BanKey::FingerprintIn(_, c) => shared.allow.with(|s| {
                let mut found = None;
                s.find_covering_map(&c, |k| {
                    if *k == AllowKind::Immune {
                        return Some(AllowKind::Immune);
                    }
                    found = Some(*k);
                    None
                })
                .or(found)
            }),
            _ => None,
        };
        let admitted = match addr {
            Some(a) => !matches!(
                shared.judge(a, Provenance::Socket, now),
                Judgement::Refuse(_)
            ),
            None => allow == Some(AllowKind::Immune) || bans.is_empty(),
        };
        let mut budgets = Vec::new();
        if let Some(a) = addr {
            budgets.extend(shared.budgets.state(a, now));
        }
        if let BanKey::Tenant(t) = key {
            if let Some(limit) = shared.identity.tenant_limit() {
                let used = shared.identity.tenant_in_flight(t.0);
                budgets.push(BudgetState {
                    class: "tenant.in_flight",
                    key,
                    remaining: limit.saturating_sub(used),
                    retry_after: None,
                });
            }
        }
        let strikes = strike_states(shared, &key, secs);
        let target = match key {
            BanKey::Address(a) => Some(Target::Source(Cidr::host(a))),
            BanKey::Prefix(c) => Some(Target::Source(c)),
            BanKey::Session(k) => Some(Target::Session(k)),
            BanKey::Account(k) => Some(Target::Account(k)),
            BanKey::Tenant(k) => Some(Target::Tenant(k)),
            BanKey::Fingerprint(k) | BanKey::FingerprintIn(k, _) => Some(Target::Fingerprint(k)),
        };
        let live_tickets = target.map_or(0, |t| {
            shared
                .registry
                .cells
                .iter()
                .filter(|cell| {
                    cell.state.load(crate::sync::Ordering::Acquire) & F_LIVE != 0
                        && maintain::matches_target(cell, &t)
                        && match key {
                            BanKey::FingerprintIn(_, c) => {
                                crate::ticket::source_of(cell).is_some_and(|a| c.contains(a))
                            }
                            _ => true,
                        }
                })
                .count() as u32
        });
        Explanation {
            key,
            admitted,
            allow,
            bans,
            offender: shared.offender_record(&key, secs),
            budgets,
            strikes,
            shared_source: addr.is_some_and(|a| shared.is_shared_source(a, secs)),
            live_tickets,
        }
    }

    /// A filtered, paged listing of bans, ordered by id. Each page is a
    /// consistent snapshot.
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::{Bouncer, Filter, Page};
    /// let bouncer = Bouncer::new();
    /// for i in 1..=5u8 {
    ///     bouncer.ban(std::net::IpAddr::from([198, 51, 100, i]))?;
    /// }
    /// bouncer.ban("2001:db8:1::/48".parse::<bouncer_io::Cidr>()?)?;
    /// let mut page = Page::first(2);
    /// let mut seen = 0;
    /// loop {
    ///     let listing = bouncer.list(&Filter::all().within("198.51.100.0/24".parse()?), page);
    ///     assert_eq!(listing.total, 5);
    ///     seen += listing.items.len();
    ///     match listing.next { Some(next) => page = next, None => break }
    /// }
    /// assert_eq!(seen, 5);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub fn list(&self, filter: &Filter, page: Page) -> Listing {
        let shared = self.shared();
        let secs = shared.now().secs();
        let mut all: Vec<BanRecord> = shared
            .bans
            .held_all(secs)
            .iter()
            .map(|h| shared.record(h))
            .filter(|r| filter.matches(r))
            .collect();
        all.sort_by_key(|r| r.id);
        let total = all.len() as u64;
        let limit = usize::from(page.limit.clamp(1, MAX_PAGE));
        let mut rest = all.into_iter().filter(|r| r.id.get() > page.after);
        let items: Vec<BanRecord> = rest.by_ref().take(limit).collect();
        let next = match (rest.next(), items.last()) {
            (Some(_), Some(last)) => Some(Page {
                after: last.id.get(),
                limit: page.limit,
            }),
            _ => None,
        };
        Listing { items, next, total }
    }

    /// Compiles a new allow list and swaps it in whole; readers never wait.
    /// Existing address, prefix, and compound fingerprint bans inside the
    /// new immune entries are lifted, each with a `ban.lifted` event.
    /// Tickets of newly immune sources are not revoked.
    ///
    /// # Errors
    ///
    /// `Config(AllowListTooLarge)` past 65,536 entries.
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::{AllowList, Bouncer};
    /// let bouncer = Bouncer::new();
    /// bouncer.ban("10.20.3.4".parse::<std::net::IpAddr>()?)?;
    /// bouncer.replace_allow(AllowList::new().immune("10.20.0.0/16".parse()?, "own infrastructure"))?;
    /// assert!(bouncer.door("10.20.3.4".parse()?).is_ok());
    /// assert!(bouncer.ban("10.20.3.4".parse::<std::net::IpAddr>()?).is_err());   // AllowListed
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn replace_allow(&self, list: AllowList) -> Result<(), BouncerError> {
        let shared = self.shared();
        let set = list.compile()?;
        // Swap first: a ban racing this call is checked against the new list.
        shared.allow.store(set);
        let lifted = shared.bans.lift_covered(|c| shared.immune_covers(c));
        for h in &lifted {
            Emit {
                actor: Actor::App,
                reason: Reason::ADMIN,
                subject: subject_of_key(&h.key),
                reference: shared.reference(h.id),
                ..Emit::new(signals::BAN_LIFTED)
            }
            .send(shared);
        }
        crate::metrics::meter!(shared.meters, bans_lifted, lifted.len() as u32);
        shared.after_lift(&lifted);
        Ok(())
    }

    /// Table loads, registry use, detached tickets, the journal backlog, the
    /// last persistence failure, and the maintainer's state.
    #[must_use]
    pub fn health(&self) -> Health {
        let shared = self.shared();
        let (mut live, mut detached) = (0u32, 0u32);
        for cell in shared.registry.cells.iter() {
            let st = cell.state.load(crate::sync::Ordering::Relaxed);
            if st & F_LIVE != 0 {
                live += 1;
                if st & F_DETACHED != 0 {
                    detached += 1;
                }
            }
        }
        let load = |n: u32, cap: u32| if cap == 0 { 0.0 } else { n as f32 / cap as f32 };
        let (bans, _) = shared.bans.counts();
        Health {
            tickets_live: live,
            tickets_capacity: shared.tickets_capacity,
            tickets_detached: detached,
            ban_load: load(bans, shared.bans.capacity()),
            revocation_load: load(shared.revocations.live(), shared.revocations.capacity()),
            budget_load: shared.budgets.load().max(shared.identity.load()),
            journal_backlog: shared.journal_backlog(),
            last_persist_error: shared.last_persist_error(),
            maintainer: shared.maintenance.state(),
            posture: shared.posture(),
        }
    }
}

/// Strike counters of a key with strikes in their window.
fn strike_states(shared: &Shared, key: &BanKey, now_secs: u64) -> Vec<StrikeState> {
    let counters = &shared.counters;
    let mut out = Vec::new();
    for kind in StrikeKind::BUILT_IN {
        let k = match *key {
            BanKey::Address(a) => counters.source_key(kind, a),
            BanKey::Session(s) => {
                let (k0, k1) = s.words();
                counters.identity_key(kind, 1, k0, k1)
            }
            BanKey::Account(a) => counters.identity_key(kind, 2, (a.0 >> 64) as u64, a.0 as u64),
            _ => return out,
        };
        let count = counters.peek(&shared.strikes, kind, k, now_secs);
        if count > 0 {
            out.push(StrikeState {
                kind,
                count,
                threshold: shared.strikes.threshold(kind),
                mode: shared.enforcement.mode(kind, shared.posture()),
            });
        }
    }
    out
}
