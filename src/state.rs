//! Where ban memory meets persistence and sharing: every state change
//! becomes a record for the journal and the outbound log; loading and
//! importing put records back.

use core::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{
    bans::{
        BanId, Guards, LiftSpec, Lifted, Own, offenders::Offence, restore::Restore, view::Held,
    },
    bouncer::{Bouncer, Shared},
    codec::{Envelope, Rec},
    directive::{Actor, ActorKind, Reason},
    error::{BouncerError, ImportError, PersistError},
    events::{Emit, signals},
    keys::BanKey,
    ledger::{Applied, Contribution, Ledger, Scope},
    persist::{self, Header, LoadFailure, Persist, Persistence, State},
    revoke::{RevokeMode, Target},
    share::{Delta, ImportReport, Sequence},
    time::Now,
    verdict::DenialCode,
};

fn unix(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// The later of two Unix-second ends; 0 (permanent) above all.
fn later(a: u32, b: u32) -> u32 {
    if a == 0 || b == 0 { 0 } else { a.max(b) }
}

fn lock(m: &std::sync::Mutex<Ledger>) -> std::sync::MutexGuard<'_, Ledger> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// How loaded times are counted.
struct LoadCtx {
    now_wall: u64,
    now_secs: u64,
    /// Remaining time is counted from here: now, or the last save when a
    /// large forward jump is kept strictly.
    base: u64,
    full: u32,
}

impl Shared {
    fn origin(&self) -> u16 {
        self.node.map_or(0, |n| n.0)
    }

    fn wall_ms(&self) -> u64 {
        self.wall()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64)
    }

    /// Whether any record would be kept: persistence, or a node to share.
    fn recording(&self) -> bool {
        self.persist.is_some() || self.node.is_some()
    }

    /// Records a local change: queued for the journal (`persist`) and the
    /// outbound log (`share`, when this node has an id).
    pub(crate) fn log(&self, rec: Rec, persist: bool, share: bool) {
        if !self.recording() {
            return;
        }
        let env = Envelope {
            origin: self.origin(),
            seq: self.share.next_seq(),
            rec,
        };
        self.log_env(env, persist, share);
    }

    fn log_env(&self, env: Envelope, persist: bool, share: bool) {
        if persist {
            if let Some(p) = &self.persist {
                if !p.enqueue(env) {
                    Emit {
                        reason: Reason::ADMIN,
                        ..Emit::new(signals::PERSIST_FAILED)
                    }
                    .send(self);
                } else if p.backlog() == 1 {
                    self.maintenance.wake();
                }
            }
        }
        if share && self.node.is_some() {
            self.share.push(env);
        }
    }

    fn ban_rec(&self, h: &Held, stamp: u64) -> Rec {
        Rec::Ban {
            key: h.key,
            until: if h.until == 0 {
                0
            } else {
                unix(self.wall_at(h.until))
            },
            issued: unix(self.wall_at(h.issued)),
            length: if h.until == 0 {
                0
            } else {
                u64::from(h.until.saturating_sub(h.issued)).max(1)
            },
            actor: h.actor.code(),
            reason: h.reason.code(),
            offences: h.offences,
            id: h.id,
            stamp,
        }
    }

    /// Records the ban now stored under `key`, and its offender record.
    pub(crate) fn log_ban(&self, key: &BanKey) {
        if !self.recording() {
            return;
        }
        let secs = self.now().secs();
        let Some(h) = self.bans.held_exact(key, secs) else {
            return;
        };
        let stamp = self.share.stamp(self.wall_ms());
        self.log(self.ban_rec(&h, stamp), true, true);
        if let Some(o) = self.bans.offender(key, secs) {
            self.log(
                Rec::Offence {
                    key: h.key,
                    score: o.score,
                    last: unix(self.wall_at(o.last)),
                },
                true,
                true,
            );
        }
    }

    /// Records a lift: a tombstone that wins over older bans on every node.
    pub(crate) fn log_lift(&self, key: &BanKey, actor: Actor) {
        let stamp = self.share.stamp(self.wall_ms());
        self.log(
            Rec::Lift {
                key: key.normalized(),
                stamp,
                actor: actor.kind().code(),
                all: true,
            },
            true,
            true,
        );
    }

    /// Seeds the sharing sequence numbers past every earlier run.
    pub(crate) fn seed_sequences(&self) {
        if self.node.is_some() {
            self.share.seed(self.share.stamp(self.wall_ms()));
        }
    }

    /// How times are counted now.
    fn ctx_now(&self) -> LoadCtx {
        let now_wall = unix(self.wall());
        LoadCtx {
            now_wall,
            now_secs: self.now().secs(),
            base: now_wall,
            full: 0,
        }
    }

    /// One origin's ban, from its record. Origin 0 (a ban stored before this
    /// node had an id) is this node's.
    fn contribution(&self, origin: u16, rec: &Rec) -> Option<(BanKey, Contribution)> {
        let Rec::Ban {
            key,
            until,
            issued,
            length,
            actor,
            reason,
            offences,
            id,
            stamp,
        } = *rec
        else {
            return None;
        };
        let origin = if origin == 0 { self.origin() } else { origin };
        let secs = |v: u64| u32::try_from(v).unwrap_or(u32::MAX);
        Some((
            key.normalized(),
            Contribution {
                origin,
                stamp,
                until: secs(until),
                issued: secs(issued),
                length: secs(length),
                actor,
                reason,
                offences,
                id,
            },
        ))
    }

    fn contribution_rec(key: &BanKey, c: &Contribution) -> Rec {
        Rec::Ban {
            key: *key,
            until: u64::from(c.until),
            issued: u64::from(c.issued),
            length: u64::from(c.length),
            actor: c.actor,
            reason: c.reason,
            offences: c.offences,
            id: c.id,
            stamp: c.stamp,
        }
    }

    /// Makes the ban table entry under `key` the ledger's merge of every
    /// origin's ban (or removes it). `Ok(true)` when the key is banned after.
    fn sync_key(
        &self,
        ledger: &mut Ledger,
        key: &BanKey,
        ctx: &LoadCtx,
    ) -> Result<bool, BouncerError> {
        let Some(c) = ledger.effective(key, ctx.now_wall) else {
            let _ = self.bans.remove_exact(key);
            return Ok(false);
        };
        let Some(r) = self.restore_of(*key, &c, ctx) else {
            let _ = self.bans.remove_exact(key);
            return Ok(false);
        };
        let allow = self.allow.load();
        let guards = Guards {
            immune: &allow,
            proxies: &self.proxies,
        };
        // A ban the insert took out leaves the ledger too, so it cannot come
        // back with a later merge or a snapshot.
        if let Some((gone, evicted)) = self.bans.replace(&r, &guards, ctx.now_secs)? {
            ledger.forget(&gone);
            if evicted {
                self.log(Rec::Remove { key: gone }, true, false);
            }
            Emit {
                subject: crate::bouncer::subject_of_key(&gone),
                ..Emit::new(if evicted {
                    signals::BAN_EVICTED
                } else {
                    signals::BAN_EXPIRED
                })
            }
            .send(self);
        }
        Ok(true)
    }

    /// Records this node's own ban (sharing nodes: in the ledger, then the
    /// table follows; others: the stored ban as it is).
    pub(crate) fn record_ban(&self, key: &BanKey, id: BanId, own: Option<&Own>) {
        let (Some(m), Some(own)) = (&self.ledger, own) else {
            if own.is_some() {
                self.log_ban(key);
            }
            return;
        };
        let node = self.origin();
        let key = key.normalized();
        let ctx = self.ctx_now();
        let mut l = lock(m);
        let secs = |v: u64| u32::try_from(v).unwrap_or(u32::MAX);
        let until = if own.until == 0 {
            0
        } else {
            secs(unix(self.wall_at(own.until))).max(1)
        };
        let mut c = Contribution {
            origin: node,
            stamp: self.share.stamp(self.wall_ms()),
            until,
            issued: secs(unix(self.wall_at(own.issued))),
            length: if own.until == 0 {
                0
            } else {
                own.until.saturating_sub(own.issued).max(1)
            },
            actor: own.actor.code(),
            reason: own.reason.code(),
            offences: own.offences,
            // The stored ban's id may be another node's (a merge): this
            // node's ban has an id of its own.
            id: if id.get() >> 48 == u64::from(node) {
                id.get()
            } else {
                self.bans.new_id().get()
            },
        };
        // A ban never shortens this node's earlier one still in force.
        if let Some(p) = l.own(&key, node, ctx.now_wall) {
            c.until = later(p.until, c.until);
            c.length = if c.until == 0 {
                0
            } else {
                p.length.max(c.length)
            };
            c.offences = c.offences.max(p.offences);
            c.id = p.id;
        }
        let _ = l.ban(key, c, ctx.now_wall);
        let _ = self.sync_key(&mut l, &key, &ctx);
        drop(l);
        self.log(Self::contribution_rec(&key, &c), true, true);
        let secs = ctx.now_secs;
        if let Some(o) = self.bans.offender(&key, secs) {
            self.log(
                Rec::Offence {
                    key,
                    score: o.score,
                    last: unix(self.wall_at(o.last)),
                },
                true,
                true,
            );
        }
    }

    /// Children folded into an escalated parent: on a sharing node, a lift
    /// of this node's own ban on each (other nodes see the fold too); other
    /// nodes' bans on a child stay.
    pub(crate) fn record_folded(&self, folded: &[BanKey]) {
        let Some(m) = &self.ledger else {
            self.log_removed(folded);
            return;
        };
        let node = self.origin();
        let ctx = self.ctx_now();
        for key in folded {
            let key = key.normalized();
            let stamp = self.share.stamp(self.wall_ms());
            let mut l = lock(m);
            let removed = l.lift(key, Scope::Origin(node), stamp, ctx.now_wall);
            let _ = self.sync_key(&mut l, &key, &ctx);
            drop(l);
            if removed > 0 {
                self.log(
                    Rec::Lift {
                        key,
                        stamp,
                        actor: ActorKind::Local.code(),
                        all: false,
                    },
                    true,
                    true,
                );
            } else {
                self.log(Rec::Remove { key }, true, false);
            }
        }
    }

    /// Bans removed here without a lift (evicted, expired, allow-listed):
    /// out of the ledger too.
    pub(crate) fn forget_shared(&self, keys: &[BanKey]) {
        if let Some(m) = &self.ledger {
            let mut l = lock(m);
            for key in keys {
                l.forget(&key.normalized());
            }
        }
    }

    /// A lift on a sharing node. An administrator's (or the application's)
    /// lift covers every origin's ban here; an automated actor's only this
    /// node's. Other nodes apply it over a node channel to this node's bans
    /// only (T-17); delivered through the administration channel
    /// (`import(.., Actor::Admin(..))`) it covers every origin there too.
    pub(crate) fn lift_shared(&self, spec: &LiftSpec) -> Result<Lifted, BouncerError> {
        let Some(m) = &self.ledger else {
            return self.bans.lift(spec);
        };
        let key = spec.key.normalized();
        let scope = if spec.actor.is_automated() {
            Scope::Origin(self.origin())
        } else {
            Scope::All
        };
        let ctx = self.ctx_now();
        let stamp = self.share.stamp(self.wall_ms());
        let mut l = lock(m);
        // Nothing to lift: nothing is recorded either (a lift no other node
        // hears of must not hold back bans here).
        if !l.would_lift(&key, scope, stamp, ctx.now_wall) {
            return Err(BouncerError::NotFound);
        }
        let removed = l.lift(key, scope, stamp, ctx.now_wall);
        let lifted = if l.effective(&key, ctx.now_wall).is_some() {
            let _ = self.sync_key(&mut l, &key, &ctx);
            Lifted {
                removed,
                tombstone: self.bans.new_id(),
            }
        } else {
            match self.bans.lift(spec) {
                Ok(t) => Lifted { removed, ..t },
                Err(_) => Lifted {
                    removed,
                    tombstone: self.bans.new_id(),
                },
            }
        };
        drop(l);
        self.log(
            Rec::Lift {
                key,
                stamp,
                actor: spec.actor.kind().code(),
                all: scope == Scope::All,
            },
            true,
            true,
        );
        Ok(lifted)
    }

    /// Records bans removed without a lift (folded, evicted, allow-listed).
    pub(crate) fn log_removed(&self, keys: &[BanKey]) {
        for &key in keys {
            self.log(Rec::Remove { key }, true, false);
        }
    }

    /// Records a revocation for other nodes.
    pub(crate) fn log_revoke(
        &self,
        target: &Target,
        mode: RevokeMode,
        keep_connection: bool,
        code: DenialCode,
        actor: Actor,
        reason: Reason,
    ) {
        if self.node.is_none() || matches!(target, Target::Connection(_) | Target::Request(_)) {
            return;
        }
        let stamp = self.share.stamp(self.wall_ms());
        self.log(
            Rec::Revoke {
                target: *target,
                code: code.number() as u8,
                keep_connection,
                eject_now: mode == RevokeMode::EjectNow,
                actor: actor.kind().code(),
                reason: reason.code(),
                stamp,
            },
            false,
            true,
        );
    }

    /// The full state as records: bans, offender records, and (sharing
    /// nodes) lifts. `export`: for another node, which takes from a channel
    /// only that node's own records, so other origins' are left out.
    fn state_records(&self, export: bool) -> Vec<Envelope> {
        let secs = self.now().secs();
        let origin = self.origin();
        let mut out = Vec::new();
        if let Some(m) = &self.ledger {
            let (bans, lifts) = lock(m).dump(unix(self.wall()));
            for (key, c) in bans {
                if export && c.origin != origin {
                    continue;
                }
                out.push(Envelope {
                    origin: c.origin,
                    seq: 0,
                    rec: Self::contribution_rec(&key, &c),
                });
            }
            for (key, scope, stamp) in lifts {
                let (from, all) = match scope {
                    Scope::All => (origin, true),
                    Scope::Origin(o) => (o, false),
                };
                if export && from != origin {
                    continue;
                }
                out.push(Envelope {
                    origin: from,
                    seq: 0,
                    rec: Rec::Lift {
                        key,
                        stamp,
                        actor: ActorKind::Admin.code(),
                        all,
                    },
                });
            }
        } else {
            for h in self.bans.held_all(secs) {
                let from = (h.id >> 48) as u16;
                let stamp = (unix(self.wall_at(h.issued)) * 1000) << 16;
                out.push(Envelope {
                    origin: if from == 0 { origin } else { from },
                    seq: h.id,
                    rec: self.ban_rec(&h, stamp),
                });
            }
        }
        for (key, o) in self.bans.offences_all(secs) {
            out.push(Envelope {
                origin,
                seq: 0,
                rec: Rec::Offence {
                    key,
                    score: o.score,
                    last: unix(self.wall_at(o.last)),
                },
            });
        }
        out
    }

    /// Puts one loaded ban back (a node that does not share). `Ok(false)`
    /// when it has expired.
    fn put_ban(&self, rec: &Rec, origin: u16, ctx: &LoadCtx) -> Result<bool, BouncerError> {
        let Some((key, c)) = self.contribution(origin, rec) else {
            return Ok(false);
        };
        let Some(r) = self.restore_of(key, &c, ctx) else {
            return Ok(false);
        };
        let allow = self.allow.load();
        let guards = Guards {
            immune: &allow,
            proxies: &self.proxies,
        };
        self.bans.restore(&r, &guards, ctx.now_secs)?;
        Ok(true)
    }

    /// A ban in this bouncer's time: remaining time from its wall times;
    /// `None` when it has ended.
    fn restore_of(&self, key: BanKey, c: &Contribution, ctx: &LoadCtx) -> Option<Restore> {
        let Contribution {
            actor,
            reason,
            offences,
            id,
            origin,
            ..
        } = *c;
        let (until, issued, length) =
            (u64::from(c.until), u64::from(c.issued), u64::from(c.length));
        let local_until = if until == 0 {
            0
        } else {
            // A clock stepped backwards past the issue time keeps the
            // original length from now; nothing ever lasts longer than it
            // did when it was issued.
            let mut remaining = if ctx.now_wall < issued {
                length
            } else {
                until.saturating_sub(ctx.base)
            };
            if length > 0 {
                remaining = remaining.min(length);
            }
            if remaining == 0 {
                return None;
            }
            u32::try_from(ctx.now_secs.saturating_add(remaining)).unwrap_or(u32::MAX)
        };
        let local_issued = ctx
            .now_secs
            .saturating_sub(ctx.now_wall.saturating_sub(issued));
        let id = if id >> 48 == 0 && origin != 0 && origin != self.origin() {
            (u64::from(origin) << 48) | (id & ((1 << 48) - 1))
        } else {
            id
        };
        Some(Restore {
            key,
            until: local_until,
            issued: u32::try_from(local_issued).unwrap_or(u32::MAX),
            actor: ActorKind::from_code(actor),
            reason: Reason::from_code(reason),
            offences,
            id,
        })
    }

    fn put_offence(&self, key: &BanKey, score: f32, last: u64, ctx: &LoadCtx) {
        let last_local = if ctx.now_wall < last {
            ctx.now_secs
        } else {
            ctx.now_secs.saturating_sub(ctx.now_wall - last)
        };
        self.bans.set_offence(
            key,
            Offence {
                score,
                last: u32::try_from(last_local).unwrap_or(u32::MAX),
            },
            ctx.now_secs,
        );
    }

    /// Applies one persisted record.
    fn load_record(&self, env: &Envelope, ctx: &mut LoadCtx) {
        if let Some(m) = &self.ledger {
            self.load_shared(m, env, ctx);
            return;
        }
        match env.rec {
            Rec::Ban { .. } => {
                if let Err(BouncerError::BanTableFull { .. }) =
                    self.put_ban(&env.rec, env.origin, ctx)
                {
                    ctx.full += 1;
                }
            }
            Rec::Lift { key, stamp, .. } => {
                self.share.observe(stamp);
                let _ = self.bans.remove_exact(&key);
            }
            Rec::Remove { key } => {
                let _ = self.bans.remove_exact(&key);
            }
            Rec::Offence { key, score, last } => self.put_offence(&key, score, last, ctx),
            Rec::Revoke { .. } => {}
        }
    }

    /// Applies one persisted record on a sharing node: its own records, so
    /// every lift keeps the scope it was recorded with.
    fn load_shared(&self, m: &std::sync::Mutex<Ledger>, env: &Envelope, ctx: &mut LoadCtx) {
        match env.rec {
            Rec::Ban { stamp, .. } => {
                self.share.observe(stamp);
                let Some((key, c)) = self.contribution(env.origin, &env.rec) else {
                    return;
                };
                let mut l = lock(m);
                if l.ban(key, c, ctx.now_wall) == Applied::Changed {
                    if let Err(BouncerError::BanTableFull { .. }) = self.sync_key(&mut l, &key, ctx)
                    {
                        l.forget(&key);
                        ctx.full += 1;
                    }
                }
            }
            Rec::Lift {
                key, stamp, all, ..
            } => {
                self.share.observe(stamp);
                let origin = if env.origin == 0 {
                    self.origin()
                } else {
                    env.origin
                };
                let scope = if all {
                    Scope::All
                } else {
                    Scope::Origin(origin)
                };
                let key = key.normalized();
                let mut l = lock(m);
                let _ = l.lift(key, scope, stamp, ctx.now_wall);
                let _ = self.sync_key(&mut l, &key, ctx);
            }
            Rec::Remove { key } => {
                let key = key.normalized();
                let mut l = lock(m);
                l.forget(&key);
                let _ = self.bans.remove_exact(&key);
            }
            Rec::Offence { key, score, last } => self.put_offence(&key, score, last, ctx),
            Rec::Revoke { .. } => {}
        }
    }

    /// Loads persisted state before the first door check.
    pub(crate) fn load_persisted(
        &self,
        policy: LoadFailure,
        max_wall_jump: Duration,
        strict_wall_jump: bool,
    ) -> Result<(), PersistError> {
        let Some(p) = &self.persist else {
            return Ok(());
        };
        let mut store = p
            .store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let loaded = (|| -> Result<Option<_>, PersistError> {
            let Some(bytes) = store.load()? else {
                if !store.journal()?.is_empty() {
                    // A journal with no snapshot: the snapshot was lost.
                    return Err(PersistError::Truncated);
                }
                return Ok(None);
            };
            let (h, records, tag) = persist::decode_snapshot(&bytes, p.key.as_ref())?;
            // (An older format is rewritten below, after loading.)
            let journal = store.journal()?;
            let chain = if p.key.is_some() { tag } else { [0; 32] };
            let rep = persist::replay(&journal, h.epoch, p.key.as_ref(), chain);
            Ok(Some((h, records, rep, journal.len() as u64)))
        })();
        let mut state = p
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.last_flush = self.now();
        let now_wall = unix(self.wall());
        match loaded {
            Ok(Some((h, records, rep, journal_len))) => {
                self.share.mark_partial();
                let last_wall = rep.last_wall.unwrap_or(h.created).max(h.created);
                let forward = now_wall.saturating_sub(last_wall);
                let jumped = now_wall < last_wall || forward > max_wall_jump.as_secs();
                if jumped {
                    Emit {
                        reason: Reason::ADMIN,
                        ..Emit::new(signals::PERSIST_WALL_JUMP)
                    }
                    .send(self);
                }
                let mut ctx = LoadCtx {
                    now_wall,
                    now_secs: self.now().secs(),
                    base: if strict_wall_jump && forward > max_wall_jump.as_secs() {
                        last_wall
                    } else {
                        now_wall
                    },
                    full: 0,
                };
                self.share.observe(h.hlc);
                for env in records.iter().chain(rep.records.iter()) {
                    self.load_record(env, &mut ctx);
                }
                if ctx.full > 0 && policy == LoadFailure::Refuse {
                    return Err(PersistError::TooLarge);
                }
                state.epoch = h.epoch;
                state.chain = rep.chain;
                state.journal_bytes = rep.bytes;
                if rep.lost > 0 || ctx.full > 0 {
                    Emit {
                        reason: Reason::ADMIN,
                        count: u32::try_from(rep.lost).unwrap_or(u32::MAX),
                        ..Emit::new(signals::PERSIST_FAILED)
                    }
                    .send(self);
                }
                // A damaged or foreign tail would swallow new appends, and a
                // snapshot of an older format must not get newer records
                // appended to it: start a clean journal on a new snapshot.
                if rep.bytes != journal_len || h.format < persist::SNAPSHOT_FORMAT {
                    self.compact_locked(p, &mut **store, &mut state)?;
                }
            }
            Ok(None) => {
                state.epoch = self.wall_ms();
                self.compact_locked(p, &mut **store, &mut state)?;
            }
            Err(e) => {
                if policy == LoadFailure::Refuse {
                    return Err(e);
                }
                Emit {
                    reason: Reason::ADMIN,
                    ..Emit::new(signals::PERSIST_FAILED)
                }
                .send(self);
                state.epoch = self.wall_ms();
                self.compact_locked(p, &mut **store, &mut state)?;
            }
        }
        Ok(())
    }

    /// Writes the full state as a new snapshot of the next epoch and empties
    /// the journal.
    fn compact_locked(
        &self,
        p: &Persist,
        store: &mut dyn Persistence,
        state: &mut State,
    ) -> Result<(), PersistError> {
        let epoch = state.epoch.wrapping_add(1).max(1);
        let header = Header {
            format: persist::SNAPSHOT_FORMAT,
            created: unix(self.wall()),
            epoch,
            node: self.origin(),
            hlc: self.share.clock(),
        };
        let (bytes, tag) =
            persist::encode_snapshot(&header, &self.state_records(false), p.key.as_ref());
        match store.replace_snapshot(&bytes) {
            Ok(()) => {
                state.epoch = epoch;
                state.chain = tag;
                state.journal_bytes = 0;
                state.failed = None;
                Ok(())
            }
            Err(e) => {
                if let PersistError::Io(kind) = e {
                    state.failed = Some(kind);
                }
                Err(e)
            }
        }
    }

    /// Writes queued records when due (or now, with `force`); compacts the
    /// journal past its limit. Returns the records written.
    pub(crate) fn persist_flush(&self, now: Now, force: bool) -> Result<u32, PersistError> {
        let Some(p) = &self.persist else {
            return Ok(0);
        };
        if !force && p.due().is_none_or(|d| d > now) {
            return Ok(0);
        }
        let mut state = p
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let records = p.drain();
        let n = records.len() as u32;
        let mut store = p
            .store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.failed.is_some() {
            // A failed append may have left a torn batch: start clean.
            if let Err(e) = self.compact_locked(p, &mut **store, &mut state) {
                p.requeue(records);
                state.last_flush = now;
                self.report_persist_failure();
                return Err(e);
            }
        }
        if !records.is_empty() {
            let (bytes, chain) = persist::encode_batch(
                state.epoch,
                unix(self.wall()),
                &records,
                p.key.as_ref(),
                &state.chain,
            );
            let written = store.append(&bytes).and_then(|()| store.sync());
            if let Err(e) = written {
                if let PersistError::Io(kind) = e {
                    state.failed = Some(kind);
                } else {
                    state.failed = Some(std::io::ErrorKind::Other);
                }
                p.requeue(records);
                state.last_flush = now;
                drop(store);
                drop(state);
                self.report_persist_failure();
                return Err(e);
            }
            state.chain = chain;
            state.journal_bytes += bytes.len() as u64;
        }
        state.last_flush = now;
        if Persist::wants_compaction(&state) {
            self.compact_locked(p, &mut **store, &mut state)?;
        }
        Ok(n)
    }

    fn report_persist_failure(&self) {
        Emit {
            reason: Reason::ADMIN,
            ..Emit::new(signals::PERSIST_FAILED)
        }
        .send(self);
    }

    /// When the next persistence flush is due.
    pub(crate) fn persist_due(&self) -> Option<Now> {
        self.persist.as_ref().and_then(Persist::due)
    }
}

impl Bouncer {
    /// Writes and syncs every journal record queued so far. Call it before a
    /// planned shutdown (dropping the bouncer also tries).
    ///
    /// # Errors
    ///
    /// `Persist(..)` when the store fails.
    ///
    /// # Examples
    ///
    /// ```
    /// let bouncer = bouncer_io::Bouncer::new();
    /// bouncer.flush()?;   // no persistence configured: nothing to do
    /// # Ok::<(), bouncer_io::BouncerError>(())
    /// ```
    pub fn flush(&self) -> Result<(), BouncerError> {
        let shared = self.shared();
        shared.persist_flush(shared.now(), true)?;
        Ok(())
    }

    /// The records since `since` (bans, lifts, offender records,
    /// revocations), for another node. When `since` is older than the
    /// outbound log keeps, everything is exported instead.
    ///
    /// # Errors
    ///
    /// `NodeIdUnset` without [`BouncerBuilder::node`](crate::BouncerBuilder::node).
    pub fn export_delta(&self, since: Sequence) -> Result<Delta, BouncerError> {
        let shared = self.shared();
        let node = shared.node.ok_or(BouncerError::NodeIdUnset)?;
        match shared.share.since(since.get()) {
            Some((records, last)) => Ok(Delta::build(node.0, false, &records, last)),
            None => self.export_snapshot(),
        }
    }

    /// Everything, for a node that is joining: every ban, offender record,
    /// and lift tombstone.
    ///
    /// # Errors
    ///
    /// `NodeIdUnset` without [`BouncerBuilder::node`](crate::BouncerBuilder::node).
    pub fn export_snapshot(&self) -> Result<Delta, BouncerError> {
        let shared = self.shared();
        let node = shared.node.ok_or(BouncerError::NodeIdUnset)?;
        let records: Vec<(u64, Envelope)> = shared
            .state_records(true)
            .into_iter()
            .map(|e| (0, e))
            .collect();
        Ok(Delta::build(node.0, true, &records, shared.share.last()))
    }

    /// Merges a delta from another node. Any order and any repetition of
    /// delivery converges: each node's ban on a key is kept apart, the
    /// latest of one node's bans wins, a lift removes the bans stamped
    /// before it, and records seen before are skipped. Revocations reach the
    /// requests running here.
    ///
    /// From a node channel (`Actor::Channel(n)`), a lift applies only to
    /// node `n`'s own bans, and only lifts that node `n` made are taken
    /// (T-17). Delivered by an administrator (`Actor::Admin(..)` or
    /// `Actor::App`, for the administration channel), a lift made by an
    /// administrator covers every node's ban on the key, as it did where it
    /// was made.
    ///
    /// # Errors
    ///
    /// `NodeIdUnset` without [`BouncerBuilder::node`](crate::BouncerBuilder::node).
    /// `Import(RateLimited)` when a channel sends too many records per
    /// second. Refused records (allow-listed keys, clock skew, foreign
    /// lifts) are counted in `rejected` and reported as events.
    pub fn import(&self, delta: &Delta, from: Actor) -> Result<ImportReport, BouncerError> {
        let shared = self.shared();
        let ledger = shared.ledger.as_ref().ok_or(BouncerError::NodeIdUnset)?;
        let records = delta.records();
        let now = shared.now();
        if let (Actor::Channel(_), Some(rate)) = (from, &shared.share.channel_rate) {
            let now_d = Duration::from_nanos(now.as_nanos());
            let n = u32::try_from(records.len()).unwrap_or(u32::MAX).max(1);
            if rate.check_n_at(n, now_d).is_deny() {
                self.reject(ImportError::RateLimited);
                return Err(ImportError::RateLimited.into());
            }
        }
        let mut report = ImportReport::default();
        let now_wall = unix(shared.wall());
        let ctx = LoadCtx {
            now_wall,
            now_secs: now.secs(),
            base: now_wall,
            full: 0,
        };
        let skew_ms = u64::try_from(shared.max_clock_skew.as_millis()).unwrap_or(u64::MAX);
        let limit = shared.wall_ms().saturating_add(skew_ms);
        let own = shared.node.map(|n| n.0);
        let trusted = matches!(from, Actor::Admin(_) | Actor::App);
        for env in records {
            // A node channel carries only its own node's records (T-17): a
            // relayed or forged record of another origin is refused before
            // it is remembered as seen, so it cannot shadow the real one.
            let foreign = match from {
                Actor::Channel(n) => u64::from(env.origin) != n,
                _ => false,
            };
            if foreign || env.origin == 0 {
                report.rejected += 1;
                self.reject(if matches!(env.rec, Rec::Lift { .. }) {
                    ImportError::ForeignLift
                } else {
                    ImportError::ForeignOrigin
                });
                continue;
            }
            // An administrator's lift seen before over a node channel
            // (where it reached only its own node's bans) still applies in
            // full when an administrator delivers it; applying a lift again
            // changes nothing else.
            let full_lift = trusted && matches!(env.rec, Rec::Lift { all: true, .. });
            if Some(env.origin) == own
                || (!delta.is_full() && !full_lift && shared.share.seen(env.origin, env.seq))
            {
                report.duplicates += 1;
                continue;
            }
            // Remembered as seen only once it was not refused: a refused
            // record must not shadow a later delivery that is allowed (from
            // the administration channel, or after a fix at the sender).
            let rejected_before = report.rejected;
            'rec: {
                let stamp = match env.rec {
                    Rec::Ban { stamp, .. }
                    | Rec::Lift { stamp, .. }
                    | Rec::Revoke { stamp, .. } => Some(stamp),
                    _ => None,
                };
                if stamp.is_some_and(|s| s >> 16 > limit) {
                    report.rejected += 1;
                    self.reject(ImportError::ClockSkew);
                    break 'rec;
                }
                if let Some(s) = stamp {
                    shared.share.observe(s);
                }
                match env.rec {
                    Rec::Ban { key, .. } => {
                        let allow = shared.allow.load();
                        let guards = Guards {
                            immune: &allow,
                            proxies: &shared.proxies,
                        };
                        if shared.bans.check(&key, &guards).is_err() {
                            report.rejected += 1;
                            self.reject(ImportError::AllowListTouched);
                            break 'rec;
                        }
                        let Some((key, c)) = shared.contribution(env.origin, &env.rec) else {
                            break 'rec;
                        };
                        // A channel's ban is held to what its actor could set
                        // here, and never covers a whole address family.
                        let whole_family = matches!(key, BanKey::Prefix(p) if p.len() == 0);
                        if !trusted
                            && (whole_family
                                || !shared.bans.allowed_for(
                                    &key,
                                    ActorKind::from_code(c.actor),
                                    c.until == 0,
                                ))
                        {
                            report.rejected += 1;
                            self.reject(ImportError::NotAllowed);
                            break 'rec;
                        }
                        let mut l = lock(ledger);
                        match l.ban(key, c, ctx.now_wall) {
                            Applied::Superseded => {
                                report.superseded += 1;
                                break 'rec;
                            }
                            Applied::Full => {
                                report.rejected += 1;
                                self.reject(ImportError::NotAllowed);
                                break 'rec;
                            }
                            Applied::Changed => {}
                        }
                        match shared.sync_key(&mut l, &key, &ctx) {
                            Ok(_) => {
                                drop(l);
                                report.applied += 1;
                                // Journaled here; not passed on (each node sends
                                // its own records).
                                shared.log_env(env, true, false);
                            }
                            Err(_) => {
                                l.forget(&key);
                                report.rejected += 1;
                            }
                        }
                    }
                    Rec::Lift {
                        key,
                        stamp,
                        actor,
                        all,
                    } => {
                        let scope = if all && trusted {
                            Scope::All
                        } else {
                            Scope::Origin(env.origin)
                        };
                        let key = key.normalized();
                        let mut l = lock(ledger);
                        if all && !trusted && l.held_by_other(&key, env.origin, ctx.now_wall) {
                            // The lift covered other nodes' bans where it was
                            // made; here it reaches only its own node's.
                            report.rejected += 1;
                            self.reject(ImportError::ForeignLift);
                        }
                        let had = shared.bans.held_exact(&key, 0).is_some();
                        let _ = l.lift(key, scope, stamp, ctx.now_wall);
                        let banned = shared.sync_key(&mut l, &key, &ctx).unwrap_or(true);
                        drop(l);
                        if had && !banned {
                            Emit {
                                actor: from,
                                reason: Reason::IMPORTED,
                                subject: crate::bouncer::subject_of_key(&key),
                                ..Emit::new(signals::BAN_LIFTED)
                            }
                            .send(shared);
                        }
                        report.applied += 1;
                        // Journaled with the scope it had here; not passed on
                        // (other nodes take lifts only from the node that made
                        // them).
                        shared.log_env(
                            Envelope {
                                rec: Rec::Lift {
                                    key,
                                    stamp,
                                    actor,
                                    all: scope == Scope::All,
                                },
                                ..env
                            },
                            true,
                            false,
                        );
                    }
                    Rec::Offence { key, score, last } => {
                        shared.put_offence(&key, score, last, &ctx);
                        report.applied += 1;
                        shared.log_env(env, true, false);
                    }
                    Rec::Remove { .. } => report.superseded += 1,
                    Rec::Revoke {
                        target,
                        code,
                        keep_connection,
                        eject_now,
                        reason,
                        ..
                    } => {
                        let mode = if eject_now {
                            RevokeMode::EjectNow
                        } else {
                            RevokeMode::AtCheckpoint
                        };
                        let applied = self.revoke_with(
                            &target,
                            from,
                            Reason::from_code(reason),
                            mode,
                            keep_connection,
                            DenialCode::from_number(code),
                            None,
                        );
                        match applied {
                            Ok(_) | Err(BouncerError::RevocationTableFull { .. }) => {
                                report.revocations += 1;
                            }
                            Err(
                                BouncerError::AllowListed { .. } | BouncerError::TrustedProxyTarget,
                            ) => {
                                report.rejected += 1;
                                self.reject(ImportError::AllowListTouched);
                            }
                            Err(_) => report.rejected += 1,
                        }
                    }
                }
            }
            if report.rejected == rejected_before && !delta.is_full() {
                shared.share.remember(env.origin, env.seq);
            }
        }
        Ok(report)
    }

    fn reject(&self, why: ImportError) {
        let _ = why;
        Emit {
            reason: Reason::IMPORTED,
            ..Emit::new(signals::IMPORT_REJECTED)
        }
        .send(self.shared());
    }
}

#[cfg(all(test, not(bouncer_loom)))]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::{
        codec::{self, Writer, crc32c},
        persist::SNAPSHOT_MAGIC,
        share::NodeId,
    };

    /// The snapshot (if any) and the journal.
    type Files = (Option<Vec<u8>>, Vec<u8>);

    /// Snapshot and journal in memory, shared with the test.
    #[derive(Clone, Default)]
    struct Mem(Arc<Mutex<Files>>);

    impl Persistence for Mem {
        fn load(&mut self) -> Result<Option<Vec<u8>>, PersistError> {
            Ok(self.0.lock().unwrap().0.clone())
        }
        fn journal(&mut self) -> Result<Vec<u8>, PersistError> {
            Ok(self.0.lock().unwrap().1.clone())
        }
        fn append(&mut self, r: &[u8]) -> Result<(), PersistError> {
            self.0.lock().unwrap().1.extend_from_slice(r);
            Ok(())
        }
        fn sync(&mut self) -> Result<(), PersistError> {
            Ok(())
        }
        fn replace_snapshot(&mut self, s: &[u8]) -> Result<(), PersistError> {
            let mut g = self.0.lock().unwrap();
            g.0 = Some(s.to_vec());
            g.1.clear();
            Ok(())
        }
    }

    fn addr(s: &str) -> BanKey {
        BanKey::Address(s.parse().unwrap())
    }

    fn ban(key: BanKey, seq: u64) -> Vec<u8> {
        let mut out = Vec::new();
        assert!(codec::encode(
            &mut out,
            &Envelope {
                origin: 0,
                seq,
                rec: Rec::Ban {
                    key,
                    until: 0,
                    issued: 1_700_000_000,
                    length: 0,
                    actor: ActorKind::Admin.code(),
                    reason: Reason::ADMIN.code(),
                    offences: 0,
                    id: seq,
                    stamp: (1_700_000_000_000 + seq) << 16,
                },
            }
        ));
        out
    }

    /// A lift as format 1 wrote it (record type 2: key, stamp, actor).
    fn legacy_lift(key: BanKey, seq: u64) -> Vec<u8> {
        let mut out = Vec::new();
        assert!(codec::encode(
            &mut out,
            &Envelope {
                origin: 0,
                seq,
                rec: Rec::Lift {
                    key,
                    stamp: (1_700_000_100_000 + seq) << 16,
                    actor: ActorKind::Admin.code(),
                    all: false,
                },
            }
        ));
        // Re-frame without the scope byte, as type 2.
        let body_len = u32::from_le_bytes(out[..4].try_into().unwrap()) as usize;
        let mut body = out[4..4 + body_len - 1].to_vec();
        body[0] = 2;
        let mut framed = (body.len() as u32).to_le_bytes().to_vec();
        framed.extend_from_slice(&body);
        framed.extend_from_slice(&crc32c(&body).to_le_bytes());
        framed
    }

    /// A format-1 snapshot of `records` (epoch 7).
    fn snapshot_v1(records: &[Vec<u8>]) -> Vec<u8> {
        let mut out = SNAPSHOT_MAGIC.to_vec();
        let mut w = Writer(&mut out);
        w.u16(1);
        w.u16(0);
        w.u64(1_700_000_000);
        w.u64(7);
        w.u16(0);
        w.u64(0);
        w.u64(records.len() as u64);
        for r in records {
            out.extend_from_slice(r);
        }
        let len = out.len() as u64;
        Writer(&mut out).u64(len);
        let crc = crc32c(&out);
        Writer(&mut out).u32(crc);
        out
    }

    /// A format-1 journal batch of epoch 7.
    fn batch_v1(records: &[Vec<u8>]) -> Vec<u8> {
        let body: Vec<u8> = records.concat();
        let mut out = b"BNCJ".to_vec();
        let mut w = Writer(&mut out);
        w.u64(7);
        w.u64(1_700_000_200);
        w.u32(body.len() as u32);
        out.extend_from_slice(&body);
        let crc = crc32c(&out);
        Writer(&mut out).u32(crc);
        out
    }

    fn format_of(snapshot: &[u8]) -> u16 {
        u16::from_le_bytes([snapshot[4], snapshot[5]])
    }

    #[test]
    fn test_format_1_files_load_and_are_rewritten_as_format_2() {
        // A snapshot and journal in the format 0.6 wrote: three bans, and a
        // lift of the second in the journal. A node that does not share and
        // one that does read them the same, and rewrite them at once.
        for node in [None, Some(NodeId(4))] {
            let store = Mem::default();
            *store.0.lock().unwrap() = (
                Some(snapshot_v1(&[
                    ban(addr("192.0.2.1"), 1),
                    ban(addr("192.0.2.2"), 2),
                    ban(addr("192.0.2.3"), 3),
                ])),
                batch_v1(&[legacy_lift(addr("192.0.2.2"), 4)]),
            );
            let mut builder = Bouncer::builder().persistence(Box::new(store.clone()));
            if let Some(n) = node {
                builder = builder.node(n);
            }
            let b = builder.try_build().unwrap();
            assert!(b.door("192.0.2.1".parse().unwrap()).is_err(), "{node:?}");
            assert!(
                b.door("192.0.2.2".parse().unwrap()).is_ok(),
                "{node:?}: lifted"
            );
            assert!(b.door("192.0.2.3".parse().unwrap()).is_err(), "{node:?}");
            let (snap, journal) = store.0.lock().unwrap().clone();
            assert_eq!(format_of(&snap.unwrap()), persist::SNAPSHOT_FORMAT);
            assert!(journal.is_empty(), "a new journal on the new snapshot");
            drop(b);
            // And the rewritten files load again.
            let mut builder = Bouncer::builder().persistence(Box::new(store.clone()));
            if let Some(n) = node {
                builder = builder.node(n);
            }
            let b = builder.try_build().unwrap();
            assert!(b.door("192.0.2.1".parse().unwrap()).is_err());
            assert!(b.door("192.0.2.2".parse().unwrap()).is_ok());
        }
    }

    #[test]
    fn test_sharing_node_keeps_each_origin_across_a_restart() {
        // Node 1 holds node 2's and node 3's bans on one address. After a
        // restart it still has both, so node 2's lift leaves node 3's ban,
        // and node 3's lift ends it.
        let store = Mem::default();
        let one = || {
            Bouncer::builder()
                .node(NodeId(1))
                .persistence(Box::new(store.clone()))
                .try_build()
                .unwrap()
        };
        let two = Bouncer::builder().node(NodeId(2)).try_build().unwrap();
        let three = Bouncer::builder().node(NodeId(3)).try_build().unwrap();
        let a: std::net::IpAddr = "198.51.100.7".parse().unwrap();
        two.ban(a).unwrap();
        three.ban(a).unwrap();
        let b = one();
        let start = crate::share::Sequence::START;
        let _ = b
            .import(&two.export_delta(start).unwrap(), Actor::Channel(2))
            .unwrap();
        let _ = b
            .import(&three.export_delta(start).unwrap(), Actor::Channel(3))
            .unwrap();
        b.flush().unwrap();
        drop(b);
        let b = one();
        assert!(b.door(a).is_err());
        let since_two = two.export_delta(start).unwrap().last();
        two.lift(LiftSpec::key(a).by(Actor::Gate)).unwrap();
        let _ = b
            .import(&two.export_delta(since_two).unwrap(), Actor::Channel(2))
            .unwrap();
        assert!(b.door(a).is_err(), "node 3's ban stands");
        let since_three = three.export_delta(start).unwrap().last();
        three.lift(LiftSpec::key(a).by(Actor::Gate)).unwrap();
        let _ = b
            .import(&three.export_delta(since_three).unwrap(), Actor::Channel(3))
            .unwrap();
        assert!(b.door(a).is_ok(), "both origins lifted");
    }

    #[test]
    fn test_records_after_a_restart_reach_peers() {
        // A node's sequence numbers and log positions continue past its
        // earlier runs, so a peer neither drops its new records as seen nor
        // waits for positions it already passed.
        let store = Mem::default();
        let one = || {
            Bouncer::builder()
                .node(NodeId(1))
                .persistence(Box::new(store.clone()))
                .try_build()
                .unwrap()
        };
        let peer = Bouncer::builder().node(NodeId(2)).try_build().unwrap();
        let a = one();
        a.ban("198.51.100.1".parse::<std::net::IpAddr>().unwrap())
            .unwrap();
        let d = a.export_delta(crate::share::Sequence::START).unwrap();
        let since = d.last();
        let _ = peer.import(&d, Actor::Channel(1)).unwrap();
        a.flush().unwrap();
        drop(a);
        let a = one();
        let second: std::net::IpAddr = "198.51.100.2".parse().unwrap();
        a.ban(second).unwrap();
        let report = peer
            .import(&a.export_delta(since).unwrap(), Actor::Channel(1))
            .unwrap();
        assert!(report.applied >= 1, "{report:?}");
        assert!(peer.door(second).is_err());
    }

    #[test]
    fn test_bans_evicted_by_imports_leave_the_ledger() {
        // A full table evicting imported automatic bans forgets them, so
        // the ledger stays within the table and evicted bans never come back.
        let a = Bouncer::builder()
            .node(NodeId(1))
            .ban_capacity(1 << 14)
            .budgets(crate::Budgets::off())
            .try_build()
            .unwrap();
        let b = Bouncer::builder()
            .node(NodeId(2))
            .ban_capacity(64)
            .budgets(crate::Budgets::off())
            .try_build()
            .unwrap();
        let cap = b.capacity().bans as usize;
        for i in 0..(cap as u32 * 3) {
            let addr = std::net::IpAddr::from((0x0a00_0000 + (i << 8)).to_be_bytes());
            let spec = crate::BanSpec::address(addr)
                .by(Actor::Local)
                .for_duration(Duration::from_secs(3600));
            a.ban(spec).unwrap();
        }
        let start = crate::share::Sequence::START;
        let _ = b.import(&a.export_delta(start).unwrap(), Actor::Channel(1));
        let held = b
            .list(&crate::Filter::all(), crate::Page::first(u16::MAX))
            .items
            .len();
        assert!(held <= cap, "{held} of {cap}");
        let ledger = lock(b.shared().ledger.as_ref().unwrap()).len();
        assert!(
            ledger <= cap,
            "the ledger follows the table: {ledger} of {cap}"
        );
        let bans = b
            .export_snapshot()
            .unwrap()
            .records()
            .iter()
            .filter(|e| matches!(e.rec, Rec::Ban { .. }))
            .count();
        assert!(
            bans <= cap,
            "evicted bans do not come back: {bans} of {cap}"
        );
    }
}
