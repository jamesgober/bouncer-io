//! Where ban memory meets persistence and sharing: every state change
//! becomes a record for the journal and the outbound log; loading and
//! importing put records back.

use core::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{
    bans::{Guards, offenders::Offence, restore::Restore, view::Held},
    bouncer::{Bouncer, Shared},
    codec::{Envelope, Rec},
    directive::{Actor, ActorKind, Reason},
    error::{BouncerError, ImportError, PersistError},
    events::{Emit, signals},
    keys::BanKey,
    persist::{self, Header, LoadFailure, Persist, Persistence, State},
    revoke::{RevokeMode, Target},
    share::{Delta, ImportReport, Sequence},
    time::Now,
    verdict::DenialCode,
};

fn unix(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
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
        self.share.tombstone(key.normalized(), stamp, self.origin());
        self.log(
            Rec::Lift {
                key: key.normalized(),
                stamp,
                actor: actor.kind().code(),
            },
            true,
            true,
        );
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

    /// The full state as records: bans, offender records, tombstones.
    fn state_records(&self) -> Vec<Envelope> {
        let secs = self.now().secs();
        let origin = self.origin();
        let mut out = Vec::new();
        for h in self.bans.held_all(secs) {
            let from = (h.id >> 48) as u16;
            let stamp = (unix(self.wall_at(h.issued)) * 1000) << 16;
            out.push(Envelope {
                origin: if from == 0 { origin } else { from },
                seq: h.id,
                rec: self.ban_rec(&h, stamp),
            });
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
        for (key, stamp, from) in self.share.tombstones() {
            out.push(Envelope {
                origin: from,
                seq: 0,
                rec: Rec::Lift {
                    key,
                    stamp,
                    actor: ActorKind::Admin.code(),
                },
            });
        }
        out
    }

    /// Puts one loaded or imported ban back. `Ok(false)` when it has
    /// expired.
    fn put_ban(&self, rec: &Rec, origin: u16, ctx: &LoadCtx) -> Result<bool, BouncerError> {
        let Rec::Ban {
            key,
            until,
            issued,
            length,
            actor,
            reason,
            offences,
            id,
            ..
        } = *rec
        else {
            return Ok(false);
        };
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
                return Ok(false);
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
        let allow = self.allow.load();
        let guards = Guards {
            immune: &allow,
            proxies: &self.proxies,
        };
        self.bans.restore(
            &Restore {
                key,
                until: local_until,
                issued: u32::try_from(local_issued).unwrap_or(u32::MAX),
                actor: ActorKind::from_code(actor),
                reason: Reason::from_code(reason),
                offences,
                id,
            },
            &guards,
            ctx.now_secs,
        )?;
        Ok(true)
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
        match env.rec {
            Rec::Ban { .. } => {
                if let Err(BouncerError::BanTableFull { .. }) =
                    self.put_ban(&env.rec, env.origin, ctx)
                {
                    ctx.full += 1;
                }
            }
            Rec::Lift { key, stamp, .. } => {
                self.share.tombstone(key, stamp, env.origin);
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
                // A damaged or foreign tail would swallow new appends: start
                // a clean journal on a new snapshot.
                if rep.bytes != journal_len {
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
            created: unix(self.wall()),
            epoch,
            node: self.origin(),
            hlc: self.share.clock(),
        };
        let (bytes, tag) = persist::encode_snapshot(&header, &self.state_records(), p.key.as_ref());
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
        let records: Vec<(u64, Envelope)> =
            shared.state_records().into_iter().map(|e| (0, e)).collect();
        Ok(Delta::build(node.0, true, &records, shared.share.last()))
    }

    /// Merges a delta from another node. Any order and any repetition of
    /// delivery converges: a ban keeps its latest end, a lift removes bans
    /// stamped before it, and records seen before are skipped. Revocations
    /// reach the requests running here.
    ///
    /// # Errors
    ///
    /// `Import(RateLimited)` when a channel sends too many records per
    /// second. Refused records (allow-listed keys, clock skew, foreign
    /// lifts) are counted in `rejected` and reported as events.
    pub fn import(&self, delta: &Delta, from: Actor) -> Result<ImportReport, BouncerError> {
        let shared = self.shared();
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
        for env in records {
            if Some(env.origin) == own
                || (!delta.is_full() && !shared.share.first_time(env.origin, env.seq))
            {
                report.duplicates += 1;
                continue;
            }
            let stamp = match env.rec {
                Rec::Ban { stamp, .. } | Rec::Lift { stamp, .. } | Rec::Revoke { stamp, .. } => {
                    Some(stamp)
                }
                _ => None,
            };
            if stamp.is_some_and(|s| s >> 16 > limit) {
                report.rejected += 1;
                self.reject(ImportError::ClockSkew);
                continue;
            }
            if let Some(s) = stamp {
                shared.share.observe(s);
            }
            match env.rec {
                Rec::Ban { key, stamp, .. } => {
                    if shared.share.lifted_at(&key).is_some_and(|t| t >= stamp) {
                        report.superseded += 1;
                        continue;
                    }
                    match shared.put_ban(&env.rec, env.origin, &ctx) {
                        Ok(true) => {
                            report.applied += 1;
                            shared.log_env(env, true, true);
                        }
                        Ok(false) => report.superseded += 1,
                        Err(
                            BouncerError::AllowListed { .. } | BouncerError::TrustedProxyTarget,
                        ) => {
                            report.rejected += 1;
                            self.reject(ImportError::AllowListTouched);
                        }
                        Err(_) => report.rejected += 1,
                    }
                }
                Rec::Lift { key, stamp, .. } => {
                    let held = shared.bans.held_exact(&key, 0);
                    if let (Actor::Channel(n), Some(h)) = (from, &held) {
                        let issuer = (h.id >> 48) as u16;
                        let issuer = if issuer == 0 {
                            own.unwrap_or(0)
                        } else {
                            issuer
                        };
                        if u64::from(issuer) != n {
                            report.rejected += 1;
                            self.reject(ImportError::ForeignLift);
                            continue;
                        }
                    }
                    shared.share.tombstone(key, stamp, env.origin);
                    match held {
                        Some(h) if (unix(shared.wall_at(h.issued)) * 1000) << 16 < stamp => {
                            if shared.bans.remove_exact(&key).is_some() {
                                Emit {
                                    actor: from,
                                    reason: Reason::IMPORTED,
                                    subject: crate::bouncer::subject_of_key(&key),
                                    ..Emit::new(signals::BAN_LIFTED)
                                }
                                .send(shared);
                            }
                            report.applied += 1;
                        }
                        Some(_) => report.superseded += 1,
                        None => report.applied += 1,
                    }
                    shared.log_env(env, true, true);
                }
                Rec::Offence { key, score, last } => {
                    shared.put_offence(&key, score, last, &ctx);
                    report.applied += 1;
                    shared.log_env(env, true, true);
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
                            shared.log_env(env, false, true);
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
