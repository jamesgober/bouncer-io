//! Putting bans back as they were stored: loading persisted state and
//! importing records from other nodes. Cold paths, under the writer lock.

use super::{
    AdminEntry, BanMemory, Guards, Placement,
    offenders::Offence,
    table::{Entry, FLAG_EVICTABLE, Inserted},
    view::Held,
};
use crate::{
    directive::{Actor, ActorKind, Reason},
    error::BouncerError,
    keys::BanKey,
};

/// A ban to put back: times in seconds since this bouncer started.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Restore {
    pub(crate) key: BanKey,
    pub(crate) until: u32,
    pub(crate) issued: u32,
    pub(crate) actor: ActorKind,
    pub(crate) reason: Reason,
    pub(crate) offences: u16,
    pub(crate) id: u64,
}

impl BanMemory {
    /// Puts a ban back. Merges with a ban already under the key (the later
    /// end wins, permanent above all). Refused for keys the allow list or a
    /// trusted proxy now covers.
    pub(crate) fn restore(
        &self,
        r: &Restore,
        guards: &Guards<'_>,
        now_secs: u64,
    ) -> Result<(), BouncerError> {
        self.put(r, guards, now_secs, false).map(|_| ())
    }

    /// Sets the ban under the key to exactly `r` (a sharing node's merge of
    /// every origin's ban, computed by the ledger). Returns a ban the insert
    /// took out to make room (`true` when evicted, `false` when expired).
    pub(crate) fn replace(
        &self,
        r: &Restore,
        guards: &Guards<'_>,
        now_secs: u64,
    ) -> Result<Option<(BanKey, bool)>, BouncerError> {
        self.put(r, guards, now_secs, true)
    }

    fn put(
        &self,
        r: &Restore,
        guards: &Guards<'_>,
        now_secs: u64,
        exact: bool,
    ) -> Result<Option<(BanKey, bool)>, BouncerError> {
        let key = r.key.normalized();
        self.guard(&key, guards)?;
        // Placement as the application: stored bans of every kind go back.
        let placement = self.place(&key, Actor::App)?;
        let mut w = self.lock();
        let writer = &mut *w;
        if r.id & ((1 << 48) - 1) >= writer.next_id & ((1 << 48) - 1)
            && r.id >> 48 == writer.next_id >> 48
        {
            writer.next_id = r.id + 1;
        }
        match placement {
            Placement::Dynamic(tkey) => {
                let flags = if r.actor == ActorKind::Local && r.until != 0 {
                    FLAG_EVICTABLE
                } else {
                    0
                };
                let entry = Entry {
                    key: tkey,
                    flags,
                    actor: r.actor,
                    reason: r.reason,
                    offences: r.offences,
                    until: r.until,
                    issued: r.issued,
                    id: r.id,
                };
                match self
                    .table
                    .insert(&mut writer.table, entry, now_secs, |old| {
                        if exact {
                            entry
                        } else {
                            super::merge(old, &entry, now_secs)
                        }
                    }) {
                    Ok(Inserted::New { removed, evicted }) => {
                        let gone = removed.and_then(|old| {
                            self.count(writer, &old.key, false);
                            self.key_of(writer, &old.key).map(|k| (k, evicted))
                        });
                        self.count(writer, &tkey, true);
                        if let BanKey::FingerprintIn(fp, c) = key {
                            self.remember_compound(writer, &tkey, fp, c);
                        }
                        Ok(gone)
                    }
                    Ok(Inserted::Merged { .. }) => Ok(None),
                    Err(_) => Err(BouncerError::BanTableFull {
                        capacity: self.table.capacity(),
                    }),
                }
            }
            Placement::Admin(cidr) => {
                match writer.admin.iter_mut().find(|(c, _)| *c == cidr) {
                    Some((_, e)) if exact => {
                        *e = AdminEntry {
                            id: r.id,
                            until: r.until,
                            issued: r.issued,
                            actor: r.actor,
                            reason: r.reason,
                        };
                    }
                    Some((_, e)) => e.until = super::longer(e.until, r.until),
                    None => {
                        if writer.admin.len() >= super::MAX_ADMIN_PREFIXES {
                            return Err(BouncerError::BanTableFull {
                                capacity: super::MAX_ADMIN_PREFIXES as u32,
                            });
                        }
                        writer.admin.push((
                            cidr,
                            AdminEntry {
                                id: r.id,
                                until: r.until,
                                issued: r.issued,
                                actor: r.actor,
                                reason: r.reason,
                            },
                        ));
                    }
                }
                self.publish_admin(&writer.admin);
                Ok(None)
            }
        }
    }

    /// Removes the ban on exactly this key, if any (no tombstone, no error).
    pub(crate) fn remove_exact(&self, key: &BanKey) -> Option<Held> {
        let held = self.held_exact(key, 0)?;
        let key = key.normalized();
        let placement = self.place(&key, Actor::App).ok()?;
        let mut w = self.lock();
        let writer = &mut *w;
        match placement {
            Placement::Dynamic(tkey) => {
                self.table.remove(&mut writer.table, &tkey)?;
                self.count(writer, &tkey, false);
            }
            Placement::Admin(cidr) => {
                let before = writer.admin.len();
                writer.admin.retain(|(c, _)| *c != cidr);
                if writer.admin.len() == before {
                    return None;
                }
                self.publish_admin(&writer.admin);
            }
        }
        Some(held)
    }

    /// The ban stored under exactly this key, expired or not when
    /// `now_secs` is 0, else unexpired.
    pub(crate) fn held_exact(&self, key: &BanKey, now_secs: u64) -> Option<Held> {
        let key = key.normalized();
        let placement = self.place(&key, Actor::App).ok()?;
        let w = self.lock();
        let held = match placement {
            Placement::Dynamic(tkey) => {
                let e = self.table.get_owned(&tkey)?;
                Held {
                    key,
                    id: e.id,
                    until: e.until,
                    issued: e.issued,
                    actor: e.actor,
                    reason: e.reason,
                    offences: e.offences,
                    admin: false,
                }
            }
            Placement::Admin(cidr) => {
                let (_, a) = w.admin.iter().find(|(c, _)| *c == cidr)?;
                Held {
                    key,
                    id: a.id,
                    until: a.until,
                    issued: a.issued,
                    actor: a.actor,
                    reason: a.reason,
                    offences: 0,
                    admin: true,
                }
            }
        };
        drop(w);
        (now_secs == 0 || !held.expired(now_secs)).then_some(held)
    }

    /// Every offender record, with its key restored.
    pub(crate) fn offences_all(&self, now_secs: u64) -> Vec<(BanKey, Offence)> {
        let w = self.lock();
        w.offenders
            .iter()
            .filter_map(|(k, o)| {
                let key = self.key_of(&w, k)?;
                let score = w.offenders.get(k, now_secs)?.score;
                (score >= 0.01).then_some((
                    key,
                    Offence {
                        score,
                        last: o.last,
                    },
                ))
            })
            .collect()
    }

    /// Sets an offender record (loaded or imported); keeps the higher score.
    pub(crate) fn set_offence(&self, key: &BanKey, o: Offence, now_secs: u64) {
        let Ok(Placement::Dynamic(tkey)) = self.place(&key.normalized(), Actor::App) else {
            return;
        };
        let mut w = self.lock();
        let current = w.offenders.get(&tkey, now_secs).map_or(0.0, |c| c.score);
        if o.score > current {
            w.offenders.set(tkey, o);
        }
    }

    /// Makes local ban ids carry this node in their top 16 bits.
    pub(crate) fn set_node(&self, node: u16) {
        let mut w = self.lock();
        let low = w.next_id & ((1 << 48) - 1);
        w.next_id = (u64::from(node) << 48) | low.max(1);
    }
}
