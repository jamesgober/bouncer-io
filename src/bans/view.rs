//! Read views of ban memory for administration: every ban covering a key,
//! a full listing, and lifting what a new allow list covers. Cold paths:
//! they take the writer lock and allocate.

use super::{BanMemory, Writer, table};
use crate::{
    bans::table::{Entry, TableKey},
    directive::{ActorKind, Reason},
    keys::{AccountKey, BanKey, Cidr, Family, FingerprintKey, SessionKey, TenantKey},
};

/// One ban as ban memory holds it, with its key restored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Held {
    pub(crate) key: BanKey,
    pub(crate) id: u64,
    /// Seconds since the bouncer started; 0 = permanent.
    pub(crate) until: u32,
    pub(crate) issued: u32,
    pub(crate) actor: ActorKind,
    pub(crate) reason: Reason,
    pub(crate) offences: u16,
    pub(crate) admin: bool,
}

impl Held {
    fn from_entry(key: BanKey, e: &Entry) -> Held {
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

    /// The prefix this ban covers, for address and prefix keys.
    pub(crate) fn cidr(&self) -> Option<Cidr> {
        match self.key {
            BanKey::Address(a) => Some(Cidr::host(a)),
            BanKey::Prefix(c) | BanKey::FingerprintIn(_, c) => Some(c),
            _ => None,
        }
    }

    pub(crate) fn expired(&self, now_secs: u64) -> bool {
        self.until != 0 && u64::from(self.until) <= now_secs
    }
}

/// The prefix of a table key of kind V4 or V6.
pub(crate) fn cidr_of(key: &TableKey) -> Option<Cidr> {
    let family = match key.kind {
        table::KIND_V4 => Family::V4,
        table::KIND_V6 => Family::V6,
        _ => return None,
    };
    Cidr::from_parts(
        family,
        key.len,
        (u128::from(key.k0) << 64) | u128::from(key.k1),
    )
}

impl BanMemory {
    /// The ban key a table key was made from. Compound fingerprint keys are
    /// digests; their originals are kept beside the table.
    fn key_of(&self, w: &Writer, key: &TableKey) -> Option<BanKey> {
        Some(match key.kind {
            table::KIND_V4 | table::KIND_V6 => {
                let c = cidr_of(key)?;
                if c.len() == c.family().max_len() {
                    BanKey::Address(c.network())
                } else {
                    BanKey::Prefix(c)
                }
            }
            table::KIND_SESSION => BanKey::Session(SessionKey::from_words(key.k0, key.k1)),
            table::KIND_ACCOUNT => {
                BanKey::Account(AccountKey((u128::from(key.k0) << 64) | u128::from(key.k1)))
            }
            table::KIND_TENANT => BanKey::Tenant(TenantKey(key.k1)),
            table::KIND_FINGERPRINT => {
                BanKey::Fingerprint(FingerprintKey::from_words(key.k0, key.k1))
            }
            table::KIND_FINGERPRINT_IN => {
                let (fp, c) = w.compound.get(&(key.len, key.k0, key.k1))?;
                BanKey::FingerprintIn(*fp, *c)
            }
            _ => return None,
        })
    }

    /// Remembers the original of a compound fingerprint key, and forgets
    /// originals whose bans are gone once they outnumber the live ones.
    pub(super) fn remember_compound(
        &self,
        w: &mut Writer,
        key: &TableKey,
        fp: FingerprintKey,
        c: Cidr,
    ) {
        w.compound.insert((key.len, key.k0, key.k1), (fp, c));
        let live = w.counts_ident[usize::from(table::KIND_FINGERPRINT_IN & 15)] as usize;
        if w.compound.len() > 2 * live + 64 {
            let table = &self.table;
            w.compound.retain(|&(len, k0, k1), _| {
                table
                    .get_owned(&TableKey {
                        kind: table::KIND_FINGERPRINT_IN,
                        len,
                        k0,
                        k1,
                    })
                    .is_some()
            });
        }
    }

    /// Every unexpired ban: the dynamic table and the administrator set.
    pub(crate) fn held_all(&self, now_secs: u64) -> Vec<Held> {
        let w = self.lock();
        let mut out = Vec::new();
        self.table.for_each(|e| {
            if !e.expired(now_secs) {
                if let Some(key) = self.key_of(&w, &e.key) {
                    out.push(Held::from_entry(key, e));
                }
            }
        });
        out.extend(
            w.admin
                .iter()
                .filter(|(_, a)| !a.expired(now_secs))
                .map(|(c, a)| admin_held(c, a)),
        );
        out
    }

    /// Every unexpired ban that applies to `key`: for an address, every
    /// prefix containing it; for a prefix, itself and every wider one; for
    /// an identity, its own ban (and a compound fingerprint's bare one).
    pub(crate) fn held_covering(&self, key: &BanKey, now_secs: u64) -> Vec<Held> {
        let key = key.normalized();
        let w = self.lock();
        let mut out = Vec::new();
        let take = |tkey: TableKey, out: &mut Vec<Held>| {
            if let Some(e) = self.table.get_owned(&tkey) {
                if !e.expired(now_secs) {
                    if let Some(k) = self.key_of(&w, &e.key) {
                        out.push(Held::from_entry(k, &e));
                    }
                }
            }
        };
        let cidr = match key {
            BanKey::Address(a) => Some(Cidr::host(a)),
            BanKey::Prefix(c) => Some(c),
            BanKey::FingerprintIn(fp, c) => {
                take(self.fingerprint_in_key(&fp, &c), &mut out);
                let (k0, k1) = fp.words();
                take(
                    TableKey {
                        kind: table::KIND_FINGERPRINT,
                        len: 0,
                        k0,
                        k1,
                    },
                    &mut out,
                );
                None
            }
            other => {
                if let Ok(super::Placement::Dynamic(tkey)) = self.place(&other, crate::Actor::App) {
                    take(tkey, &mut out);
                }
                None
            }
        };
        if let Some(c) = cidr {
            for len in (0..=c.len()).rev() {
                if !self.is_auto(c.family(), len) {
                    continue;
                }
                if let Some(p) = c.parent(len) {
                    take(Self::prefix_key(&p), &mut out);
                }
            }
            out.extend(
                w.admin
                    .iter()
                    .filter(|(p, a)| p.covers(&c) && !a.expired(now_secs))
                    .map(|(p, a)| admin_held(p, a)),
            );
        }
        out
    }

    /// Removes every address, prefix, and compound fingerprint ban whose
    /// prefix `covered` accepts (a new allow list's immune entries). Returns
    /// what was removed.
    pub(crate) fn lift_covered(&self, covered: impl Fn(&Cidr) -> bool) -> Vec<Held> {
        let mut guard = self.lock();
        let w = &mut *guard;
        let compound = &w.compound;
        let removed = self.table.remove_where(&mut w.table, |e| {
            let c = match e.key.kind {
                table::KIND_V4 | table::KIND_V6 => cidr_of(&e.key),
                table::KIND_FINGERPRINT_IN => compound
                    .get(&(e.key.len, e.key.k0, e.key.k1))
                    .map(|(_, c)| *c),
                _ => None,
            };
            c.as_ref().is_some_and(&covered)
        });
        let mut out = Vec::with_capacity(removed.len());
        for e in &removed {
            self.count(w, &e.key, false);
            if let Some(k) = self.key_of(w, &e.key) {
                out.push(Held::from_entry(k, e));
            }
        }
        let before = w.admin.len();
        let mut lifted_admin = Vec::new();
        w.admin.retain(|(c, a)| {
            let lift = covered(c);
            if lift {
                lifted_admin.push(admin_held(c, a));
            }
            !lift
        });
        if w.admin.len() != before {
            self.publish_admin(&w.admin);
        }
        out.extend(lifted_admin);
        out
    }

    /// Live entries in the dynamic table (expired ones not yet reclaimed
    /// included) and administrator prefixes.
    pub(crate) fn counts(&self) -> (u32, u32) {
        let w = self.lock();
        (w.table.live(), w.admin.len() as u32)
    }
}

fn admin_held(c: &Cidr, a: &super::AdminEntry) -> Held {
    Held {
        key: if c.len() == c.family().max_len() {
            BanKey::Address(c.network())
        } else {
            BanKey::Prefix(*c)
        },
        id: a.id,
        until: a.until,
        issued: a.issued,
        actor: a.actor,
        reason: a.reason,
        offences: 0,
        admin: true,
    }
}
