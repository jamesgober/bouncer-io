//! Loom models of the revocation protocol (dev/PLAN.md section 12.4):
//! L-1 epoch ordering, L-4 bind against revoke, L-5 release against revoke,
//! L-6 concurrency counters, L-7 a request issued while its connection is
//! released, L-8 the door against `revoke_and_ban`, L-9 a revocation against
//! epoch moves from elsewhere, L-11 the door filter against bans and its own
//! rebuilds. Built only under `--cfg bouncer_loom`.

use loom::{
    sync::{
        Arc,
        atomic::{AtomicU64 as LoomU64, Ordering as LoomOrdering},
    },
    thread,
};

use crate::{
    bans::{
        filter::Filter,
        table::{Entry, KIND_SESSION, KIND_V4, Probe, Table, TableKey, TableWriter},
    },
    directive::{ActorKind, Reason},
    hash::HashKey,
    registry::{Cell, F_LIVE, F_REVOKED, KIND_CONNECTION, generation},
    revoke::RevocationEpoch,
    sync::{AtomicU64, Ordering, fence, update},
    ticket::mark_revoked,
    verdict::DenialCode,
};

fn key() -> TableKey {
    TableKey {
        kind: KIND_SESSION,
        len: 0,
        k0: 7,
        k1: 9,
    }
}

fn entry() -> Entry {
    Entry {
        key: key(),
        flags: 0,
        actor: ActorKind::App,
        reason: Reason::LOGOUT,
        offences: 5,
        until: 0,
        issued: 0,
        id: 1,
    }
}

/// Whether a ticket that last checked at `since` is reached by the entry, as
/// `Revocations::probe` decides: born after `since`, or its slot held by its
/// writer (fail closed).
fn reaches(table: &Table, since: u64) -> bool {
    match table.find(&key(), 0) {
        Probe::Hit(e) => e.id > since,
        Probe::Busy => true,
        Probe::Miss => false,
    }
}

/// L-1: a checkpoint that reads the new epoch sees the table entry; a
/// before-commit check that starts after `revoke` returned reads the new
/// epoch.
#[test]
fn loom_l1_epoch_publishes_entry() {
    loom::model(|| {
        let epoch = Arc::new(RevocationEpoch::new());
        let table = Arc::new(Table::new(2, HashKey::new(1, 2)));
        let returned = Arc::new(LoomU64::new(0));
        let (e, t, r) = (
            Arc::clone(&epoch),
            Arc::clone(&table),
            Arc::clone(&returned),
        );
        let revoker = thread::spawn(move || {
            let mut w = TableWriter::default();
            t.insert(&mut w, entry(), 0, |e| *e).unwrap();
            e.bump();
            r.store(1, LoomOrdering::SeqCst);
        });
        let (e, t, r) = (
            Arc::clone(&epoch),
            Arc::clone(&table),
            Arc::clone(&returned),
        );
        let checker = thread::spawn(move || {
            let was_returned = r.load(LoomOrdering::SeqCst);
            let now = e.load_seq_cst();
            let hit = now != 0 && matches!(t.find(&key(), 0), Probe::Hit(_));
            (was_returned, now, hit)
        });
        revoker.join().unwrap();
        let (was_returned, now, hit) = checker.join().unwrap();
        if now != 0 {
            assert!(hit, "new epoch without the entry");
        }
        if was_returned == 1 {
            assert_ne!(now, 0, "a commit after revoke returned passed");
        }
    });
}

/// L-4: a key bound while it is revoked is seen by the binder's check or by
/// the revoker's sweep (paired SeqCst fences).
#[test]
fn loom_l4_bind_and_revoke_never_both_miss() {
    loom::model(|| {
        let epoch = Arc::new(RevocationEpoch::new());
        let table = Arc::new(Table::new(2, HashKey::new(1, 2)));
        let present = Arc::new(AtomicU64::new(0));
        let (e, t, p) = (Arc::clone(&epoch), Arc::clone(&table), Arc::clone(&present));
        let revoker = thread::spawn(move || {
            let mut w = TableWriter::default();
            t.insert(&mut w, entry(), 0, |e| *e).unwrap();
            e.bump(); // ends with fence(SeqCst)
            p.load(Ordering::Relaxed) != 0
        });
        let (t, p) = (Arc::clone(&table), Arc::clone(&present));
        let binder = thread::spawn(move || {
            p.fetch_or(1, Ordering::AcqRel);
            fence(Ordering::SeqCst);
            matches!(t.find(&key(), 0), Probe::Hit(_))
        });
        let revoker_saw = revoker.join().unwrap();
        let binder_saw = binder.join().unwrap();
        assert!(binder_saw || revoker_saw, "both sides missed the other");
    });
}

/// L-8: a connection at the door while its source is revoked and banned is
/// refused by the ban or reached by the revocation. The door reads the epoch
/// before the ban lookup and its cell starts from that value; the revoker
/// bans first. A revocation matches only cells that have not reached its
/// birth, so reading the epoch after the lookup would let this one escape.
#[test]
fn loom_l8_door_never_escapes_revoke_and_ban() {
    loom::model(|| {
        let epoch = Arc::new(RevocationEpoch::new());
        let table = Arc::new(Table::new(2, HashKey::new(1, 2)));
        let banned = Arc::new(LoomU64::new(0));
        let (e, t, b) = (Arc::clone(&epoch), Arc::clone(&table), Arc::clone(&banned));
        let revoker = thread::spawn(move || {
            b.store(1, LoomOrdering::SeqCst);
            let mut w = TableWriter::default();
            t.insert(
                &mut w,
                Entry {
                    id: crate::revoke::PENDING_BIRTH,
                    ..entry()
                },
                0,
                |e| *e,
            )
            .unwrap();
            let birth = e.bump();
            t.insert(&mut w, entry(), 0, |old| Entry { id: birth, ..*old })
                .unwrap();
        });
        let (e, t, b) = (Arc::clone(&epoch), Arc::clone(&table), Arc::clone(&banned));
        let door = thread::spawn(move || {
            let seen = e.load();
            if b.load(LoomOrdering::SeqCst) != 0 {
                return None;
            }
            // Admitted: the ticket's check at issue, as `Ticket::issue` runs it.
            fence(Ordering::SeqCst);
            Some((seen, reaches(&t, seen)))
        });
        revoker.join().unwrap();
        let Some((seen, mut denied)) = door.join().unwrap() else {
            return;
        };
        // Its next checkpoint: the epoch has moved past `seen` if it needs to.
        let now = epoch.load();
        if now != seen {
            denied |= reaches(&table, seen);
        }
        assert!(denied, "the door passed the ban and the revocation missed");
    });
}

/// L-5: revoking a connection while its ticket is released never leaves the
/// next generation revoked.
#[test]
fn loom_l5_revoke_never_lands_on_next_generation() {
    loom::model(|| {
        let cell = Arc::new(Cell::new());
        let gen0 = generation(cell.state.load(Ordering::Relaxed));
        cell.state.store(
            u64::from(gen0) << 32 | F_LIVE | KIND_CONNECTION,
            Ordering::Release,
        );
        let c = Arc::clone(&cell);
        let revoker = thread::spawn(move || {
            mark_revoked(&c, gen0, DenialCode::Forbidden);
        });
        // Release: the same compare-and-swap `release_cell` performs.
        let next = gen0.wrapping_add(1);
        let c = Arc::clone(&cell);
        let releaser = thread::spawn(move || {
            update(&c.state, Ordering::AcqRel, Ordering::Acquire, |st| {
                (generation(st) == gen0 && st & F_LIVE != 0).then_some(u64::from(next) << 32)
            })
            .is_ok()
        });
        revoker.join().unwrap();
        assert!(releaser.join().unwrap());
        let st = cell.state.load(Ordering::Acquire);
        assert_eq!(generation(st), next);
        assert_eq!(
            st & F_REVOKED,
            0,
            "a revocation landed on the next generation"
        );
    });
}

/// L-6: two admissions of one key racing for a concurrency limit of one
/// never both pass, and releases never take the count below zero. The steps
/// are those of the door's concurrency tiers (`Counts`, D-117).
#[test]
fn loom_l6_concurrency_counter_never_underflows() {
    loom::model(|| {
        let counts = Arc::new(crate::claims::Counts::new(16));
        let key = crate::claims::Claims::key(0x5eed);
        let c2 = Arc::clone(&counts);
        let other = thread::spawn(move || {
            let ok = c2.acquire(key, 1, || false) == Ok(true);
            if ok {
                c2.release(key);
            }
            ok
        });
        let c1 = Arc::clone(&counts);
        let me = thread::spawn(move || c1.acquire(key, 1, || false) == Ok(true));
        let theirs = other.join().unwrap();
        let mine = me.join().unwrap();
        if mine {
            // Both can pass only if the other released first.
            counts.release(key);
        }
        let _ = theirs;
        assert_eq!(counts.count(key), 0, "the count leaked or underflowed");
        // A release with nothing counted takes nothing.
        counts.release(key);
        assert_eq!(counts.count(key), 0);
    });
}

/// L-7: a request issued while its connection is released is never left
/// passing on its fast path: either the issue fails (the connection is
/// stale), or the request is revoked, or the epoch it recorded is behind the
/// final one (its next checkpoint takes the slow path and finds the
/// connection gone). The steps are those of `issue_request` and
/// `release_cell`.
#[test]
fn loom_l7_request_issued_during_release_never_passes() {
    loom::model(|| {
        let parent = Arc::new(Cell::new());
        let gen0 = generation(parent.state.load(Ordering::Relaxed));
        parent.state.store(
            u64::from(gen0) << 32 | F_LIVE | KIND_CONNECTION,
            Ordering::Release,
        );
        parent.link.store(u64::from(gen0) << 32, Ordering::Release);
        let epoch = Arc::new(RevocationEpoch::new());
        let (p, e) = (Arc::clone(&parent), Arc::clone(&epoch));
        let releaser = thread::spawn(move || {
            let next = gen0.wrapping_add(1);
            let taken = update(&p.state, Ordering::AcqRel, Ordering::Acquire, |st| {
                (generation(st) == gen0 && st & F_LIVE != 0).then_some(u64::from(next) << 32)
            });
            assert!(taken.is_ok());
            let old = p.link.swap(u64::from(next) << 32, Ordering::AcqRel);
            if generation(old) == gen0 && old as u32 > 0 {
                e.bump();
            }
        });
        // The issuer: check the connection, count the child, record the
        // epoch, then look at the connection again.
        let (parent2, e2) = (Arc::clone(&parent), Arc::clone(&epoch));
        let issuer = thread::spawn(move || {
            let st = parent2.state.load(Ordering::Acquire);
            if generation(st) != gen0 || st & F_LIVE == 0 {
                return None;
            }
            let counted = update(&parent2.link, Ordering::AcqRel, Ordering::Acquire, |l| {
                (generation(l) == gen0).then(|| l.wrapping_add(1))
            })
            .is_ok();
            if !counted {
                return None;
            }
            let seen = e2.load();
            fence(Ordering::SeqCst);
            let pst = parent2.state.load(Ordering::Acquire);
            let revoked = generation(pst) != gen0 || pst & F_LIVE == 0;
            Some((seen, revoked))
        });
        releaser.join().unwrap();
        let outcome = issuer.join().unwrap();
        if let Some((seen, revoked)) = outcome {
            assert!(
                revoked || seen != epoch.load(),
                "a request outlived its connection on the fast path"
            );
        }
    });
}

/// L-9: a revocation reaches a ticket that was live before it, while
/// another thread moves the epoch (a release, another revocation). The
/// steps are those of `Revocations::insert` and of a checkpoint's slow path:
/// read the epoch, probe for entries born after the epoch last checked,
/// record the epoch read.
#[test]
fn loom_l9_revocation_reaches_a_live_ticket_despite_other_epoch_moves() {
    loom::model(|| {
        let epoch = Arc::new(RevocationEpoch::new());
        let table = Arc::new(Table::new(2, HashKey::new(1, 2)));
        let (e, t) = (Arc::clone(&epoch), Arc::clone(&table));
        let revoker = thread::spawn(move || {
            let mut w = TableWriter::default();
            t.insert(
                &mut w,
                Entry {
                    id: crate::revoke::PENDING_BIRTH,
                    ..entry()
                },
                0,
                |e| *e,
            )
            .unwrap();
            let birth = e.bump();
            t.insert(&mut w, entry(), 0, |old| Entry { id: birth, ..*old })
                .unwrap();
        });
        let e2 = Arc::clone(&epoch);
        let mover = thread::spawn(move || {
            e2.bump();
        });
        // The ticket, checked at 0 when it was issued, takes its slow path
        // once the epoch has moved: it probes for entries born after the
        // epoch it last checked at, and records the epoch it read.
        let (e3, t3) = (Arc::clone(&epoch), Arc::clone(&table));
        let ticket = thread::spawn(move || {
            let now = e3.load();
            (now, now != 0 && reaches(&t3, 0))
        });
        revoker.join().unwrap();
        mover.join().unwrap();
        let (seen, mut denied) = ticket.join().unwrap();
        // Its next checkpoint after `revoke` returned.
        if epoch.load() != seen {
            denied |= reaches(&table, seen);
        }
        assert!(
            denied,
            "the revocation missed a ticket that was live before it"
        );
    });
}

fn v4(len: u8, word: u64) -> TableKey {
    TableKey {
        kind: KIND_V4,
        len,
        k0: 0,
        k1: word,
    }
}

/// L-11a: a door that reads the epoch a `revoke_and_ban` moved sees the
/// ban's filter bits, even when the filter switched buffers just before
/// (the writer adds the key, then moves the epoch, as `revoke_and_ban`
/// does). A door that reads the old epoch is reached by the revocation
/// instead (L-8).
#[test]
fn loom_l11_filter_never_hides_a_ban_the_epoch_announced() {
    loom::model(|| {
        let epoch = Arc::new(RevocationEpoch::new());
        let filter = Arc::new(Filter::new(1, HashKey::new(1, 2)));
        let (anchor, k) = (v4(24, 0xc000_0200), v4(32, 0xc000_0201));
        let (e, f) = (Arc::clone(&epoch), Arc::clone(&filter));
        let before = epoch.load();
        // Both sides are spawned: loom then also runs the writer first.
        let writer = thread::spawn(move || {
            f.rebuild(|_| {});
            f.add(&anchor, &k);
            e.bump();
        });
        let (e, f) = (Arc::clone(&epoch), Arc::clone(&filter));
        let door = thread::spawn(move || (e.load(), f.maybe(&anchor, &[k])));
        writer.join().unwrap();
        let (seen, maybe) = door.join().unwrap();
        assert!(
            maybe == 1 || seen == before,
            "the door read the new epoch and the filter hid the ban"
        );
    });
}

/// L-11b: a reader stalled while the filter is rebuilt twice (its buffer
/// cleared and filled again) never answers "no" for a key the table holds
/// throughout: the buffer's generation word sends it to the table.
#[test]
fn loom_l11_filter_rebuilds_never_hide_a_held_key() {
    loom::model(|| {
        let filter = Arc::new(Filter::new(1, HashKey::new(3, 4)));
        let (anchor, k) = (v4(24, 0xc000_0200), v4(32, 0xc000_0201));
        filter.add(&anchor, &k);
        let f = Arc::clone(&filter);
        let writer = thread::spawn(move || {
            for _ in 0..2 {
                f.rebuild(|add| add(&anchor, &k));
            }
        });
        let f = Arc::clone(&filter);
        let reader = thread::spawn(move || f.maybe(&anchor, &[k]));
        writer.join().unwrap();
        assert_eq!(reader.join().unwrap(), 1, "a held key read as absent");
    });
}
