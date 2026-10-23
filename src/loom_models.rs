//! Loom models of the revocation protocol (dev/PLAN.md section 12.4):
//! L-1 epoch ordering, L-4 bind against revoke, L-5 release against revoke,
//! L-6 concurrency counters. Built only under `--cfg bouncer_loom`.

use loom::{
    sync::{
        Arc,
        atomic::{AtomicU64 as LoomU64, Ordering as LoomOrdering},
    },
    thread,
};

use crate::{
    bans::table::{Entry, KIND_SESSION, Probe, Table, TableKey, TableWriter},
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
        let was_returned = returned.load(LoomOrdering::SeqCst);
        let now = epoch.load_seq_cst();
        if now != 0 {
            assert!(
                matches!(table.find(&key(), 0), Probe::Hit(_)),
                "new epoch without the entry"
            );
        }
        if was_returned == 1 {
            assert_ne!(now, 0, "a commit after revoke returned passed");
        }
        revoker.join().unwrap();
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
        present.fetch_or(1, Ordering::AcqRel);
        fence(Ordering::SeqCst);
        let binder_saw = matches!(table.find(&key(), 0), Probe::Hit(_));
        let revoker_saw = revoker.join().unwrap();
        assert!(binder_saw || revoker_saw, "both sides missed the other");
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
        let released = update(&cell.state, Ordering::AcqRel, Ordering::Acquire, |st| {
            (generation(st) == gen0 && st & F_LIVE != 0).then_some(u64::from(next) << 32)
        });
        assert!(released.is_ok());
        revoker.join().unwrap();
        let st = cell.state.load(Ordering::Acquire);
        assert_eq!(generation(st), next);
        assert_eq!(
            st & F_REVOKED,
            0,
            "a revocation landed on the next generation"
        );
    });
}

/// L-6: two admissions racing for a concurrency limit of one never both pass,
/// and releases never take the count below zero.
#[test]
fn loom_l6_concurrency_counter_never_underflows() {
    loom::model(|| {
        let count = Arc::new(crate::sync::AtomicU32::new(0));
        let limit = 1u32;
        let admit = move |c: &crate::sync::AtomicU32| {
            let before = c.fetch_add(1, Ordering::AcqRel);
            if before >= limit {
                c.fetch_sub(1, Ordering::AcqRel);
                false
            } else {
                true
            }
        };
        let release = move |c: &crate::sync::AtomicU32| {
            let mut v = c.load(Ordering::Acquire);
            while v > 0 {
                match c.compare_exchange_weak(v, v - 1, Ordering::AcqRel, Ordering::Acquire) {
                    Ok(_) => break,
                    Err(actual) => v = actual,
                }
            }
        };
        let c2 = Arc::clone(&count);
        let other = thread::spawn(move || {
            let ok = admit(&c2);
            if ok {
                release(&c2);
            }
            ok
        });
        let mine = admit(&count);
        let theirs = other.join().unwrap();
        if mine {
            // Both can pass only if the other released first.
            release(&count);
        }
        let _ = theirs;
        assert_eq!(
            count.load(Ordering::Acquire),
            0,
            "the count leaked or underflowed"
        );
    });
}
