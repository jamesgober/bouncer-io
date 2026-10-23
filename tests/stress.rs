//! Checkpoints under concurrent revocations: no missed revocation (T-6, the
//! 0.4 exit criterion). The full run is 10^8 checkpoints:
//! `cargo test --release --test stress -- --ignored`. The default run is
//! shorter so CI stays fast.
//!
//! Eight threads each hold a request whose session changes every round. The
//! revoker waits until the threads have done their share of checkpoints for
//! the round, revokes every session of that round, and then sets a flag. A
//! check that reads the flag set must already be denied.

use std::{
    net::IpAddr,
    sync::{
        Arc, Barrier,
        atomic::{AtomicU64, Ordering},
    },
};

use bouncer_io::{Bouncer, Budgets, Directive, Reason, RequestId, SessionKey};

const THREADS: usize = 8;
const ROUNDS: u64 = 64;

fn session(round: u64, thread: usize) -> SessionKey {
    let mut d = [0u8; 16];
    d[..8].copy_from_slice(&round.to_le_bytes());
    d[8] = thread as u8;
    SessionKey::from_digest(d)
}

fn run(total_checkpoints: u64) {
    let b = Bouncer::builder()
        .budgets(Budgets::off())
        .try_build()
        .unwrap();
    let barrier = Arc::new(Barrier::new(THREADS + 1));
    // The last round whose revocations have all returned.
    let revoked_round = Arc::new(AtomicU64::new(0));
    let checks = Arc::new(AtomicU64::new(0));
    // How many threads have bound the session of each round.
    let bound: Arc<Vec<AtomicU64>> = Arc::new((0..=ROUNDS).map(|_| AtomicU64::new(0)).collect());
    let handles: Vec<_> = (0..THREADS)
        .map(|t| {
            let (b, barrier, revoked_round, checks, bound) = (
                b.clone(),
                Arc::clone(&barrier),
                Arc::clone(&revoked_round),
                Arc::clone(&checks),
                Arc::clone(&bound),
            );
            std::thread::spawn(move || {
                let conn = b.door(IpAddr::from([192, 0, 2, t as u8 + 1])).unwrap();
                barrier.wait();
                for round in 1..=ROUNDS {
                    let mut req = conn.request(RequestId(u128::from(round))).unwrap();
                    let bound_now = req.bind_session(session(round, t));
                    assert!(
                        bound_now.is_pass(),
                        "thread {t} round {round}: {bound_now:?}"
                    );
                    bound[round as usize].fetch_add(1, Ordering::SeqCst);
                    let mut local = 0u64;
                    loop {
                        let done = revoked_round.load(Ordering::SeqCst) >= round;
                        let v = if local % 2 == 0 {
                            req.before_commit()
                        } else {
                            req.checkpoint()
                        };
                        local += 1;
                        if done {
                            assert!(v.is_deny(), "missed revocation: thread {t}, round {round}");
                            break;
                        }
                        if local % 1024 == 0 {
                            checks.fetch_add(1024, Ordering::Relaxed);
                        }
                    }
                }
            })
        })
        .collect();
    barrier.wait();
    for round in 1..=ROUNDS {
        let target = total_checkpoints * round / ROUNDS;
        while checks.load(Ordering::Relaxed) < target
            || bound[round as usize].load(Ordering::SeqCst) < THREADS as u64
        {
            // A thread that panicked never adds more: stop waiting for it.
            if handles.iter().any(|h| h.is_finished()) {
                break;
            }
            std::thread::yield_now();
        }
        for t in 0..THREADS {
            // The connection stays: each round opens a new request on it.
            let _ = b
                .apply(
                    Directive::revoke(session(round, t))
                        .because(Reason::LOGOUT)
                        .keep_connection(),
                )
                .unwrap();
        }
        revoked_round.store(round, Ordering::SeqCst);
    }
    for h in handles {
        h.join().unwrap();
    }
    assert!(checks.load(Ordering::Relaxed) >= total_checkpoints);
}

#[test]
fn stress_checkpoints_with_concurrent_revocations() {
    run(1_000_000);
}

#[test]
#[ignore = "10^8 checkpoints; run with --release -- --ignored"]
fn stress_1e8_checkpoints_with_concurrent_revocations() {
    run(100_000_000);
}
