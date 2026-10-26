//! T-12: checkpoint cost while another thread revokes 100,000 times a
//! second (PLAN 11). Every revocation moves the epoch, so checkpoints keep
//! taking the slow path; the revocation table is cleaned as maintenance
//! would. Also measures `#[track_caller]` on a checkpoint wrapper (a 0.2
//! defence idea: report the caller of a denied checkpoint).
//!
//! `cargo bench --bench storm`. Run it on two cores (one for the revoker).

use std::{
    hint::black_box,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use bouncer_io::{AccountKey, Bouncer, Budgets, Reason, RequestId, SessionKey, Ticket, Verdict};

/// Checkpoints per sample (Windows' clock resolves 100 ns, so samples are
/// long); the table shows per-checkpoint nanoseconds.
const BATCH: usize = 10_000;
const SAMPLES: usize = 2_000;

fn percentiles(mut v: Vec<f64>) -> (f64, f64, f64, f64) {
    v.sort_by(f64::total_cmp);
    let at = |p: f64| v[((v.len() as f64 - 1.0) * p) as usize];
    (at(0.0), at(0.5), at(0.99), at(0.999))
}

fn sample(req: &mut Ticket) -> Vec<f64> {
    (0..SAMPLES)
        .map(|_| {
            let start = Instant::now();
            for _ in 0..BATCH {
                black_box(req.checkpoint().is_pass());
            }
            start.elapsed().as_nanos() as f64 / BATCH as f64
        })
        .collect()
}

#[track_caller]
#[inline(never)]
fn tracked(req: &mut Ticket) -> Verdict {
    let _ = std::panic::Location::caller();
    req.checkpoint()
}

#[inline(never)]
fn untracked(req: &mut Ticket) -> Verdict {
    req.checkpoint()
}

fn main() {
    let b = Arc::new(
        Bouncer::builder()
            .budgets(Budgets::off())
            .tickets(1024)
            .try_build()
            .unwrap(),
    );
    let conn = b.door("192.0.2.1".parse().unwrap()).unwrap();
    let mut req = conn.request(RequestId(1)).unwrap();
    assert!(req.bind_session(SessionKey::from_digest([1; 16])).is_pass());
    assert!(req.bind_account(AccountKey(1)).is_pass());

    let quiet = sample(&mut req);
    let stop = Arc::new(AtomicBool::new(false));
    let done = Arc::new(AtomicU64::new(0));
    let revoker = {
        let (b, stop, done) = (Arc::clone(&b), Arc::clone(&stop), Arc::clone(&done));
        std::thread::spawn(move || {
            // 100,000 per second: one every 10 Âµs, paced by the clock.
            let start = Instant::now();
            let mut n: u64 = 0;
            while !stop.load(Ordering::Relaxed) {
                let due = start + Duration::from_nanos(n * 10_000);
                while Instant::now() < due {
                    std::hint::spin_loop();
                }
                // Other accounts: every revocation moves the epoch, none
                // matches the measured request.
                let _ = b.revoke(AccountKey(u128::from(n) + 1_000), Reason::ADMIN);
                n += 1;
                if n % 1_000 == 0 {
                    let _ = b.maintain(b.now());
                }
            }
            done.store(n, Ordering::Relaxed);
            start.elapsed()
        })
    };
    std::thread::sleep(Duration::from_millis(100));
    let storm = sample(&mut req);
    stop.store(true, Ordering::Relaxed);
    let elapsed = revoker.join().unwrap();
    let rate = done.load(Ordering::Relaxed) as f64 / elapsed.as_secs_f64();
    assert!(
        req.checkpoint().is_pass(),
        "no revocation matched the request"
    );

    println!(
        "{:<44} {:>8} {:>8} {:>8} {:>8}",
        "checkpoint (ns, mean of 10,000)", "min", "p50", "p99", "p99.9"
    );
    for (name, v) in [("quiet", quiet), ("storm", storm)] {
        let (min, p50, p99, p999) = percentiles(v);
        println!("{name:<44} {min:>8.1} {p50:>8.1} {p99:>8.1} {p999:>8.1}");
    }
    println!("revocations per second during the storm: {rate:.0}");

    // The slow path itself: 1,024 tickets with seven keys each, the epoch
    // moved by an unrelated revocation, then one checkpoint per ticket.
    let many = Bouncer::builder()
        .budgets(Budgets::off())
        .tickets(4096)
        .try_build()
        .unwrap();
    let c = many.door("198.51.100.1".parse().unwrap()).unwrap();
    let mut fp_conn = many.door("198.51.100.2".parse().unwrap()).unwrap();
    assert!(
        fp_conn
            .bind_fingerprint(bouncer_io::FingerprintKey::from_digest([7; 16]))
            .is_pass()
    );
    let mut tickets: Vec<Ticket> = (0..1024u128)
        .map(|i| {
            let mut r = c.request(RequestId(i + 10)).unwrap();
            let mut d = [0u8; 16];
            d[..8].copy_from_slice(&(i as u64).to_le_bytes());
            assert!(r.bind_session(SessionKey::from_digest(d)).is_pass());
            assert!(r.bind_account(AccountKey(i + 10)).is_pass());
            assert!(r.bind_tenant(bouncer_io::TenantKey(7)).is_pass());
            assert!(
                r.bind_fingerprint(bouncer_io::FingerprintKey::from_digest(d))
                    .is_pass()
            );
            r
        })
        .collect();
    // A table holding one entry of every kind, so every probe runs.
    let _ = many.revoke(AccountKey(1), Reason::ADMIN);
    let _ = many.revoke(SessionKey::from_digest([0xee; 16]), Reason::ADMIN);
    let _ = many.revoke(bouncer_io::TenantKey(99), Reason::ADMIN);
    let _ = many.revoke(
        bouncer_io::FingerprintKey::from_digest([0xee; 16]),
        Reason::ADMIN,
    );
    let _ = many.revoke(
        "203.0.113.0/24".parse::<bouncer_io::Cidr>().unwrap(),
        Reason::ADMIN,
    );
    let mut slow = Vec::with_capacity(400);
    for n in 0..400u128 {
        let _ = many.revoke(AccountKey(1_000_000 + n), Reason::ADMIN);
        let start = Instant::now();
        for t in tickets.iter_mut() {
            black_box(t.checkpoint().is_pass());
        }
        slow.push(start.elapsed().as_nanos() as f64 / tickets.len() as f64);
        if n % 50 == 0 {
            let _ = many.maintain(many.now());
        }
    }
    let (min, p50, p99, _) = percentiles(slow);
    println!(
        "slow path, seven keys bound (ns per checkpoint): min {min:.1}, p50 {p50:.1}, p99 {p99:.1}"
    );

    let best = |f: &mut dyn FnMut()| {
        (0..41)
            .map(|_| {
                let s = Instant::now();
                for _ in 0..100_000 {
                    f();
                }
                s.elapsed().as_nanos() as f64 / 100_000.0
            })
            .fold(f64::MAX, f64::min)
    };
    let t = best(&mut || {
        black_box(tracked(&mut req).is_pass());
    });
    let u = best(&mut || {
        black_box(untracked(&mut req).is_pass());
    });
    println!("checkpoint through a #[track_caller] wrapper: {t:.2} ns; plain wrapper: {u:.2} ns");
}
