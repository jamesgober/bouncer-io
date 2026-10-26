//! Threat T-8: timing does not reveal ban state a client cannot already see
//! from the verdict (dev/PLAN.md section 8, D-093).
//!
//! Each test times two classes of calls in interleaved batches (so drift on
//! a shared machine falls on both) and compares the batch means with a
//! two-sample Kolmogorov-Smirnov test at p < 0.01, three times; a claim
//! fails when two or more of the three separate (a real difference
//! separates every time; a shared machine makes one in a few runs separate
//! by chance). A control pair that does differ (admitted against banned)
//! must separate, which shows the harness can see a difference of the size
//! that matters.
//!
//! Timing needs a quiet machine and a release build, so the tests are
//! ignored by default:
//! `cargo test --release --test timing -- --ignored --test-threads=1`.

use std::{hint::black_box, net::IpAddr, time::Instant};

use bouncer_io::{BanSpec, Bouncer, Budgets, ConnId, Provenance, RequestId, SessionKey};

/// Calls per batch: Windows' clock resolves 100 ns.
const BATCH: usize = 64;
/// Batches per class.
const BATCHES: usize = 4_000;
/// Measurements per claim; it fails when `FAIL_AT` or more separate.
const ROUNDS: usize = 3;
const FAIL_AT: usize = 2;

/// The two-sample Kolmogorov-Smirnov statistic D and its critical value at
/// p = 0.01.
fn ks(a: &mut [f64], b: &mut [f64]) -> (f64, f64) {
    a.sort_by(f64::total_cmp);
    b.sort_by(f64::total_cmp);
    let (n, m) = (a.len(), b.len());
    let (mut i, mut j, mut d) = (0, 0, 0.0f64);
    while i < n && j < m {
        let x = a[i].min(b[j]);
        while i < n && a[i] <= x {
            i += 1;
        }
        while j < m && b[j] <= x {
            j += 1;
        }
        d = d.max((i as f64 / n as f64 - j as f64 / m as f64).abs());
    }
    let critical = 1.628 * (((n + m) as f64) / ((n * m) as f64)).sqrt();
    (d, critical)
}

/// Times `run` over each class's inputs in interleaved batches; returns
/// the batch means in nanoseconds per call.
fn interleaved<T: Copy>(a: &[T], b: &[T], mut run: impl FnMut(T, usize)) -> (Vec<f64>, Vec<f64>) {
    let (mut ta, mut tb) = (Vec::with_capacity(BATCHES), Vec::with_capacity(BATCHES));
    let mut n = 0usize;
    let mut time = |inputs: &[T], k: usize, n: &mut usize| {
        let start = Instant::now();
        for i in 0..BATCH {
            run(inputs[(k * BATCH + i) % inputs.len()], *n);
            *n += 1;
        }
        start.elapsed().as_nanos() as f64 / BATCH as f64
    };
    for k in 0..BATCHES {
        // Alternate which class goes first.
        if k % 2 == 0 {
            ta.push(time(a, k, &mut n));
            tb.push(time(b, k, &mut n));
        } else {
            tb.push(time(b, k, &mut n));
            ta.push(time(a, k, &mut n));
        }
    }
    (ta, tb)
}

fn median(v: &[f64]) -> f64 {
    let mut s = v.to_vec();
    s.sort_by(f64::total_cmp);
    s[s.len() / 2]
}

fn mean(v: &[f64]) -> f64 {
    v.iter().sum::<f64>() / v.len() as f64
}

fn v4(a: u32) -> IpAddr {
    IpAddr::from(a.to_be_bytes())
}

/// 100,000 banned hosts, one in each of 100,000 /24s ("dirty" prefixes).
fn fixture() -> (Bouncer, Vec<IpAddr>, Vec<IpAddr>, Vec<IpAddr>) {
    let b = Bouncer::builder()
        .budgets(Budgets::off())
        .tickets(1 << 16)
        .ban_capacity(1 << 18)
        .try_build()
        .unwrap();
    let mut dirty = Vec::new();
    let mut clean = Vec::new();
    let mut banned = Vec::new();
    for i in 0..100_000u32 {
        // 10.0.0.0/8 and 11.0.0.0/8 hold dirty prefixes; 12.0.0.0/8 and
        // 13.0.0.0/8 clean ones, with the same host numbers.
        let net = 0x0a00_0000 + (i << 8);
        let host = net + 1;
        b.ban(BanSpec::address(v4(host))).unwrap();
        banned.push(v4(host));
        let probe = 2 + (i % 250);
        dirty.push(v4(net + probe));
        clean.push(v4(0x0c00_0000 + (i << 8) + probe));
    }
    (b, dirty, clean, banned)
}

fn door_case(b: &Bouncer, a: &[IpAddr], c: &[IpAddr]) -> (f64, f64, f64, f64) {
    let now = b.now();
    let (mut ta, mut tc) = interleaved(a, c, |peer, n| {
        let r = b.door_at(ConnId(n as u64), peer, Provenance::Socket, now);
        black_box(r.is_ok());
    });
    let (ma, mc) = (median(&ta), median(&tc));
    println!("  means {:.2} / {:.2} ns", mean(&ta), mean(&tc));
    let (d, critical) = ks(&mut ta, &mut tc);
    (d, critical, ma, mc)
}

#[test]
#[ignore = "timing: run on a quiet machine with --release"]
fn test_timing_admitted_does_not_reveal_neighbour_bans() {
    let (b, dirty, clean, banned) = fixture();
    // Warm both classes.
    let _ = door_case(&b, &dirty, &clean);

    let separated = (0..ROUNDS)
        .filter(|_| {
            let (d, critical, md, mc) = door_case(&b, &dirty, &clean);
            println!("admitted, dirty /24 against clean /24: D {d:.4} (critical {critical:.4}); medians {md:.1} / {mc:.1} ns");
            d > critical
        })
        .count();
    // Control: admitted against banned differs, and the harness sees it.
    let (cd, ccritical, mb, ma) = door_case(&b, &banned, &clean);
    println!(
        "control, banned against admitted: D {cd:.4} (critical {ccritical:.4}); medians {mb:.1} / {ma:.1} ns"
    );
    assert!(cd > ccritical, "the control must separate");
    assert!(
        separated < FAIL_AT,
        "admitted latency separates by neighbours' ban state in {separated} of {ROUNDS}"
    );
}

#[test]
#[ignore = "timing: run on a quiet machine with --release"]
fn test_timing_bind_does_not_reveal_near_banned_digests() {
    let b = Bouncer::builder()
        .budgets(Budgets::off())
        .ban_capacity(1 << 16)
        .try_build()
        .unwrap();
    // 1,000 banned sessions; "near" digests differ from one in the last
    // byte only, "far" digests are unrelated.
    let mut near = Vec::new();
    let mut far = Vec::new();
    for i in 0..1_000u32 {
        let mut d = [0u8; 16];
        d[..4].copy_from_slice(&i.to_le_bytes());
        d[4..8].copy_from_slice(&0x5eed_u32.to_le_bytes());
        b.ban(BanSpec::key(SessionKey::from_digest(d))).unwrap();
        for last in 1..=4u8 {
            let mut n = d;
            n[15] = last;
            near.push(SessionKey::from_digest(n));
            let mut f = [0u8; 16];
            f[..4].copy_from_slice(&(i + 1_000_000).to_le_bytes());
            f[8..12].copy_from_slice(&0xfa7_u32.to_le_bytes());
            f[15] = last;
            far.push(SessionKey::from_digest(f));
        }
    }
    let conn = b.door("192.0.2.1".parse().unwrap()).unwrap();
    let run = |a: &[SessionKey], c: &[SessionKey]| {
        let (mut ta, mut tc) = interleaved(a, c, |key, n| {
            let mut req = conn.request(RequestId(n as u128 + 1)).unwrap();
            black_box(req.bind_session(key).is_pass());
        });
        let (ma, mc) = (median(&ta), median(&tc));
        println!("  means {:.2} / {:.2} ns", mean(&ta), mean(&tc));
        let (d, critical) = ks(&mut ta, &mut tc);
        (d, critical, ma, mc)
    };
    let _ = run(&near, &far);
    let separated = (0..ROUNDS)
        .filter(|_| {
            let (d, critical, mn, mf) = run(&near, &far);
            println!("bind, near-banned against far digests: D {d:.4} (critical {critical:.4}); medians {mn:.1} / {mf:.1} ns");
            d > critical
        })
        .count();
    assert!(
        separated < FAIL_AT,
        "bind latency separates digests near a banned one in {separated} of {ROUNDS}"
    );
}

#[test]
fn test_timing_ks_harness() {
    // The statistic itself: equal samples do not separate, shifted ones do.
    let mut a: Vec<f64> = (0..1_000).map(|i| f64::from(i % 97)).collect();
    let mut b = a.clone();
    let (d, critical) = ks(&mut a, &mut b);
    assert!(d <= critical);
    let mut c: Vec<f64> = a.iter().map(|x| x + 20.0).collect();
    let (d, critical) = ks(&mut a, &mut c);
    assert!(d > critical);
}
