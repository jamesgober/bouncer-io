//! Door and checkpoint latency percentiles with 1,000,000 bans and 10,000
//! administrator prefixes.
//!
//! `cargo run --release --example door_p99`

use std::{
    net::IpAddr,
    time::{Duration, Instant},
};

use bouncer_io::{BanSpec, Bouncer, Cidr, ConnId, Provenance, RequestId};

fn v6(bits: u128) -> IpAddr {
    IpAddr::V6(std::net::Ipv6Addr::from(bits))
}

struct Mix(u64);
impl Mix {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

fn percentile(sorted: &[Duration], p: f64) -> Duration {
    sorted[((sorted.len() as f64 - 1.0) * p) as usize]
}

fn report(name: &str, mut samples: Vec<Duration>, overhead: Duration) {
    samples.sort_unstable();
    let ns = |p: f64| percentile(&samples, p).saturating_sub(overhead).as_nanos() as f64;
    let mean = samples.iter().sum::<Duration>().as_nanos() as f64 / samples.len() as f64
        - overhead.as_nanos() as f64;
    println!(
        "{name:<24} mean {mean:>7.1} ns   p50 {:>7.1} ns   p99 {:>7.1} ns   p99.9 {:>8.1} ns",
        ns(0.50),
        ns(0.99),
        ns(0.999)
    );
}

/// The median cost of one `Instant::now()` pair, subtracted from samples.
fn timer_overhead() -> Duration {
    let mut v: Vec<Duration> = (0..100_000)
        .map(|_| {
            let t = Instant::now();
            t.elapsed()
        })
        .collect();
    v.sort_unstable();
    v[v.len() / 2]
}

fn main() {
    let started = Instant::now();
    let b = Bouncer::builder()
        .ban_capacity(1_100_000)
        .tickets(4096)
        .seed([9; 32])
        .try_build()
        .unwrap();
    let mut m = Mix(1);
    let mut banned = Vec::new();
    for (len, is_v6, count) in [
        (32u8, false, 300_000u32),
        (24, false, 200_000),
        (64, true, 300_000),
        (56, true, 100_000),
        (48, true, 100_000),
    ] {
        for _ in 0..count {
            let addr = if is_v6 {
                v6((u128::from(m.next()) << 64) | u128::from(m.next()) | (0x2001u128 << 112))
            } else {
                IpAddr::from((m.next() as u32 | 0x8000_0000).to_be_bytes())
            };
            if b.ban(BanSpec::prefix(Cidr::new(addr, len).unwrap()).permanent())
                .is_ok()
                && banned.len() < 100_000
            {
                banned.push(addr);
            }
        }
    }
    let mut admin = 0;
    while admin < 10_000 {
        let r = m.next();
        let cidr = if r % 2 == 0 {
            let len = 8 + (r >> 8) as u8 % 23;
            if len == 24 {
                continue;
            }
            Cidr::new(
                IpAddr::from((m.next() as u32 & 0x7fff_ffff).to_be_bytes()),
                len,
            )
            .unwrap()
        } else {
            let len = 20 + (r >> 8) as u8 % 100;
            if [48, 56, 64].contains(&len) {
                continue;
            }
            Cidr::new(v6((u128::from(m.next()) << 64) | (0x2a00u128 << 112)), len).unwrap()
        };
        if b.ban(cidr).is_ok() {
            admin += 1;
        }
    }
    let cap = b.capacity();
    println!(
        "fixture: 1,000,000 bans + 10,000 admin prefixes in {:.1} s; tables {} MiB",
        started.elapsed().as_secs_f64(),
        cap.total_bytes / (1 << 20)
    );

    let n = 1_000_000;
    let mut admitted: Vec<IpAddr> = Vec::with_capacity(n);
    while admitted.len() < n {
        let peer = if admitted.len() % 2 == 0 {
            IpAddr::from((m.next() as u32).to_be_bytes())
        } else {
            v6((0x2001_u128 << 112) | (u128::from(m.next()) << 64) | u128::from(m.next()))
        };
        if b.door(peer).is_ok() {
            admitted.push(peer);
        }
    }
    let overhead = timer_overhead();
    println!(
        "timer overhead (median Instant pair): {} ns, subtracted",
        overhead.as_nanos()
    );
    let now = b.now();
    for round in 0..2 {
        let mut adm = Vec::with_capacity(n);
        for (i, &peer) in admitted.iter().enumerate() {
            let t0 = Instant::now();
            let t = b.door_at(ConnId(i as u64), peer, Provenance::Socket, now);
            adm.push(t0.elapsed());
            drop(t);
        }
        let mut ban = Vec::with_capacity(n);
        for i in 0..n {
            let peer = banned[i % banned.len()];
            let t0 = Instant::now();
            let r = b.door_at(ConnId(i as u64), peer, Provenance::Socket, now);
            ban.push(t0.elapsed());
            assert!(r.is_err());
        }
        if round == 1 {
            report("door, admitted", adm, overhead);
            report("door, banned", ban, overhead);
        }
    }
    let conn = b.door(admitted[0]).unwrap();
    let mut req = conn.request(RequestId(1)).unwrap();
    let batch = 1000;
    let mut cp = Vec::with_capacity(n / batch);
    for _ in 0..n / batch {
        let t0 = Instant::now();
        for _ in 0..batch {
            let _ = std::hint::black_box(req.checkpoint());
        }
        cp.push(t0.elapsed() / batch as u32);
    }
    report("checkpoint (per call)", cp, Duration::ZERO);
    println!("(timer: std::time::Instant; door samples include the ticket issue and release)");
}
