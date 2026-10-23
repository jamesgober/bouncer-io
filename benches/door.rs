//! The door with 1,000,000 bans over every automatic length and 10,000
//! administrator prefixes (NFR-2), and the checkpoint fast path (NFR-1).
//!
//! `cargo bench --bench door`. The p99 numbers come from
//! `cargo run --release --example door_p99`.

use std::{hint::black_box, net::IpAddr};

use bouncer_io::{BanSpec, Bouncer, Cidr, ConnId, Provenance, RequestId};
use criterion::{Criterion, criterion_group, criterion_main};

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

/// A bouncer holding the NFR-2 fixture, plus banned and admitted probes.
pub fn fixture() -> (Bouncer, Vec<IpAddr>, Vec<IpAddr>) {
    let b = Bouncer::builder()
        .ban_capacity(1_100_000)
        .tickets(4096)
        .seed([9; 32])
        .try_build()
        .unwrap();
    let mut m = Mix(1);
    let mut banned = Vec::new();
    let plan: [(u8, bool, u32); 5] = [
        (32, false, 300_000),
        (24, false, 200_000),
        (64, true, 300_000),
        (56, true, 100_000),
        (48, true, 100_000),
    ];
    for (len, is_v6, count) in plan {
        for _ in 0..count {
            let addr = if is_v6 {
                v6(((u128::from(m.next()) << 64) | u128::from(m.next())) | (0x2001u128 << 112))
            } else {
                IpAddr::from((m.next() as u32 | 0x8000_0000).to_be_bytes())
            };
            let cidr = Cidr::new(addr, len).unwrap();
            if b.ban(BanSpec::prefix(cidr).permanent()).is_ok() && banned.len() < 4096 {
                banned.push(addr);
            }
        }
    }
    let mut admin = 0;
    while admin < 10_000 {
        let r = m.next();
        let cidr = if r % 2 == 0 {
            let len = 8 + (r >> 8) as u8 % 23; // 8..=30, skipping the automatic lengths below
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
    let admitted = (0..4096)
        .map(|i| {
            if i % 2 == 0 {
                IpAddr::from([192, 0, (i >> 8) as u8, i as u8])
            } else {
                v6((0x3fff_u128 << 112) | u128::from(m.next()))
            }
        })
        .collect();
    (b, banned, admitted)
}

fn benches(c: &mut Criterion) {
    let (b, banned, admitted) = fixture();
    let now = b.now();
    let mut i = 0usize;
    c.bench_function("door_1m/admitted", |bench| {
        bench.iter(|| {
            i = (i + 1) & 4095;
            let t = b.door_at(
                ConnId(i as u64),
                black_box(admitted[i]),
                Provenance::Socket,
                now,
            );
            black_box(t.is_ok())
        })
    });
    c.bench_function("door_1m/banned", |bench| {
        bench.iter(|| {
            i = (i + 1) % banned.len();
            let t = b.door_at(
                ConnId(i as u64),
                black_box(banned[i]),
                Provenance::Socket,
                now,
            );
            black_box(t.is_err())
        })
    });
    let conn = b.door(admitted[0]).unwrap();
    let mut req = conn.request(RequestId(1)).unwrap();
    c.bench_function("checkpoint_fast", |bench| {
        bench.iter(|| black_box(req.checkpoint().is_pass()))
    });
    c.bench_function("ticket_cycle", |bench| {
        bench.iter(|| black_box(conn.request(RequestId(2)).is_ok()))
    });
}

criterion_group! {
    name = door;
    config = Criterion::default().sample_size(50);
    targets = benches
}
criterion_main!(door);
