//! The regression gate: hot paths in their own functions, for an
//! instruction count under Callgrind (deterministic, unlike time on a shared
//! machine). CI runs `valgrind --tool=callgrind` on this binary and
//! `scripts/gate.py` compares each `gate_*` function's inclusive count with
//! `benches/gate-baseline.txt`; more than 5% over blocks the change.
//!
//! Fixed seeds, fixed inputs: the counts repeat run to run.

use std::{hint::black_box, net::IpAddr};

use bouncer_io::{
    BanSpec, Bouncer, Budgets, Cidr, ConnId, Provenance, Rate, RequestId, SessionKey, Ticket,
};

/// Operations per gated function.
const OPS: usize = 10_000;

fn addr(i: usize) -> IpAddr {
    IpAddr::from([198, 18 + (i >> 16) as u8 % 2, (i >> 8) as u8, i as u8])
}

#[inline(never)]
fn gate_door_admitted(b: &Bouncer, peers: &[IpAddr]) {
    let now = b.now();
    for (i, p) in peers.iter().enumerate() {
        black_box(
            b.door_at(ConnId(i as u64), *p, Provenance::Socket, now)
                .is_ok(),
        );
    }
}

#[inline(never)]
fn gate_door_banned(b: &Bouncer, peers: &[IpAddr]) {
    let now = b.now();
    for (i, p) in peers.iter().enumerate() {
        black_box(
            b.door_at(ConnId(i as u64), *p, Provenance::Socket, now)
                .is_err(),
        );
    }
}

#[inline(never)]
fn gate_request_cycle(conn: &Ticket) {
    for i in 0..OPS {
        black_box(conn.request(RequestId(i as u128 + 100)).is_ok());
    }
}

#[inline(never)]
fn gate_checkpoint(req: &mut Ticket) {
    for _ in 0..OPS {
        black_box(req.checkpoint().is_pass());
    }
}

#[inline(never)]
fn gate_bind_session(conn: &Ticket) {
    for i in 0..OPS {
        let mut r = conn.request(RequestId(i as u128 + 1_000_000)).unwrap();
        let mut d = [0u8; 16];
        d[..8].copy_from_slice(&(i as u64).to_le_bytes());
        black_box(r.bind_session(SessionKey::from_digest(d)).is_pass());
    }
}

#[inline(never)]
fn gate_ban_insert(b: &Bouncer) {
    for i in 0..OPS {
        let a = IpAddr::from([100, 64 + (i >> 16) as u8 % 64, (i >> 8) as u8, i as u8]);
        black_box(b.ban(a).is_ok());
    }
}

fn main() {
    let rate = Rate::per_second(1_000_000_000).burst(1_000_000_000);
    let b = Bouncer::builder()
        .budgets(Budgets::off().door_rate(rate, rate).capacity(1 << 16))
        .ban_capacity(1 << 17)
        .tickets(1 << 15)
        .seed([7; 32])
        .escalation(bouncer_io::EscalationPolicy::default().off())
        .try_build()
        .unwrap();
    // 50,000 bans over the automatic lengths.
    for i in 0..25_000usize {
        let v4 = IpAddr::from([203, (i >> 16) as u8, (i >> 8) as u8, i as u8]);
        let _ = b.ban(BanSpec::prefix(Cidr::new(v4, 32).unwrap()).permanent());
        let v6 = IpAddr::from([0x2001, 0xdb8, i as u16, 0, 0, 0, 0, 1]);
        let _ = b.ban(BanSpec::prefix(Cidr::new(v6, 48).unwrap()).permanent());
    }
    let admitted: Vec<IpAddr> = (0..OPS).map(addr).collect();
    let banned: Vec<IpAddr> = (0..OPS)
        .map(|i| IpAddr::from([203, (i >> 16) as u8, (i >> 8) as u8, i as u8]))
        .collect();
    gate_door_admitted(&b, &admitted);
    gate_door_banned(&b, &banned);
    let conn = b.door("192.0.2.1".parse().unwrap()).unwrap();
    gate_request_cycle(&conn);
    let mut req = conn.request(RequestId(1)).unwrap();
    gate_checkpoint(&mut req);
    gate_bind_session(&conn);
    gate_ban_insert(&b);
}
