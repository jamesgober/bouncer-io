//! The replay harness: hostile traffic of four kinds replayed through the
//! door, tickets, binds, and strikes the way a transport and a protocol
//! engine drive them (net-io's gate does exactly this, `tests/net_io.rs`),
//! on a manual clock, with innocent traffic beside it. Each trace is
//! generated from a fixed seed, so a run is repeatable.
//!
//! Each scenario counts what got through and what was refused, for the
//! attacker and for the innocents, and bounds both: the attacker is stopped
//! within its scenario's budget, and no innocent is refused.

use std::{net::IpAddr, sync::Arc, time::Duration};

use bouncer_io::{
    AccountKey, Bouncer, Budgets, ConnId, Enforcement, Provenance, Refusal, RequestId, SessionKey,
    StrikeKind, Ticket,
};
use clock_lib::ManualClock;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

/// A repeatable stream of numbers (xorshift).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// What one side of a scenario saw.
#[derive(Debug, Default, Clone, Copy)]
struct Side {
    admitted: u32,
    refused: u32,
    /// Requests that passed every check.
    served: u32,
    /// Requests refused at a bind or a checkpoint.
    denied: u32,
}

/// A replay: one bouncer on a manual clock.
struct Replay {
    clock: Arc<ManualClock>,
    bouncer: Bouncer,
    now_ms: u64,
    next_conn: u64,
    next_request: u128,
    attacker: Side,
    innocent: Side,
    /// When the attacker was first refused at the door, in ms.
    stopped_at: Option<u64>,
}

impl Replay {
    fn new(budgets: Budgets, enforcement: Enforcement) -> Replay {
        let clock = Arc::new(ManualClock::new());
        let bouncer = Bouncer::builder()
            .clock(clock.clone())
            .budgets(budgets)
            .enforcement(enforcement)
            .try_build()
            .unwrap();
        Replay {
            clock,
            bouncer,
            now_ms: 0,
            next_conn: 1,
            next_request: 1,
            attacker: Side::default(),
            innocent: Side::default(),
            stopped_at: None,
        }
    }

    /// Moves the clock to `ms` (never back).
    fn at(&mut self, ms: u64) {
        if ms > self.now_ms {
            self.clock.advance(Duration::from_millis(ms - self.now_ms));
            self.now_ms = ms;
        }
    }

    fn side(&mut self, attacker: bool) -> &mut Side {
        if attacker {
            &mut self.attacker
        } else {
            &mut self.innocent
        }
    }

    /// A connection from `peer`, as net-io's gate opens it.
    fn connect(&mut self, peer: IpAddr, attacker: bool) -> Option<Ticket> {
        let conn = ConnId(self.next_conn);
        self.next_conn += 1;
        let now = self.bouncer.now();
        match self.bouncer.door_at(conn, peer, Provenance::Socket, now) {
            Ok(t) => {
                self.side(attacker).admitted += 1;
                Some(t)
            }
            Err(r) => {
                self.side(attacker).refused += 1;
                if attacker && self.stopped_at.is_none() && matches!(r, Refusal::Banned { .. }) {
                    self.stopped_at = Some(self.now_ms);
                }
                None
            }
        }
    }

    /// A request on `conn` bound to `session` (and `account` when given);
    /// `true` when it passed.
    fn request(
        &mut self,
        conn: &Ticket,
        session: SessionKey,
        account: Option<AccountKey>,
        attacker: bool,
    ) -> Option<Ticket> {
        let id = RequestId(self.next_request);
        self.next_request += 1;
        let mut r = conn.request(id).ok()?;
        let mut pass = r.bind_session(session).is_pass();
        if let Some(a) = account {
            pass &= r.bind_account(a).is_pass();
        }
        pass &= r.checkpoint().is_pass();
        let side = self.side(attacker);
        if pass {
            side.served += 1;
            Some(r)
        } else {
            side.denied += 1;
            None
        }
    }
}

fn session(n: u64) -> SessionKey {
    let mut d = [0u8; 16];
    d[..8].copy_from_slice(&n.to_be_bytes());
    d[8] = 0x5e;
    SessionKey::from_digest(d)
}

#[test]
fn test_replay_scanner_is_banned_within_its_threshold() {
    // One IPv4 address opening 20 connections a second for a minute, each
    // sending traffic the protocol engine cannot parse; 50 neighbours in its
    // /24 browse at one connection a second each.
    let mut r = Replay::new(
        Budgets::default(),
        Enforcement::observe_all().enforce(StrikeKind::Malformed),
    );
    let scanner = ip("203.0.113.50");
    for tick in 0..1200u64 {
        r.at(tick * 50);
        if let Some(conn) = r.connect(scanner, true) {
            let _ = conn.strike(StrikeKind::Malformed);
        }
        if tick % 20 == 0 {
            for n in 1..=50u8 {
                let peer = IpAddr::from([203, 0, 113, 100 + n]);
                if let Some(conn) = r.connect(peer, false) {
                    let _ = r.request(&conn, session(u64::from(n)), None, false);
                }
            }
        }
    }
    eprintln!(
        "scanner: {:?} {:?} stopped at {:?} ms",
        r.attacker, r.innocent, r.stopped_at
    );
    assert!(
        r.attacker.admitted <= 5,
        "the default threshold: {:?}",
        r.attacker
    );
    assert!(r.stopped_at.is_some_and(|ms| ms <= 300));
    assert_eq!(r.innocent.refused, 0, "{:?}", r.innocent);
    assert_eq!(r.innocent.denied, 0);
}

#[test]
fn test_replay_slowloris_is_held_to_its_concurrency_then_banned() {
    // One address opening a connection every 10 ms and holding each until
    // the transport kills it for its rate (net-io reports `SlowPeer`, the
    // gate strikes) after 30 seconds; 20 hosts elsewhere connect twice a
    // second and close at once.
    let mut r = Replay::new(
        Budgets::default(),
        Enforcement::observe_all().enforce(StrikeKind::SlowPeer),
    );
    let attacker = ip("198.51.100.7");
    let mut held: std::collections::VecDeque<(u64, Ticket)> = Default::default();
    let mut most_held = 0usize;
    let mut rng = Rng(0x51_0e_17);
    for tick in 0..12_000u64 {
        let ms = tick * 10;
        r.at(ms);
        while held.front().is_some_and(|(at, _)| ms >= at + 30_000) {
            let (_, conn) = held.pop_front().unwrap();
            let _ = conn.strike(StrikeKind::SlowPeer);
        }
        if let Some(conn) = r.connect(attacker, true) {
            held.push_back((ms, conn));
        }
        most_held = most_held.max(held.len());
        if tick % 50 == 0 {
            for _ in 0..20 {
                let peer = IpAddr::from([192, 0, 2, 1 + rng.below(200) as u8]);
                if let Some(conn) = r.connect(peer, false) {
                    let _ = r.request(&conn, session(rng.below(1000)), None, false);
                }
            }
        }
    }
    eprintln!(
        "slowloris: {:?} {:?} most held {most_held}, stopped at {:?} ms",
        r.attacker, r.innocent, r.stopped_at
    );
    assert!(most_held <= 64, "the default concurrency per address");
    assert!(
        r.stopped_at.is_some_and(|ms| ms <= 31_000),
        "banned after five kills"
    );
    assert_eq!(r.innocent.refused, 0, "{:?}", r.innocent);
}

#[test]
fn test_replay_credential_stuffing_from_a_48_bans_the_48() {
    // Login attempts against many accounts from 2001:db8:77::/48, the
    // attacker moving to a new /64 for every attempt, spread over the /48's
    // /56s; innocents in the next /48 log in normally.
    let mut r = Replay::new(
        Budgets::default(),
        Enforcement::observe_all().enforce(StrikeKind::LoginFailed),
    );
    let mut rng = Rng(0xc4ed);
    let mut attempts = 0u32;
    for tick in 0..6000u64 {
        r.at(tick * 100);
        let s = rng.below(256) as u16;
        let h = rng.below(256) as u16;
        let peer = IpAddr::from([0x2001, 0xdb8, 0x77, (s << 8) | h, 0, 0, 0, 1]);
        if let Some(conn) = r.connect(peer, true) {
            attempts += 1;
            if let Some(req) = r.request(
                &conn,
                session(tick),
                Some(AccountKey(u128::from(tick))),
                true,
            ) {
                let _ = req.strike(StrikeKind::LoginFailed);
            }
        }
        if tick % 10 == 0 {
            let peer = IpAddr::from([0x2001, 0xdb8, 0x78, rng.below(4096) as u16, 0, 0, 0, 1]);
            if let Some(conn) = r.connect(peer, false) {
                let _ = r.request(&conn, session(1_000_000 + tick % 50), None, false);
            }
        }
    }
    let banned = r.bouncer.door(ip("2001:db8:77:ffff::9")).is_err();
    eprintln!(
        "stuffing: {:?} {:?} attempts {attempts}, /48 banned {banned}, stopped at {:?} ms",
        r.attacker, r.innocent, r.stopped_at
    );
    assert!(banned, "the /48 ends banned");
    // Five strikes per /64, four /64s per /56, four /56s per /48: the
    // strikes escalation would need, and not one attempt more.
    assert!(attempts <= 80, "{attempts} attempts got through");
    assert_eq!(r.innocent.refused, 0, "{:?}", r.innocent);
    assert_eq!(r.innocent.denied, 0);
}

#[test]
fn test_replay_cgnat_population_keeps_its_users_and_loses_its_attacker() {
    // 2,000 users behind one carrier-grade NAT address, each connecting
    // every 20 seconds on average and holding the connection for 2 seconds;
    // one of them tries passwords against one account. Default budgets.
    let mut r = Replay::new(
        Budgets::default(),
        Enforcement::observe_all().enforce(StrikeKind::LoginFailed),
    );
    let nat = ip("100.64.12.34");
    let attacker = session(0xbad);
    let mut rng = Rng(0xc9a7);
    let mut held: std::collections::VecDeque<(u64, Ticket)> = Default::default();
    let mut attacker_served_late = 0u32;
    for tick in 0..12_000u64 {
        let ms = tick * 10;
        r.at(ms);
        while held.front().is_some_and(|(at, _)| ms >= at + 2_000) {
            held.pop_front();
        }
        // 2,000 users every 20 s: one connection per 10 ms on average.
        if let Some(conn) = r.connect(nat, false) {
            let user = rng.below(2000);
            let _ = r.request(&conn, session(user), None, false);
            held.push_back((ms, conn));
        }
        if tick % 100 == 0 {
            if let Some(conn) = r.connect(nat, true) {
                if let Some(req) = r.request(&conn, attacker, Some(AccountKey(42)), true) {
                    let _ = req.strike(StrikeKind::LoginFailed);
                    if ms > 60_000 {
                        attacker_served_late += 1;
                    }
                }
            }
        }
    }
    eprintln!(
        "cgnat: {:?} {:?} attacker served after a minute {attacker_served_late}",
        r.attacker, r.innocent
    );
    assert!(r.bouncer.explain(nat).shared_source);
    assert!(r.bouncer.door(nat).is_ok(), "the address is not banned");
    assert_eq!(attacker_served_late, 0, "the attacker's session is");
    assert_eq!(r.innocent.refused, 0, "{:?}", r.innocent);
    assert_eq!(r.innocent.denied, 0);
}
