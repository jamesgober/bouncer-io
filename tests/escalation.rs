//! Escalation, offender memory, shared addresses, datagrams (0.5).
//! Threats T-2, T-3, T-4, T-5, T-25; edge cases 47 to 49, 51, 52, 54.

use std::{
    net::IpAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use bouncer_io::{
    AccountKey, Actor, AllowList, BanKey, BanSpec, Bouncer, Budgets, Cidr, DatagramVerdict,
    Directive, DurationPolicy, Enforcement, EscalationPolicy, Event, EventSink, Filter, Mode, Page,
    Rate, Reason, RequestId, SessionKey, StrikeKind, StrikeOutcome, signals,
};
use clock_lib::ManualClock;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn c(s: &str) -> Cidr {
    s.parse().unwrap()
}

/// An address in 2001:db8:`a`::/48, in /56 number `s` and /64 number `h`
/// of that /56.
fn v6(a: u16, s: u16, h: u16) -> IpAddr {
    IpAddr::from([0x2001, 0xdb8, a, (s << 8) | h, 0, 0, 0, 1])
}

#[derive(Default)]
struct Sink(Mutex<Vec<(u32, Mode, Option<Cidr>)>>);
impl EventSink for Sink {
    fn event(&self, e: &Event<'_>) {
        self.0
            .lock()
            .unwrap()
            .push((e.signal.id, e.mode, e.subject.prefix));
    }
}

impl Sink {
    fn count(&self, id: u32, mode: Mode) -> usize {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.0 == id && e.1 == mode)
            .count()
    }
}

fn local(addr: IpAddr) -> BanSpec {
    BanSpec::address(addr)
        .by(Actor::Local)
        .because(Reason::STRIKE_THRESHOLD)
}

#[test]
fn test_escalation_ipv4_eight_hosts_bans_24() {
    // T-3.
    let sink = Arc::new(Sink::default());
    let b = Bouncer::builder()
        .event_sink(sink.clone())
        .try_build()
        .unwrap();
    for i in 1..=7u8 {
        b.ban(local(IpAddr::from([198, 51, 100, i]))).unwrap();
    }
    assert!(b.door(ip("198.51.100.200")).is_ok(), "seven is not enough");
    b.ban(local(ip("198.51.100.8"))).unwrap();
    assert!(b.door(ip("198.51.100.200")).is_err(), "the /24 is banned");
    assert_eq!(sink.count(signals::BAN_ESCALATED.id, Mode::Enforce), 1);
    // The children were folded into the parent.
    let all = b.list(&Filter::all(), Page::first(100));
    assert_eq!(all.total, 1);
    assert_eq!(all.items[0].key, BanKey::Prefix(c("198.51.100.0/24")));
    // A new child inside the banned parent adds nothing.
    b.ban(local(ip("198.51.100.99"))).unwrap();
    assert_eq!(b.list(&Filter::all(), Page::first(100)).total, 1);
}

#[test]
fn test_escalation_four_64s_bans_56_then_48() {
    // T-2 and edge case 49 (stops at the widest prefix).
    let b = Bouncer::new();
    for s in 0..4u16 {
        for h in 0..4u16 {
            b.ban(local(v6(1, s, h))).unwrap();
        }
        let fifty_six = v6(1, s, 0xff);
        assert!(b.door(fifty_six).is_err(), "/56 number {s} escalated");
    }
    assert!(
        b.door(ip("2001:db8:1:ff00::1")).is_err(),
        "four /56 escalate the /48"
    );
    assert!(b.door(ip("2001:db8:2::1")).is_ok());
    // With the widest at /56, a full /48 of /56 bans stays at /56.
    let b = Bouncer::builder()
        .escalation(EscalationPolicy::default().widest_ipv6(56))
        .try_build()
        .unwrap();
    for s in 0..4u16 {
        for h in 0..4u16 {
            b.ban(local(v6(1, s, h))).unwrap();
        }
    }
    assert!(
        b.door(ip("2001:db8:1:ff00::1")).is_ok(),
        "never wider than /56"
    );
}

#[test]
fn test_escalation_blocked_by_allow_list_and_proxy_and_shared() {
    // Edge case 48, T-25.
    let sink = Arc::new(Sink::default());
    let b = Bouncer::builder()
        .allow(AllowList::new().immune(c("198.51.100.250/32"), "partner"))
        .trusted_proxies(&[c("203.0.113.250/32")])
        .event_sink(sink.clone())
        .try_build()
        .unwrap();
    for prefix in [[198, 51, 100], [203, 0, 113]] {
        for i in 1..=8u8 {
            b.ban(local(IpAddr::from([prefix[0], prefix[1], prefix[2], i])))
                .unwrap();
        }
        let other = IpAddr::from([prefix[0], prefix[1], prefix[2], 100]);
        assert!(b.door(other).is_ok(), "{other}: escalation refused");
        assert!(
            b.door(IpAddr::from([prefix[0], prefix[1], prefix[2], 3]))
                .is_err(),
            "children kept"
        );
    }
    assert_eq!(sink.count(signals::BAN_ESCALATED.id, Mode::Observe), 2);
    assert_eq!(sink.count(signals::BAN_ESCALATED.id, Mode::Enforce), 0);
}

#[test]
fn test_escalation_per_parent_quota_forces_escalation() {
    // Edge case 47.
    let b = Bouncer::builder()
        .escalation(
            EscalationPolicy::default()
                .ipv4_threshold(100)
                .max_children_per_parent(4),
        )
        .try_build()
        .unwrap();
    for i in 1..=4u8 {
        b.ban(local(IpAddr::from([192, 0, 2, i]))).unwrap();
    }
    assert!(b.door(ip("192.0.2.100")).is_ok());
    b.ban(local(ip("192.0.2.5"))).unwrap();
    assert!(b.door(ip("192.0.2.100")).is_err(), "past the quota of 4");
}

#[test]
fn test_lift_of_parent_does_not_resurrect_children() {
    // Edge case 51.
    let b = Bouncer::new();
    for i in 1..=8u8 {
        b.ban(local(IpAddr::from([198, 51, 100, i]))).unwrap();
    }
    b.lift(c("198.51.100.0/24")).unwrap();
    for i in 1..=8u8 {
        assert!(b.door(IpAddr::from([198, 51, 100, i])).is_ok());
    }
}

#[test]
fn test_escalation_flood_keeps_table_bounded() {
    // T-4: ten times the capacity in unique /64s from 64 /48s.
    let cap = 4096u32;
    let b = Bouncer::builder().ban_capacity(cap).try_build().unwrap();
    for i in 0..8u16 {
        b.ban(
            BanSpec::address(IpAddr::from([0x2001, 0xdb8, 0xaaaa, i, 0, 0, 0, 1]))
                .by(Actor::Admin(1))
                .for_duration(Duration::from_secs(86_400)),
        )
        .unwrap();
    }
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    for n in 0..(10 * cap as u64) {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        let fortyeight = (n % 64) as u16;
        let addr = IpAddr::from([
            0x2001,
            0xdb8,
            0x100 + fortyeight,
            (x & 0xffff) as u16,
            0,
            0,
            0,
            1,
        ]);
        let _ = b.ban(local(addr));
    }
    assert!(b.health().ban_load <= 1.0);
    for f in 0..64u16 {
        let probe = IpAddr::from([0x2001, 0xdb8, 0x100 + f, 0x7777, 0, 0, 0, 9]);
        assert!(b.door(probe).is_err(), "/48 number {f} ends banned");
    }
    for i in 0..8u16 {
        assert!(
            b.door(IpAddr::from([0x2001, 0xdb8, 0xaaaa, i, 0, 0, 0, 1]))
                .is_err(),
            "admin bans intact"
        );
    }
}

#[test]
fn test_offender_memory_lengthens_and_decays() {
    // Edge case 52: durations follow the decayed offences.
    let clock = Arc::new(ManualClock::new());
    let b = Bouncer::builder()
        .clock(clock.clone())
        .durations(
            DurationPolicy::default()
                .base(Duration::from_secs(100))
                .jitter(Duration::ZERO)
                .half_life(Duration::from_secs(1000)),
        )
        .try_build()
        .unwrap();
    let addr = ip("192.0.2.77");
    let length = |b: &Bouncer| {
        let r = &b.explain(addr).bans[0];
        r.until.unwrap().duration_since(r.issued).unwrap().as_secs()
    };
    b.ban(addr).unwrap();
    assert_eq!(length(&b), 100);
    clock.advance(Duration::from_secs(150));
    assert!(b.door(addr).is_ok(), "expired");
    b.ban(addr).unwrap();
    assert_eq!(length(&b), 200, "a returning offender's ban is longer");
    let o = b.explain(addr).offender.unwrap();
    assert!(o.offences > 1.8 && o.offences < 2.0, "{}", o.offences);
    clock.advance(Duration::from_secs(10_000));
    b.ban(addr).unwrap();
    assert_eq!(length(&b), 100, "ten half-lives later it is forgotten");
}

#[test]
fn test_shared_source_strikes_throttle_not_ban() {
    // T-5: 500 sessions behind one address, one attacker.
    let b = Bouncer::builder()
        .budgets(Budgets::off())
        .enforcement(Enforcement::observe_all().enforce(StrikeKind::LoginFailed))
        .try_build()
        .unwrap();
    let nat = ip("100.64.0.1");
    let conn = b.door(nat).unwrap();
    for s in 0..500u32 {
        let mut r = conn.request(RequestId(u128::from(s))).unwrap();
        let mut d = [0u8; 16];
        d[..4].copy_from_slice(&s.to_be_bytes());
        assert!(r.bind_session(SessionKey::from_digest(d)).is_pass());
    }
    assert!(b.explain(nat).shared_source);
    let attacker = SessionKey::from_digest([0xee; 16]);
    let mut last = StrikeOutcome::Counted;
    for i in 0..5u128 {
        let mut r = conn.request(RequestId(1000 + i)).unwrap();
        assert!(r.bind_session(attacker).is_pass() || i > 0);
        let _ = r.bind_account(AccountKey(66));
        last = r.strike(StrikeKind::LoginFailed);
    }
    assert_eq!(last, StrikeOutcome::Throttled);
    assert!(b.door(nat).is_ok(), "the address is not banned");
    assert!(!b.explain(attacker).admitted, "the attacker's session is");
    assert!(!b.explain(AccountKey(66)).admitted, "and its account");
    assert!(
        b.explain(SessionKey::from_digest([0; 16])).admitted,
        "nobody else"
    );
    // A weak automated directive cannot ban a shared address either.
    let applied = b
        .apply(Directive::ban(nat).by(Actor::Policy(3)).confidence(50))
        .unwrap();
    assert!(applied.downgraded && applied.ban.is_none());
    let applied = b.apply(Directive::ban(nat).by(Actor::Admin(1))).unwrap();
    assert!(applied.ban.is_some(), "an administrator still can");
}

#[test]
fn test_shared_source_blocks_escalation() {
    let b = Bouncer::builder()
        .budgets(Budgets::off())
        .try_build()
        .unwrap();
    let nat = ip("198.51.100.77");
    let conn = b.door(nat).unwrap();
    for s in 0..100u8 {
        let mut r = conn.request(RequestId(u128::from(s))).unwrap();
        let _ = r.bind_session(SessionKey::from_digest([s; 16]));
    }
    assert!(b.explain(nat).shared_source);
    for i in 1..=8u8 {
        b.ban(local(IpAddr::from([198, 51, 100, i]))).unwrap();
    }
    assert!(
        b.door(ip("198.51.100.200")).is_ok(),
        "no escalation over a shared address"
    );
}

#[test]
fn test_datagram_bans_and_budgets() {
    let clock = Arc::new(ManualClock::new());
    let b = Bouncer::builder()
        .clock(clock.clone())
        .budgets(Budgets::off().door_rate(Rate::per_second(2), Rate::per_second(5)))
        .try_build()
        .unwrap();
    b.ban(ip("192.0.2.66")).unwrap();
    assert_eq!(
        b.datagram(ip("192.0.2.66"), true, b.now()),
        DatagramVerdict::Drop
    );
    // Unverified: charged at the prefix only (5 per second for the /24).
    let accepted = (1..=20u8)
        .filter(|i| {
            b.datagram(IpAddr::from([198, 51, 100, *i]), false, b.now()) == DatagramVerdict::Accept
        })
        .count();
    assert_eq!(accepted, 5);
    // Verified: the client's own budget too.
    let accepted = (0..10)
        .filter(|_| b.datagram(ip("203.0.113.9"), true, b.now()) == DatagramVerdict::Accept)
        .count();
    assert_eq!(accepted, 2);
    clock.advance(Duration::from_secs(1));
    assert_eq!(
        b.datagram(ip("203.0.113.9"), true, b.now()),
        DatagramVerdict::Accept
    );
}
