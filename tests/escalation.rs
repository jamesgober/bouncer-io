//! Escalation, offender memory, shared addresses, datagrams (0.5).
//! Threats T-2, T-3, T-4, T-5, T-20, T-25; edge cases 49 to 51, 53, 54, 56.

use std::{
    net::IpAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use bouncer_io::{
    AccountKey, Actor, AllowList, BanKey, BanKeys, Bouncer, Budgets, Cidr, DatagramVerdict,
    Directive, DurationPolicy, Enforcement, EscalationPolicy, Event, EventSink, Filter, Mode, Page,
    Rate, Reason, RequestId, SessionKey, SharedAddresses, StrikeKind, StrikeOutcome, signals,
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

fn local(addr: IpAddr) -> Directive {
    Directive::ban(addr)
        .by(Actor::Local)
        .because(Reason::STRIKE_THRESHOLD)
}

#[test]
fn test_escalation_ipv4_eight_hosts_bans_24() {
    // T-3.
    let sink = Arc::new(Sink::default());
    let b = Bouncer::builder().event_sink(sink.clone()).build().unwrap();
    for i in 1..=7u8 {
        b.apply(local(IpAddr::from([198, 51, 100, i]))).unwrap();
    }
    assert!(b.door(ip("198.51.100.200")).is_ok(), "seven is not enough");
    b.apply(local(ip("198.51.100.8"))).unwrap();
    assert!(b.door(ip("198.51.100.200")).is_err(), "the /24 is banned");
    assert_eq!(sink.count(signals::BAN_ESCALATED.id, Mode::Enforce), 1);
    // The children were folded into the parent.
    let all = b.list(&Filter::all(), Page::first(100));
    assert_eq!(all.total, 1);
    assert_eq!(all.items[0].key, BanKey::Prefix(c("198.51.100.0/24")));
    // A new child inside the banned parent adds nothing.
    b.apply(local(ip("198.51.100.99"))).unwrap();
    assert_eq!(b.list(&Filter::all(), Page::first(100)).total, 1);
}

#[test]
fn test_escalation_four_64s_bans_56_then_48() {
    // T-2 and edge case 51 (stops at the widest prefix).
    let b = Bouncer::new();
    for s in 0..4u16 {
        for h in 0..4u16 {
            b.apply(local(v6(1, s, h))).unwrap();
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
        .build()
        .unwrap();
    for s in 0..4u16 {
        for h in 0..4u16 {
            b.apply(local(v6(1, s, h))).unwrap();
        }
    }
    assert!(
        b.door(ip("2001:db8:1:ff00::1")).is_ok(),
        "never wider than /56"
    );
}

#[test]
fn test_escalation_blocked_by_allow_list_and_proxy_and_shared() {
    // Edge case 50, T-25.
    let sink = Arc::new(Sink::default());
    let b = Bouncer::builder()
        .allow(AllowList::new().immune(c("198.51.100.250/32"), "partner"))
        .trusted_proxies(&[c("203.0.113.250/32")])
        .event_sink(sink.clone())
        .build()
        .unwrap();
    for prefix in [[198, 51, 100], [203, 0, 113]] {
        for i in 1..=8u8 {
            b.apply(local(IpAddr::from([prefix[0], prefix[1], prefix[2], i])))
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
    // Edge case 49.
    let b = Bouncer::builder()
        .escalation(
            EscalationPolicy::default()
                .ipv4_threshold(100)
                .max_children_per_parent(4),
        )
        .build()
        .unwrap();
    for i in 1..=4u8 {
        b.apply(local(IpAddr::from([192, 0, 2, i]))).unwrap();
    }
    assert!(b.door(ip("192.0.2.100")).is_ok());
    b.apply(local(ip("192.0.2.5"))).unwrap();
    assert!(b.door(ip("192.0.2.100")).is_err(), "past the quota of 4");
}

#[test]
fn test_lift_of_parent_does_not_resurrect_children() {
    // Edge case 53.
    let b = Bouncer::new();
    for i in 1..=8u8 {
        b.apply(local(IpAddr::from([198, 51, 100, i]))).unwrap();
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
    let b = Bouncer::builder().ban_capacity(cap).build().unwrap();
    for i in 0..8u16 {
        b.apply(
            Directive::ban(IpAddr::from([0x2001, 0xdb8, 0xaaaa, i, 0, 0, 0, 1]))
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
        let _ = b.apply(local(addr));
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
    // Edge case 54: durations follow the decayed offences.
    let clock = Arc::new(ManualClock::new());
    let b = Bouncer::builder()
        .clock(clock.clone())
        .durations(
            DurationPolicy::default()
                .base(Duration::from_secs(100))
                .jitter(Duration::ZERO)
                .half_life(Duration::from_secs(1000)),
        )
        .build()
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
    // T-5: 500 accounts behind one address, one attacker.
    let b = Bouncer::builder()
        .budgets(Budgets::off())
        .enforcement(Enforcement::observe_all().enforce(StrikeKind::LoginFailed))
        .build()
        .unwrap();
    let nat = ip("100.64.0.1");
    let conn = b.door(nat).unwrap();
    for s in 0..500u32 {
        let mut r = conn.request(RequestId(u128::from(s))).unwrap();
        assert!(
            r.bind_account(AccountKey(0x1_0000 + u128::from(s)))
                .is_pass()
        );
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
fn test_known_shared_ranges_block_escalation_and_detected_addresses_do_not() {
    // D-137: a range the deployment names as shared keeps escalation off
    // its prefix. An address flagged by detection does not: a client that
    // earned the flag would otherwise shield its whole /24.
    let run = |policy: SharedAddresses| {
        let b = Bouncer::builder()
            .budgets(Budgets::off())
            .shared_addresses(policy)
            .build()
            .unwrap();
        let nat = ip("198.51.100.77");
        let conn = b.door(nat).unwrap();
        for s in 0..100u32 {
            let mut r = conn.request(RequestId(u128::from(s))).unwrap();
            let _ = r.bind_account(AccountKey(0x2_0000 + u128::from(s)));
        }
        assert!(b.explain(nat).shared_source);
        for i in 1..=8u8 {
            b.apply(local(IpAddr::from([198, 51, 100, i]))).unwrap();
        }
        b.door(ip("198.51.100.200")).is_err()
    };
    assert!(
        run(SharedAddresses::detect()),
        "escalated over a detected address"
    );
    assert!(
        !run(SharedAddresses::detect().known(&["198.51.100.77/32".parse().unwrap()])),
        "no escalation over a known shared range"
    );
}

#[test]
fn test_datagram_bans_and_budgets() {
    let clock = Arc::new(ManualClock::new());
    let b = Bouncer::builder()
        .clock(clock.clone())
        .budgets(Budgets::off().door_rate(Rate::per_second(2), Rate::per_second(5)))
        .build()
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

#[test]
fn test_datagram_unverified_never_banned() {
    // Threat T-20: a forged UDP source is never struck, banned, or escalated,
    // however much of it arrives, under the strictest enforcement.
    let sink = Arc::new(Sink::default());
    let b = Bouncer::builder()
        .enforcement(Enforcement::enforce_all())
        .event_sink(sink.clone())
        .budgets(Budgets::off().door_rate(Rate::per_second(2), Rate::per_second(5)))
        .build()
        .unwrap();
    let victim = ip("192.0.2.80");
    let dropped = (0..100_000)
        .filter(|_| b.datagram(victim, false, b.now()) == DatagramVerdict::Drop)
        .count();
    assert!(dropped > 99_000, "the flood is dropped at the budget");
    let _ = b.maintain(b.now());
    let seen = b.explain(victim);
    assert!(seen.bans.is_empty(), "{seen:?}");
    assert!(seen.admitted);
    assert!(b.explain(c("192.0.2.0/24")).bans.is_empty());
    assert!(
        b.door(victim).is_ok(),
        "the victim's own connections still pass"
    );
    assert_eq!(sink.count(signals::BAN_ADDED.id, Mode::Enforce), 0);
    assert_eq!(sink.count(signals::BAN_ADDED.id, Mode::Observe), 0);
}

#[test]
fn test_datagram_forged_flood_does_not_starve_verified_sources() {
    // Threat T-20 (budget part): forged datagrams naming a victim's prefix
    // drain only the unverified budget; the victim's verified datagrams
    // keep their own client and prefix budgets.
    let b = Bouncer::builder()
        .budgets(Budgets::off().door_rate(Rate::per_second(2), Rate::per_second(5)))
        .build()
        .unwrap();
    for i in 0..1_000u32 {
        let forged = IpAddr::from([192, 0, 2, (i % 250) as u8 + 1]);
        let _ = b.datagram(forged, false, b.now());
    }
    let victim = ip("192.0.2.80");
    assert_eq!(
        b.datagram(victim, true, b.now()),
        DatagramVerdict::Accept,
        "a verified source is not starved by forged traffic from its prefix"
    );
    // Unverified traffic from the prefix stays capped.
    assert_eq!(
        b.datagram(ip("192.0.2.81"), false, b.now()),
        DatagramVerdict::Drop
    );
}

#[test]
fn test_lifted_children_do_not_count_toward_escalation() {
    let b = Bouncer::new();
    for i in 1..=20u8 {
        let addr = IpAddr::from([198, 51, 100, i]);
        b.apply(local(addr)).unwrap();
        b.lift(addr).unwrap();
    }
    assert!(
        b.door(ip("198.51.100.200")).is_ok(),
        "never more than one banned at a time"
    );
}

#[test]
fn test_prefix_strikes_never_ban_over_a_known_shared_range() {
    // T-5 and D-108: strikes from a /24's hosts reach the prefix threshold
    // (40 at the default). A range named as shared keeps the /24 from being
    // banned; an address flagged by detection does not (D-137), though its
    // own strikes never count at the prefix.
    let run = |policy: Option<SharedAddresses>| {
        let mut builder = Bouncer::builder()
            .budgets(Budgets::off())
            .enforcement(Enforcement::observe_all().enforce(StrikeKind::LoginFailed));
        if let Some(policy) = policy {
            builder = builder.shared_addresses(policy);
        }
        let b = builder.build().unwrap();
        let nat = ip("100.64.0.1");
        let conn = b.door(nat).unwrap();
        for s in 0..100u32 {
            let mut r = conn.request(RequestId(u128::from(s))).unwrap();
            let _ = r.bind_account(AccountKey(0x3_0000 + u128::from(s)));
        }
        assert!(b.explain(nat).shared_source);
        // Four strikes from each of twelve hosts: none reaches its own
        // threshold, the /24 passes 40.
        for h in 10..22u8 {
            for _ in 0..4 {
                // Once the /24 is banned, its hosts are refused.
                if let Ok(conn) = b.door(IpAddr::from([100, 64, 0, h])) {
                    let _ = conn.strike(StrikeKind::LoginFailed);
                }
            }
        }
        b.door(ip("100.64.0.200")).is_err()
    };
    assert!(run(None), "the /24 is banned over a detected address");
    assert!(
        !run(Some(
            SharedAddresses::detect().known(&["100.64.0.1/32".parse().unwrap()])
        )),
        "no prefix ban over a known shared range"
    );

    // The shared address's own strikes do not add up to a prefix ban.
    let b = Bouncer::builder()
        .budgets(Budgets::off())
        .enforcement(Enforcement::observe_all().enforce(StrikeKind::LoginFailed))
        .build()
        .unwrap();
    let nat = ip("100.64.0.2");
    let conn = b.door(nat).unwrap();
    for s in 0..100u32 {
        let mut r = conn.request(RequestId(u128::from(s))).unwrap();
        let _ = r.bind_account(AccountKey(0x4_0000 + u128::from(s)));
    }
    for _ in 0..4 {
        let _ = conn.strike(StrikeKind::LoginFailed);
    }
    for h in 10..19u8 {
        for _ in 0..4 {
            let _ = b
                .door(IpAddr::from([100, 64, 0, h]))
                .unwrap()
                .strike(StrikeKind::LoginFailed);
        }
    }
    assert!(
        b.door(ip("100.64.0.200")).is_ok(),
        "36 strikes from ordinary hosts, the shared address's not counted"
    );
}

#[test]
fn test_connection_ban_never_takes_a_shared_address_on_a_weak_word() {
    // T-5: a directive aimed at a connection or request behind a shared
    // address bans the ticket's session, not the address, unless a strong
    // actor names the address itself.
    let setup = || {
        let b = Bouncer::builder().budgets(Budgets::off()).build().unwrap();
        let nat = ip("100.64.0.9");
        let conn = b.door(nat).unwrap();
        for s in 0..500u32 {
            let mut r = conn.request(RequestId(u128::from(s))).unwrap();
            assert!(
                r.bind_account(AccountKey(0x1_0000 + u128::from(s)))
                    .is_pass()
            );
        }
        assert!(b.explain(nat).shared_source);
        (b, nat, conn)
    };
    let attacker = SessionKey::from_digest([0xab; 16]);

    // A weak actor, the default keys: the session, not the address.
    let (b, nat, conn) = setup();
    let mut r = conn.request(RequestId(9_000)).unwrap();
    assert!(r.bind_session(attacker).is_pass());
    let applied = b
        .apply(
            Directive::revoke_and_ban(RequestId(9_000))
                .by(Actor::Policy(3))
                .confidence(50),
        )
        .unwrap();
    assert!(b.door(nat).is_ok(), "the shared address is not banned");
    assert!(!b.explain(attacker).admitted, "the request's session is");
    assert_eq!(applied.bans, 1);

    // A weak actor that asks for the source by name: refused, recorded.
    let (b, nat, conn) = setup();
    let _r = conn.request(RequestId(9_001)).unwrap();
    let applied = b
        .apply(
            Directive::ban(RequestId(9_001))
                .by(Actor::Local)
                .ban_keys(BanKeys::SOURCE),
        )
        .unwrap();
    assert!(b.door(nat).is_ok(), "a local heuristic cannot ban it");
    assert!(applied.downgraded && applied.bans == 0);

    // A peer node's channel is weak too.
    let (b, nat, conn) = setup();
    let mut r = conn.request(RequestId(9_002)).unwrap();
    assert!(r.bind_session(attacker).is_pass());
    b.apply(Directive::ban(RequestId(9_002)).by(Actor::Channel(2)))
        .unwrap();
    assert!(b.door(nat).is_ok());
    assert!(!b.explain(attacker).admitted);

    // The default keys with a strong actor: still the session, as documented.
    let (b, nat, conn) = setup();
    let mut r = conn.request(RequestId(9_003)).unwrap();
    assert!(r.bind_session(attacker).is_pass());
    b.apply(Directive::ban(RequestId(9_003)).by(Actor::Admin(1)))
        .unwrap();
    assert!(b.door(nat).is_ok());
    assert!(!b.explain(attacker).admitted);

    // A strong actor that names the source bans it.
    let (b, nat, conn) = setup();
    let _r = conn.request(RequestId(9_004)).unwrap();
    let applied = b
        .apply(
            Directive::ban(RequestId(9_004))
                .by(Actor::Admin(1))
                .ban_keys(BanKeys::SOURCE),
        )
        .unwrap();
    assert!(applied.ban.is_some() && !applied.downgraded);
    assert!(b.door(nat).is_err(), "an administrator still can");

    // Nothing shared: the default keys ban the source, as before.
    let b = Bouncer::builder().budgets(Budgets::off()).build().unwrap();
    let addr = ip("198.51.100.40");
    let conn = b.door(addr).unwrap();
    let _r = conn.request(RequestId(1)).unwrap();
    b.apply(
        Directive::ban(RequestId(1))
            .by(Actor::Policy(3))
            .confidence(50),
    )
    .unwrap();
    assert!(b.door(addr).is_err());
}

#[test]
fn test_decoy_touch_behind_a_shared_address_bans_the_identities_only() {
    // T-5: a decoy touch is definitive for whoever touched it, but bouncer's
    // own word never bans a shared address (likely a NAT).
    let b = Bouncer::builder().budgets(Budgets::off()).build().unwrap();
    let nat = ip("100.64.0.33");
    let conn = b.door(nat).unwrap();
    for s in 0..500u32 {
        let mut r = conn.request(RequestId(u128::from(s))).unwrap();
        assert!(
            r.bind_account(AccountKey(0x1_0000 + u128::from(s)))
                .is_pass()
        );
    }
    assert!(b.explain(nat).shared_source);
    let toucher = SessionKey::from_digest([0xdc; 16]);
    let mut r = conn.request(RequestId(9_100)).unwrap();
    assert!(r.bind_session(toucher).is_pass());
    assert!(r.bind_account(AccountKey(91)).is_pass());
    let outcome = r.strike(StrikeKind::DecoyTouched);
    assert!(matches!(outcome, StrikeOutcome::Banned(_)), "{outcome:?}");
    assert!(r.checkpoint().is_deny(), "the touching request is revoked");
    assert!(b.door(nat).is_ok(), "the shared address is not banned");
    assert!(!b.explain(toucher).admitted);
    assert!(!b.explain(AccountKey(91)).admitted);
    assert!(
        b.explain(SessionKey::from_digest([0; 16])).admitted,
        "nobody else"
    );

    // Nothing shared: the source is banned, as before.
    let b = Bouncer::builder().budgets(Budgets::off()).build().unwrap();
    let addr = ip("198.51.100.41");
    let conn = b.door(addr).unwrap();
    assert!(matches!(
        conn.strike(StrikeKind::DecoyTouched),
        StrikeOutcome::Banned(_)
    ));
    assert!(b.door(addr).is_err());
}
