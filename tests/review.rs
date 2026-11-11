//! Regressions from the 0.10 security and performance review: each test
//! failed before its fix.

use std::net::IpAddr;
use std::sync::{Arc, Barrier};
use std::time::Duration;

use bouncer_io::{
    AccountKey, AllowKind, AllowList, Bouncer, BouncerError, Budgets, Cidr, Collected,
    DatagramVerdict, Directive, Enforcement, IgnoredBecause, Provenance, Reason, RequestId,
    SessionKey, StrikeKind, StrikeOutcome,
};
use clock_lib::ManualClock;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn session(i: u32) -> SessionKey {
    let mut d = [0u8; 16];
    d[..4].copy_from_slice(&i.to_be_bytes());
    d[4] = 0xa5;
    SessionKey::from_digest(d)
}

fn burst(b: &Bouncer, addr: IpAddr, tries: usize) -> usize {
    let mut held = Vec::new();
    for _ in 0..tries {
        if let Ok(t) = b.door(addr) {
            held.push(t);
        }
    }
    held.len()
}

/// Binds `n` distinct accounts from `addr`, each on its own request.
fn bind_accounts(b: &Bouncer, addr: IpAddr, n: u32) {
    let conn = b.door(addr).unwrap();
    for i in 0..n {
        let mut r = conn.request(RequestId(u128::from(i))).unwrap();
        assert!(r.bind_account(AccountKey(0x1000 + u128::from(i))).is_pass());
    }
}

#[test]
fn test_minted_sessions_do_not_make_an_address_shared() {
    // F-1: sessions are minted at will, so they are no evidence of a NAT.
    let b = Bouncer::builder()
        .clock(ManualClock::new())
        .enforcement(Enforcement::enforce_all())
        .build()
        .unwrap();
    let attacker = ip("198.51.100.7");
    let conn = b.door(attacker).unwrap();
    for i in 0..200 {
        let mut r = conn.request(RequestId(u128::from(i))).unwrap();
        assert!(r.bind_session(session(i)).is_pass());
    }
    assert!(!b.explain(attacker).shared_source);
    let mut last = StrikeOutcome::Counted;
    for _ in 0..5 {
        last = conn.strike(StrikeKind::Malformed);
    }
    assert!(matches!(last, StrikeOutcome::Banned(_)), "{last:?}");
    drop(conn);
    assert!(b.door(attacker).is_err(), "banned at the door");
}

#[test]
fn test_a_shared_address_is_banned_at_its_second_threshold() {
    // F-1: a shared address is throttled at a threshold, never shielded
    // without end: the next threshold while it is throttled bans it.
    let b = Bouncer::builder()
        .clock(ManualClock::new())
        .enforcement(Enforcement::enforce_all())
        .build()
        .unwrap();
    let nat = ip("198.51.100.8");
    bind_accounts(&b, nat, 200);
    assert!(b.explain(nat).shared_source, "many accounts: a NAT");
    let conn = b.door(nat).unwrap();
    let mut first = StrikeOutcome::Counted;
    for _ in 0..5 {
        first = conn.strike(StrikeKind::Malformed);
    }
    assert_eq!(first, StrikeOutcome::Throttled);
    let mut second = StrikeOutcome::Counted;
    for _ in 0..5 {
        second = conn.strike(StrikeKind::Malformed);
    }
    assert!(matches!(second, StrikeOutcome::Banned(_)), "{second:?}");
    drop(conn);
    assert!(b.door(nat).is_err());
}

#[test]
fn test_a_throttled_shared_address_is_admitted_at_a_quarter_of_its_rate() {
    // F-2: the throttle that stands in for a ban has to slow the address at
    // the door. Two addresses in separate /24s, both shared; one throttled.
    let clock = Arc::new(ManualClock::new());
    let b = Bouncer::builder().clock(clock.clone()).build().unwrap();
    let (free, slowed) = (ip("198.51.100.9"), ip("203.0.113.9"));
    bind_accounts(&b, free, 200);
    bind_accounts(&b, slowed, 200);
    assert!(b.explain(free).shared_source && b.explain(slowed).shared_source);
    clock.advance(Duration::from_secs(60));
    b.apply(Directive::throttle(slowed, 4, Duration::from_secs(600)))
        .unwrap();
    let unthrottled = burst(&b, free, 1_000);
    let throttled = burst(&b, slowed, 1_000);
    assert!(unthrottled > 40, "a shared address has its prefix's budget");
    assert!(
        throttled <= unthrottled / 4 + 2,
        "throttled {throttled}, unthrottled {unthrottled}"
    );
}

#[test]
fn test_forwarded_header_clients_are_charged_door_budgets() {
    // F-3: behind an HTTP proxy each request names its client; the client is
    // held to the door's budgets as if it had connected itself.
    let b = Bouncer::builder()
        .clock(ManualClock::new())
        .trusted_proxies(&["10.0.0.0/8".parse::<Cidr>().unwrap()])
        .build()
        .unwrap();
    let client = ip("198.51.100.44");
    let hop = b.door(ip("10.0.0.1")).unwrap();
    let mut held = Vec::new();
    for i in 0..1_000u128 {
        let mut r = hop.request(RequestId(i)).unwrap();
        if r.bind_client(client, Provenance::ForwardedHeader).is_pass() {
            held.push(r);
        }
    }
    assert_eq!(held.len(), 40, "the default burst for one address");
    // Ended requests give their concurrency back.
    drop(held);
    assert_eq!(b.health().tickets_live, 1, "only the hop is left");
}

#[test]
fn test_a_full_strike_table_still_counts_and_bans() {
    // F-4: filling the strike counters with one strike per new key must not
    // switch strikes off for everyone else.
    let b = Bouncer::builder()
        .clock(ManualClock::new())
        .budgets(Budgets::off())
        .enforcement(Enforcement::enforce_all())
        .build()
        .unwrap();
    let slots = b.capacity().strike_counters;
    // 30 hosts per /24: below the /24's prefix threshold.
    for i in 0..(slots + slots / 4) {
        let net = i / 30;
        let host = (i % 30) as u8 + 1;
        let a = IpAddr::from([20 + (net >> 16) as u8, (net >> 8) as u8, net as u8, host]);
        let t = b.door(a).unwrap();
        let _ = t.strike(StrikeKind::Malformed);
    }
    let attacker = ip("198.51.100.200");
    let t = b.door(attacker).unwrap();
    let outcomes: Vec<StrikeOutcome> = (0..5).map(|_| t.strike(StrikeKind::LoginFailed)).collect();
    assert!(
        !outcomes.contains(&StrikeOutcome::Ignored(IgnoredBecause::CounterTableFull)),
        "{outcomes:?}"
    );
    assert!(
        matches!(outcomes[4], StrikeOutcome::Banned(_)),
        "{outcomes:?}"
    );
    drop(t);
    assert!(b.door(attacker).is_err());
}

#[test]
fn test_a_strike_flood_does_not_flush_an_offender_near_its_threshold() {
    // F-4: a full table gives a newcomer the slot with the fewest strikes, so
    // one-strike keys never push out a key with four.
    let b = Bouncer::builder()
        .clock(ManualClock::new())
        .budgets(Budgets::off())
        .enforcement(Enforcement::enforce_all())
        .build()
        .unwrap();
    let slots = b.capacity().strike_counters;
    let offender = ip("198.51.100.201");
    let t = b.door(offender).unwrap();
    for _ in 0..4 {
        assert_eq!(t.strike(StrikeKind::LoginFailed), StrikeOutcome::Counted);
    }
    for i in 0..(slots * 2) {
        let net = i / 30;
        let host = (i % 30) as u8 + 1;
        let a = IpAddr::from([20 + (net >> 16) as u8, (net >> 8) as u8, net as u8, host]);
        let _ = b.door(a).unwrap().strike(StrikeKind::LoginFailed);
    }
    assert!(matches!(
        t.strike(StrikeKind::LoginFailed),
        StrikeOutcome::Banned(_)
    ));
}

#[test]
fn test_concurrent_allow_list_replacements_leave_the_door_consistent() {
    // F-8: two reloads racing must leave the door reading the list that won.
    let x = ip("192.0.2.77");
    for _ in 0..2_000 {
        let b = Bouncer::builder().budgets(Budgets::off()).build().unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let (b1, b2) = (b.clone(), b.clone());
        let (g1, g2) = (barrier.clone(), barrier.clone());
        let t1 = std::thread::spawn(move || {
            g1.wait();
            b1.replace_allow(AllowList::new()).unwrap();
        });
        let t2 = std::thread::spawn(move || {
            g2.wait();
            b2.replace_allow(AllowList::new().immune(Cidr::host(x), "infra"))
                .unwrap();
        });
        t1.join().unwrap();
        t2.join().unwrap();
        let published = b.explain(x).allow == Some(AllowKind::Immune);
        let at_door = b.door(x).unwrap().strike(StrikeKind::Malformed)
            == StrikeOutcome::Ignored(IgnoredBecause::AllowListed);
        assert_eq!(published, at_door, "the door reads the published list");
    }
}

#[test]
fn test_clear_wipes_bytes_written_through_spare() {
    // F-9: bytes written through `spare` and not committed are wiped too.
    let mut c = Collected::with_capacity(64, 64).unwrap();
    c.spare(32)
        .unwrap()
        .copy_from_slice(b"SECRET-TOKEN-0123456789abcdefgh!");
    c.commit(4).unwrap();
    c.clear();
    assert!(c.spare(32).unwrap().iter().all(|&b| b == 0));

    let mut c = Collected::with_capacity(64, 64).unwrap();
    c.spare(32)
        .unwrap()
        .copy_from_slice(b"SECRET-TOKEN-0123456789abcdefgh!");
    c.commit(8).unwrap();
    c.truncate(2);
    assert!(c.spare(30).unwrap().iter().all(|&b| b == 0));
}

#[test]
fn test_unverified_datagrams_get_no_exemption_from_their_source() {
    // F-5: a UDP source address is forgeable, so it earns no exemption until
    // the protocol has verified it.
    let b = Bouncer::builder()
        .clock(ManualClock::new())
        .trusted_proxies(&["173.245.48.0/20".parse::<Cidr>().unwrap()])
        .allow(AllowList::new().exempt_budgets("192.0.2.0/24".parse().unwrap(), "health"))
        .build()
        .unwrap();
    let now = b.now();
    let count = |src: IpAddr, verified: bool| {
        (0..10_000)
            .filter(|_| b.datagram(src, verified, now) == DatagramVerdict::Accept)
            .count()
    };
    let ordinary = count(ip("198.51.100.1"), false);
    assert_eq!(count(ip("173.245.48.5"), false), ordinary);
    assert_eq!(count(ip("192.0.2.9"), false), ordinary);
    // Verified, the allow entry applies again.
    assert_eq!(count(ip("192.0.2.10"), true), 10_000);
}

#[test]
fn test_revocations_without_a_maintainer_never_fill_the_table() {
    // F-6: with no maintainer thread, a full revocation table reclaims what
    // no live ticket needs before it gives up.
    let b = Bouncer::new();
    let capacity = b.capacity().revocations;
    let started = std::time::Instant::now();
    for i in 0..(capacity + capacity / 2) {
        b.revoke(session(i), Reason::LOGOUT)
            .unwrap_or_else(|e| panic!("revocation {i}: {e}"));
    }
    assert!(started.elapsed() < Duration::from_secs(60));
}

#[test]
fn test_ipv6_automatic_lengths_must_include_64() {
    // F-12: an address ban is kept at the client's /64; without that length
    // a host rotates out of it (longer lengths) or bans its neighbours
    // (shorter).
    for lengths in [&[96u8][..], &[48], &[56, 48]] {
        assert!(
            matches!(
                Bouncer::builder().ipv6_lengths(lengths).build(),
                Err(BouncerError::Config(_))
            ),
            "{lengths:?}"
        );
    }
    assert!(Bouncer::builder().ipv6_lengths(&[64, 48]).build().is_ok());
}

#[test]
fn test_a_bulk_load_of_administrator_prefixes_builds_the_set_once() {
    // F-7: a blocklist of 20,000 prefixes at a length that is not automatic
    // goes to the administrator set; built per insert it took minutes.
    let b = Bouncer::builder().budgets(Budgets::off()).build().unwrap();
    let prefixes: Vec<Cidr> = (0..20_000u32)
        .map(|i| Cidr::new(IpAddr::from((0x0a00_0000 | (i << 12)).to_be_bytes()), 20).unwrap())
        .collect();
    let started = std::time::Instant::now();
    let results = b.apply_all(prefixes.iter().map(|&c| {
        Directive::ban(c)
            .by(bouncer_io::Actor::Admin(1))
            .because(Reason::POLICY)
            .permanent()
    }));
    let took = started.elapsed();
    assert!(results.iter().all(Result::is_ok));
    assert!(took < Duration::from_secs(20), "{took:?}");
    assert!(b.door(ip("10.0.16.1")).is_err());
    assert!(
        b.door(IpAddr::from(
            (0x0a00_0000u32 | (19_999 << 12) | 7).to_be_bytes()
        ))
        .is_err()
    );
    assert!(b.door(ip("192.0.2.1")).is_ok());
    // A single ban after the batch is visible at once.
    b.apply(
        Directive::ban("172.16.0.0/20".parse::<Cidr>().unwrap()).by(bouncer_io::Actor::Admin(1)),
    )
    .unwrap();
    assert!(b.door(ip("172.16.3.3")).is_err());
}
