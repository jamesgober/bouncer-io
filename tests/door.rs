//! The door, ban memory, and tickets: edge cases 1 to 26 and the 0.3 threat
//! tests (dev/PLAN.md sections 8 and 12.5).

use std::{
    net::IpAddr,
    sync::{Arc, Barrier},
    time::Duration,
};

use bouncer_io::{
    AccountKey, Actor, AllowList, BanKey, BanSpec, Bouncer, BouncerError, Budgets, Cidr, ConnId,
    DenialCode, DurationPolicy, FingerprintKey, LiftSpec, Now, Provenance, Refusal, RequestId,
    SessionKey, Verdict,
};
use clock_lib::ManualClock;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn c(s: &str) -> Cidr {
    s.parse().unwrap()
}

fn admitted(b: &Bouncer, s: &str) -> bool {
    b.door(ip(s)).is_ok()
}

fn small() -> Bouncer {
    Bouncer::builder()
        .tickets(1024)
        .ban_capacity(4096)
        .seed([7; 32])
        .try_build()
        .unwrap()
}

// ---- Addresses and prefixes -------------------------------------------------

#[test]
fn test_door_everything_banned_by_admin_zero_prefix_except_immune() {
    // Edge case 1.
    let b = Bouncer::builder()
        .allow(AllowList::new().immune(c("10.0.0.0/8"), "infra"))
        .ban_capacity(64)
        .tickets(64)
        .try_build()
        .unwrap();
    b.ban(c("0.0.0.0/0")).unwrap();
    b.ban(c("::/0")).unwrap();
    assert!(!admitted(&b, "8.8.8.8"));
    assert!(!admitted(&b, "2001:db8::1"));
    assert!(admitted(&b, "10.1.2.3"));
    for actor in [
        Actor::Local,
        Actor::Policy(1),
        Actor::Sentinel,
        Actor::Gate,
        Actor::Channel(1),
    ] {
        assert!(
            matches!(
                b.ban(BanSpec::prefix(c("0.0.0.0/0")).by(actor)),
                Err(BouncerError::InvalidPrefix { .. })
            ),
            "{actor}"
        );
    }
}

#[test]
fn test_door_ban_at_boundary_lengths() {
    // Edge case 2: administrators may ban any length.
    let b = small();
    for (text, inside, outside) in [
        ("198.51.0.0/1", "200.0.0.1", "127.0.0.1"),
        ("198.51.100.0/31", "198.51.100.1", "198.51.100.2"),
        ("198.51.100.77/32", "198.51.100.77", "198.51.100.78"),
        ("2001:db8:1::/63", "2001:db8:1:1::1", "2001:db8:1:2::1"),
        ("2001:db8:2::/65", "2001:db8:2::1", "2001:db8:2:0:8000::1"),
        ("2001:db8:3::5/127", "2001:db8:3::4", "2001:db8:3::6"),
        ("2001:db8:4::5/128", "2001:db8:4::5", "2001:db8:4::6"),
    ] {
        b.ban(c(text)).unwrap();
        assert!(!admitted(&b, inside), "{text} should cover {inside}");
        assert!(admitted(&b, outside), "{text} should not cover {outside}");
        assert_eq!(b.lift(c(text)).unwrap().removed, 1);
    }
}

#[test]
fn test_door_ipv4_mapped_matches_address_and_prefix_bans() {
    // Edge case 4.
    let b = small();
    b.ban(ip("203.0.113.7")).unwrap();
    assert!(!admitted(&b, "::ffff:203.0.113.7"));
    b.ban(c("198.51.100.0/24")).unwrap();
    assert!(!admitted(&b, "::ffff:198.51.100.200"));
    b.ban(ip("::ffff:192.0.2.9")).unwrap();
    assert!(!admitted(&b, "192.0.2.9"));
}

#[test]
fn test_door_compatible_nat64_teredo_6to4_never_match_embedded_ipv4() {
    // Edge cases 5, 6, 7.
    let b = small();
    b.ban(ip("203.0.113.7")).unwrap();
    for s in [
        "::203.0.113.7",
        "64:ff9b::cb00:7107",
        "2001:0:cb00:7107::1",
        "2002:cb00:7107::1",
    ] {
        assert!(admitted(&b, s), "{s}");
    }
}

#[test]
fn test_door_allow_wins_over_ban_and_automation_refused() {
    // Edge case 11.
    let b = Bouncer::builder()
        .allow(AllowList::new().immune(c("192.0.2.10/32"), "partner"))
        .tickets(64)
        .ban_capacity(64)
        .try_build()
        .unwrap();
    assert!(matches!(
        b.ban(ip("192.0.2.10")),
        Err(BouncerError::AllowListed { .. })
    ));
    assert!(matches!(
        b.ban(BanSpec::address(ip("192.0.2.10")).by(Actor::Policy(4))),
        Err(BouncerError::AllowListed { .. })
    ));
    b.ban(c("192.0.2.0/24")).unwrap();
    assert!(admitted(&b, "192.0.2.10"));
    assert!(!admitted(&b, "192.0.2.11"));
}

#[test]
fn test_door_allow_entry_inside_banned_prefix() {
    // Edge case 12.
    let b = Bouncer::builder()
        .allow(AllowList::new().immune(c("203.0.113.128/25"), "office"))
        .tickets(64)
        .ban_capacity(64)
        .try_build()
        .unwrap();
    b.ban(c("203.0.113.0/24")).unwrap();
    assert!(admitted(&b, "203.0.113.200"));
    assert!(!admitted(&b, "203.0.113.20"));
}

#[test]
fn test_door_trusted_proxy_inside_banned_prefix_admits_hop_and_judges_clients() {
    // Edge case 13, threat T-1.
    let b = Bouncer::builder()
        .trusted_proxies(&[c("198.51.100.1/32")])
        .tickets(64)
        .ban_capacity(64)
        .try_build()
        .unwrap();
    b.ban(c("198.51.100.0/24")).unwrap();
    b.ban(ip("203.0.113.66")).unwrap();
    let hop = b.door(ip("198.51.100.1")).unwrap();
    assert_eq!(hop.source(), None);
    let mut good = hop.request(RequestId(1)).unwrap();
    assert!(
        good.bind_client(ip("192.0.2.5"), Provenance::ForwardedHeader)
            .is_pass()
    );
    let mut bad = hop.request(RequestId(2)).unwrap();
    let v = bad.bind_client(ip("203.0.113.66"), Provenance::ForwardedHeader);
    assert!(matches!(v, Verdict::Deny(d) if d.code == DenialCode::Forbidden));
    assert!(bad.checkpoint().is_deny());
    // Neighbours of the proxy inside the banned /24 are still refused.
    assert!(!admitted(&b, "198.51.100.2"));
}

#[test]
fn test_ban_trusted_proxy_refused() {
    // Threat T-1.
    let b = Bouncer::builder()
        .trusted_proxies(&[c("10.0.0.0/8")])
        .try_build()
        .unwrap();
    assert_eq!(b.ban(ip("10.1.1.1")), Err(BouncerError::TrustedProxyTarget));
    assert_eq!(
        b.ban(c("10.2.0.0/16")),
        Err(BouncerError::TrustedProxyTarget)
    );
}

#[test]
fn test_door_forwarded_header_from_untrusted_peer_not_bound() {
    // Threat T-1: a peer that is not a trusted proxy cannot name another
    // client, to evade its own ban or to frame someone else.
    let b = Bouncer::builder()
        .trusted_proxies(&[c("10.0.0.1/32")])
        .tickets(64)
        .ban_capacity(64)
        .try_build()
        .unwrap();
    b.ban(ip("198.51.100.66")).unwrap();
    let peer = ip("192.0.2.7");
    let conn = b.door(peer).unwrap();
    assert_eq!(conn.source(), Some(peer));
    let mut req = conn.request(RequestId(1)).unwrap();
    for provenance in [
        Provenance::ForwardedHeader,
        Provenance::ProxyProtocol,
        Provenance::FastCgi,
    ] {
        // Naming an innocent address, and naming a banned one.
        for named in ["203.0.113.5", "198.51.100.66"] {
            let v = req.bind_client(ip(named), provenance);
            assert!(
                matches!(v, Verdict::Deny(d) if d.code == DenialCode::Unavailable),
                "{named} via {provenance:?}"
            );
        }
    }
    assert_eq!(req.source(), Some(peer), "the socket peer stays the source");
    // Not a trusted provenance at all, from a trusted proxy.
    let hop = b.door(ip("10.0.0.1")).unwrap();
    let mut via = hop.request(RequestId(2)).unwrap();
    for provenance in [Provenance::Socket, Provenance::Local] {
        assert!(via.bind_client(ip("203.0.113.5"), provenance).is_deny());
    }
    assert_eq!(via.source(), None, "still waiting for a trusted client");
}

#[test]
fn test_ban_ipv6_rotation_within_64_refused() {
    // Threat T-2.
    let b = small();
    b.ban(BanSpec::address(ip("2001:db8:aa:bb::1")).by(Actor::Local))
        .unwrap();
    for host in [
        "2001:db8:aa:bb::2",
        "2001:db8:aa:bb:ffff:ffff:ffff:ffff",
        "2001:db8:aa:bb:1234::",
    ] {
        assert!(!admitted(&b, host), "{host}");
    }
    assert!(admitted(&b, "2001:db8:aa:bc::1"));
}

// ---- Door and tickets ---------------------------------------------------------

#[test]
fn test_registry_capacity_one_refuses_second_until_release() {
    // Edge case 14.
    let b = Bouncer::builder().tickets(1).try_build().unwrap();
    let first = b.door(ip("192.0.2.1")).unwrap();
    assert_eq!(b.door(ip("192.0.2.2")).err(), Some(Refusal::RegistryFull));
    assert!(matches!(
        first.request(RequestId(1)),
        Err(BouncerError::RegistryFull { .. })
    ));
    drop(first);
    assert!(admitted(&b, "192.0.2.2"));
}

#[test]
fn test_registry_concurrent_issue_n_minus_one_n_n_plus_one() {
    // Edge case 15.
    for extra in [-1i64, 0, 1] {
        let capacity = 256u32;
        let b = Bouncer::builder()
            .tickets(capacity)
            .shards(4)
            .budgets(Budgets::off())
            .try_build()
            .unwrap();
        let real = b.capacity().tickets as i64;
        let want = (real + extra) as usize;
        let threads = 32;
        let barrier = Arc::new(Barrier::new(threads));
        let handles: Vec<_> = (0..threads)
            .map(|t| {
                let b = b.clone();
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    let mut held = Vec::new();
                    for i in 0..want.div_ceil(threads) {
                        if t * want.div_ceil(threads) + i >= want {
                            break;
                        }
                        if let Ok(tk) = b.door(IpAddr::from([192, 0, 2, (t % 250) as u8])) {
                            held.push(tk);
                        }
                    }
                    held
                })
            })
            .collect();
        let held: Vec<_> = handles
            .into_iter()
            .flat_map(|h| h.join().unwrap())
            .collect();
        let expected = want.min(real as usize);
        assert_eq!(held.len(), expected, "extra {extra}");
        let mut ids: Vec<_> = held.iter().map(|t| t.id()).collect();
        ids.sort_by_key(|i| i.get());
        ids.dedup();
        assert_eq!(ids.len(), held.len(), "a cell was handed out twice");
    }
}

#[test]
fn test_ticket_dropped_on_another_thread() {
    // Edge case 16.
    let b = Bouncer::builder().tickets(1).try_build().unwrap();
    let t = b.door(ip("192.0.2.1")).unwrap();
    std::thread::spawn(move || drop(t)).join().unwrap();
    assert!(admitted(&b, "192.0.2.1"));
}

#[test]
fn test_connection_dropped_before_requests_denies_them() {
    // Edge case 17.
    let b = small();
    let conn = b.door(ip("192.0.2.1")).unwrap();
    let mut r1 = conn.request(RequestId(1)).unwrap();
    let mut r2 = conn.request(RequestId(2)).unwrap();
    assert!(r1.checkpoint().is_pass());
    drop(conn);
    for r in [&mut r1, &mut r2] {
        assert!(matches!(r.checkpoint(), Verdict::Deny(d) if d.code == DenialCode::Unavailable));
        assert!(r.checkpoint().is_deny(), "stays denied");
    }
    // A new connection in the same cell does not revive them.
    let _again = b.door(ip("192.0.2.1")).unwrap();
    assert!(r1.checkpoint().is_deny());
}

#[test]
fn test_request_on_request_ticket_refused() {
    // Edge case 18.
    let b = small();
    let conn = b.door(ip("192.0.2.1")).unwrap();
    let r = conn.request(RequestId(1)).unwrap();
    assert_eq!(
        r.request(RequestId(2)).err(),
        Some(BouncerError::NotAConnectionTicket)
    );
}

#[test]
fn test_request_on_revoked_connection_refused() {
    // Edge case 19: a PROXY-protocol client found banned revokes the connection.
    let b = Bouncer::builder()
        .trusted_proxies(&[c("10.0.0.1/32")])
        .try_build()
        .unwrap();
    b.ban(ip("203.0.113.9")).unwrap();
    let mut conn = b.door(ip("10.0.0.1")).unwrap();
    assert!(
        conn.bind_client(ip("203.0.113.9"), Provenance::ProxyProtocol)
            .is_deny()
    );
    assert_eq!(
        conn.request(RequestId(1)).err(),
        Some(BouncerError::Revoked)
    );
    assert!(conn.checkpoint().is_deny());
}

#[test]
fn test_bind_client_rules() {
    // Edge case 21, threat T-1.
    let b = Bouncer::builder()
        .trusted_proxies(&[c("10.0.0.1/32")])
        .try_build()
        .unwrap();
    // A socket peer: no re-binding, whatever the provenance.
    let mut direct = b.door(ip("192.0.2.1")).unwrap();
    assert!(
        direct
            .bind_client(ip("192.0.2.99"), Provenance::ForwardedHeader)
            .is_deny()
    );
    assert_eq!(direct.source(), Some(ip("192.0.2.1")));
    let mut req = direct.request(RequestId(1)).unwrap();
    assert!(
        req.bind_client(ip("192.0.2.99"), Provenance::ForwardedHeader)
            .is_deny()
    );
    // On a proxy hop: only a trusted provenance, and only once.
    let mut hop = b.door(ip("10.0.0.1")).unwrap();
    assert!(
        hop.bind_client(ip("192.0.2.7"), Provenance::Socket)
            .is_deny()
    );
    assert!(
        hop.bind_client(ip("192.0.2.7"), Provenance::Local)
            .is_deny()
    );
    assert!(
        hop.bind_client(ip("192.0.2.7"), Provenance::ProxyProtocol)
            .is_pass()
    );
    assert_eq!(hop.provenance(), Provenance::ProxyProtocol);
    assert!(
        hop.bind_client(ip("192.0.2.8"), Provenance::ProxyProtocol)
            .is_deny()
    );
    assert_eq!(hop.source(), Some(ip("192.0.2.7")));
    // Requests inherit the bound client and cannot re-bind.
    let mut r = hop.request(RequestId(2)).unwrap();
    assert_eq!(r.source(), Some(ip("192.0.2.7")));
    assert!(r.checkpoint().is_pass());
    assert!(
        r.bind_client(ip("192.0.2.9"), Provenance::ForwardedHeader)
            .is_deny()
    );
    // A trusted proxy named as the client is refused.
    let mut hop2 = b.door(ip("10.0.0.1")).unwrap();
    let mut r2 = hop2.request(RequestId(3)).unwrap();
    assert!(
        r2.bind_client(ip("10.0.0.1"), Provenance::ForwardedHeader)
            .is_deny()
    );
    assert!(
        hop2.bind_client(ip("10.0.0.1"), Provenance::ProxyProtocol)
            .is_deny()
    );
}

#[test]
fn test_proxied_request_without_client_denies_every_checkpoint() {
    // Edge case 22, threat T-1.
    let b = Bouncer::builder()
        .trusted_proxies(&[c("10.0.0.0/8")])
        .try_build()
        .unwrap();
    let hop = b.door(ip("10.0.0.5")).unwrap();
    let mut r = hop.request(RequestId(1)).unwrap();
    for _ in 0..3 {
        assert!(matches!(r.checkpoint(), Verdict::Deny(d) if d.code == DenialCode::Unavailable));
    }
    assert_eq!(r.source(), None);
}

#[test]
fn test_stale_now_never_expires_early_and_end_is_exclusive() {
    // Edge cases 23 and 24.
    let clock = Arc::new(ManualClock::new());
    let b = Bouncer::builder().clock(clock.clone()).try_build().unwrap();
    clock.advance(Duration::from_secs(100));
    b.ban(BanSpec::address(ip("192.0.2.1")).for_duration(Duration::from_secs(10)))
        .unwrap();
    let at = |secs: u64| Now::from_nanos(secs * 1_000_000_000);
    assert!(
        b.door_at(ConnId(1), ip("192.0.2.1"), Provenance::Socket, at(50))
            .is_err(),
        "older now"
    );
    assert!(
        b.door_at(ConnId(2), ip("192.0.2.1"), Provenance::Socket, at(109))
            .is_err()
    );
    assert!(
        b.door_at(ConnId(3), ip("192.0.2.1"), Provenance::Socket, at(110))
            .is_ok(),
        "until <= now"
    );
    clock.advance(Duration::from_secs(10));
    assert!(admitted(&b, "192.0.2.1"));
}

// ---- Bans ---------------------------------------------------------------------

#[test]
fn test_ban_policy_durations_with_manual_clock() {
    let clock = Arc::new(ManualClock::new());
    let b = Bouncer::builder()
        .clock(clock.clone())
        .durations(
            DurationPolicy::default()
                .base(Duration::from_secs(60))
                .jitter(Duration::ZERO),
        )
        .try_build()
        .unwrap();
    b.ban(BanSpec::address(ip("198.51.100.1")).by(Actor::Local))
        .unwrap();
    clock.advance(Duration::from_secs(59));
    assert!(!admitted(&b, "198.51.100.1"));
    clock.advance(Duration::from_secs(1));
    assert!(admitted(&b, "198.51.100.1"));
    // Second offence: twice as long.
    b.ban(BanSpec::address(ip("198.51.100.1")).by(Actor::Local))
        .unwrap();
    clock.advance(Duration::from_secs(119));
    assert!(!admitted(&b, "198.51.100.1"));
    clock.advance(Duration::from_secs(1));
    assert!(admitted(&b, "198.51.100.1"));
}

#[test]
fn test_ban_permanent_rules_per_actor() {
    let b = small();
    for (actor, ok) in [
        (Actor::App, true),
        (Actor::Admin(1), true),
        (Actor::Sentinel, true),
        (Actor::Policy(1), false),
        (Actor::Gate, false),
        (Actor::Channel(1), false),
        (Actor::Local, false),
    ] {
        let r = b.ban(BanSpec::address(ip("192.0.2.200")).permanent().by(actor));
        assert_eq!(r.is_ok(), ok, "{actor}");
        if !ok {
            assert_eq!(r, Err(BouncerError::PermanentNotAllowed));
        }
    }
}

#[test]
fn test_ban_identity_keys_stored_and_liftable() {
    let b = small();
    b.ban(BanSpec::key(SessionKey::from_digest([1; 16])))
        .unwrap();
    b.ban(BanSpec::key(AccountKey(42)).permanent()).unwrap();
    b.ban(BanSpec::key(BanKey::FingerprintIn(
        FingerprintKey::from_digest([2; 16]),
        c("203.0.113.0/24"),
    )))
    .unwrap();
    assert_eq!(b.lift(BanKey::Account(AccountKey(42))).unwrap().removed, 1);
    assert_eq!(
        b.lift(BanKey::Account(AccountKey(42))).err(),
        Some(BouncerError::NotFound)
    );
}

#[test]
fn test_lift_prefix_leaves_covering_ban() {
    let b = small();
    b.ban(c("203.0.113.0/24")).unwrap();
    b.ban(ip("203.0.113.7")).unwrap();
    assert_eq!(b.lift(LiftSpec::key(ip("203.0.113.7"))).unwrap().removed, 1);
    assert!(!admitted(&b, "203.0.113.7"));
}

#[test]
fn test_ban_table_full_only_unevictable_left() {
    let b = Bouncer::builder().ban_capacity(16).try_build().unwrap();
    // One per /24, so nothing escalates.
    for i in 0..16u8 {
        b.ban(IpAddr::from([192, 0, i, 2])).unwrap();
    }
    assert_eq!(
        b.ban(BanSpec::address(ip("198.51.100.1")).by(Actor::Local)),
        Err(BouncerError::BanTableFull { capacity: 16 })
    );
    for i in 0..16u8 {
        assert!(
            b.door(IpAddr::from([192, 0, i, 2])).is_err(),
            "admin ban {i} kept"
        );
    }
}

#[test]
fn test_ban_table_evicts_local_bans_never_admin() {
    let b = Bouncer::builder().ban_capacity(32).try_build().unwrap();
    for i in 0..8u8 {
        b.ban(IpAddr::from([192, 0, 2, i])).unwrap();
    }
    for i in 0..200u8 {
        b.ban(BanSpec::address(IpAddr::from([198, 51, 100, i])).by(Actor::Local))
            .unwrap();
    }
    for i in 0..8u8 {
        assert!(
            b.door(IpAddr::from([192, 0, 2, i])).is_err(),
            "admin ban {i} kept"
        );
    }
}

#[test]
fn test_ban_fills_to_capacity_and_every_entry_is_found() {
    let n = 20_000u32;
    let b = Bouncer::builder()
        .ban_capacity(n)
        .tickets(64)
        .try_build()
        .unwrap();
    for i in 0..n {
        b.ban(BanSpec::address(IpAddr::from((0x0a00_0000 | i).to_be_bytes())).permanent())
            .unwrap();
    }
    for i in (0..n).step_by(7) {
        assert!(
            b.door(IpAddr::from((0x0a00_0000 | i).to_be_bytes()))
                .is_err(),
            "{i}"
        );
    }
    assert!(b.door(ip("192.0.2.1")).is_ok());
}

#[test]
fn test_errors_never_print_digests() {
    // Threat T-18.
    let s = SessionKey::from_digest([0xab; 16]);
    let e = BouncerError::AllowListed {
        key: BanKey::Session(s),
    };
    let shown = format!("{e} {e:?}").to_lowercase();
    assert!(
        !shown.contains("ab, ") && !shown.contains("0xab") && !shown.contains("abab"),
        "{shown}"
    );
    let b = small();
    let t = b.door(ip("192.0.2.1")).unwrap();
    assert!(format!("{t:?}").contains("Ticket"));
}

#[test]
fn test_registry_flood_from_one_address_cannot_exhaust_it() {
    // Threat T-14: per-address concurrency at the door keeps one source from
    // taking every ticket; a legitimate address is still admitted.
    let b = Bouncer::builder()
        .tickets(256)
        .budgets(Budgets::default())
        .try_build()
        .unwrap();
    let mut held = Vec::new();
    for _ in 0..1000 {
        if let Ok(t) = b.door(ip("198.51.100.1")) {
            held.push(t);
        }
    }
    assert!(held.len() <= 64, "one address held {}", held.len());
    assert!(
        b.door(ip("192.0.2.77")).is_ok(),
        "a legitimate address is still admitted"
    );
}
