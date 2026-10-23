//! Property tests: dev/PLAN.md section 12.2, rows 1 to 6.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bouncer_io::{
    Actor, AllowList, BanSpec, Bouncer, BouncerError, Cidr, RequestId, normalize, prefix_of,
};
use proptest::prelude::*;

fn any_ip() -> impl Strategy<Value = IpAddr> {
    prop_oneof![
        any::<u32>().prop_map(|v| IpAddr::V4(Ipv4Addr::from(v))),
        any::<u128>().prop_map(|v| IpAddr::V6(Ipv6Addr::from(v))),
        any::<u32>().prop_map(|v| IpAddr::V6(Ipv4Addr::from(v).to_ipv6_mapped())),
    ]
}

fn any_cidr() -> impl Strategy<Value = Cidr> {
    prop_oneof![
        (any::<u32>(), 0u8..=32)
            .prop_map(|(v, l)| Cidr::new(IpAddr::V4(Ipv4Addr::from(v)), l).unwrap()),
        (any::<u128>(), 0u8..=128)
            .prop_map(|(v, l)| Cidr::new(IpAddr::V6(Ipv6Addr::from(v)), l).unwrap()),
    ]
}

fn bouncer() -> Bouncer {
    Bouncer::builder()
        .tickets(256)
        .ban_capacity(2048)
        .seed([3; 32])
        .try_build()
        .unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, .. ProptestConfig::default() })]

    /// Row 1: normalization is idempotent, and IPv4-mapped and plain IPv4 get
    /// the same verdict after any bans.
    #[test]
    fn prop_normalize_idempotent_and_mapped_same_verdict(
        bans in proptest::collection::vec(any::<u32>(), 0..20),
        probe in any::<u32>(),
    ) {
        let b = bouncer();
        for v in &bans {
            let _ = b.ban(IpAddr::V4(Ipv4Addr::from(*v)));
        }
        let v4 = IpAddr::V4(Ipv4Addr::from(probe));
        let mapped = IpAddr::V6(Ipv4Addr::from(probe).to_ipv6_mapped());
        prop_assert_eq!(normalize(normalize(mapped)), normalize(mapped));
        prop_assert_eq!(b.door(v4).is_ok(), b.door(mapped).is_ok());
        let probe_banned = bans.contains(&probe);
        prop_assert_eq!(b.door(v4).is_err(), probe_banned);
    }

    /// Row 2: every address inside a banned prefix is refused; with nothing
    /// else banned, every address outside it is admitted.
    #[test]
    fn prop_banned_prefix_refuses_inside_admits_outside(cidr in any_cidr(), addr in any_ip()) {
        let b = bouncer();
        b.ban(cidr).unwrap();
        let inside = cidr.contains(addr);
        prop_assert_eq!(b.door(addr).is_err(), inside, "{} vs {}", cidr, addr);
    }

    /// Row 3: printing and parsing a prefix is the identity.
    #[test]
    fn prop_cidr_display_parse_round_trip(cidr in any_cidr()) {
        prop_assert_eq!(Cidr::parse(&cidr.to_string()).unwrap(), cidr);
        prop_assert_eq!(Cidr::parse_strict(&cidr.to_string()).unwrap(), cidr);
    }

    /// Row 3 (parser): arbitrary text never panics, and accepted text is
    /// at most 64 bytes.
    #[test]
    fn prop_cidr_parse_never_panics(text in "\\PC{0,80}") {
        if let Ok(c) = Cidr::parse(&text) {
            prop_assert!(text.len() <= 64);
            prop_assert_eq!(Cidr::parse(&c.to_string()).unwrap(), c);
        }
    }

    /// Row 4: no sequence of automated bans leaves an allow-listed or
    /// trusted-proxy address refused.
    #[test]
    fn prop_automation_never_bans_allowlisted_or_proxy(
        ops in proptest::collection::vec((any::<u8>(), 0u8..=3, any::<bool>()), 1..40),
    ) {
        let b = Bouncer::builder()
            .allow(AllowList::new().immune("10.0.0.0/24".parse().unwrap(), "infra"))
            .trusted_proxies(&["10.0.1.1/32".parse().unwrap()])
            .tickets(64)
            .ban_capacity(512)
            .try_build()
            .unwrap();
        let actors = [Actor::Local, Actor::Policy(1), Actor::Sentinel, Actor::Gate];
        for (host, actor, wide) in ops {
            let target: IpAddr = IpAddr::from([10, 0, if host % 2 == 0 { 0 } else { 1 }, host]);
            let spec = if wide {
                BanSpec::prefix(prefix_of(target, 24).unwrap())
            } else {
                BanSpec::address(target)
            };
            match b.ban(spec.by(actors[usize::from(actor)])) {
                Ok(_) | Err(BouncerError::AllowListed { .. }) | Err(BouncerError::TrustedProxyTarget) => {}
                Err(other) => prop_assert!(false, "unexpected {other}"),
            }
        }
        for host in [0u8, 7, 200, 255] {
            prop_assert!(b.door(IpAddr::from([10, 0, 0, host])).is_ok());
        }
        prop_assert!(b.door(IpAddr::from([10, 0, 1, 1])).is_ok());
    }

    /// Row 5: the ban table never exceeds its capacity, and administrator
    /// bans are never evicted by automated ones.
    #[test]
    fn prop_ban_table_bounded_admin_never_evicted(
        admin in proptest::collection::vec(any::<u32>(), 1..16),
        local in proptest::collection::vec(any::<u32>(), 0..200),
    ) {
        let b = Bouncer::builder().ban_capacity(32).tickets(32).seed([5; 32]).try_build().unwrap();
        let mut kept = Vec::new();
        for v in &admin {
            if b.ban(IpAddr::V4(Ipv4Addr::from(*v))).is_ok() {
                kept.push(*v);
            }
        }
        for v in &local {
            let r = b.ban(BanSpec::address(IpAddr::V4(Ipv4Addr::from(*v))).by(Actor::Local));
            prop_assert!(matches!(r, Ok(_) | Err(BouncerError::BanTableFull { .. })), "unexpected {:?}", r);
        }
        for v in &kept {
            prop_assert!(b.door(IpAddr::V4(Ipv4Addr::from(*v))).is_err(), "admin ban {} evicted", v);
        }
    }

    /// Row 6: a request denied because its connection is gone never passes
    /// again until released.
    #[test]
    fn prop_denied_request_never_passes_again(checks in 1usize..20, reissue in any::<bool>()) {
        let b = bouncer();
        let conn = b.door(IpAddr::from([192, 0, 2, 1])).unwrap();
        let mut req = conn.request(RequestId(1)).unwrap();
        drop(conn);
        if reissue {
            let _other = b.door(IpAddr::from([192, 0, 2, 2])).unwrap();
            for _ in 0..checks {
                prop_assert!(req.checkpoint().is_deny());
            }
        } else {
            for _ in 0..checks {
                prop_assert!(req.checkpoint().is_deny());
            }
        }
    }
}
