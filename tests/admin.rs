//! Administration: explain, list, replace_allow, health (0.5). Edge case 50.

use std::{
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use bouncer_io::{
    AccountKey, Actor, AllowKind, AllowList, BanKey, BanSpec, Bouncer, Budgets, Cidr, Event,
    EventSink, Family, Filter, FingerprintKey, MaintainerState, Page, Posture, Rate, Reason,
    RequestId, SessionKey, StrikeKind, signals,
};
use clock_lib::ManualClock;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn c(s: &str) -> Cidr {
    s.parse().unwrap()
}

/// Signal id, source, and prefix of each event.
type Seen = Vec<(u32, Option<IpAddr>, Option<Cidr>)>;

#[derive(Default)]
struct Sink(Mutex<Seen>);
impl EventSink for Sink {
    fn event(&self, e: &Event<'_>) {
        self.0
            .lock()
            .unwrap()
            .push((e.signal.id, e.subject.source, e.subject.prefix));
    }
}

#[test]
fn test_explain_address_shows_every_covering_ban_and_state() {
    let clock = Arc::new(ManualClock::new());
    let b = Bouncer::builder()
        .clock(clock.clone())
        .budgets(Budgets::off().door_rate(Rate::per_second(2), Rate::per_second(100)))
        .try_build()
        .unwrap();
    let addr = ip("203.0.113.7");
    assert!(b.explain(addr).admitted);
    // Strikes and budget use show up before any ban.
    let conn = b.door(addr).unwrap();
    let second = b.door(addr).unwrap();
    for _ in 0..3 {
        let _ = conn.strike(StrikeKind::Malformed);
    }
    let why = b.explain(addr);
    assert!(why.admitted);
    assert_eq!(why.live_tickets, 2);
    let strike = why
        .strikes
        .iter()
        .find(|s| s.kind == StrikeKind::Malformed)
        .unwrap();
    assert_eq!((strike.count, strike.threshold), (3, 5));
    let client = why
        .budgets
        .iter()
        .find(|s| s.class == "door.rate.client")
        .unwrap();
    assert_eq!(client.remaining, 0);
    assert!(client.retry_after.is_some());
    assert!(why.to_string().contains("door.rate.client spent"), "{why}");
    drop((conn, second));
    // Edge case 50: a child ban and its parent; lift the child, the parent stands.
    b.ban(addr).unwrap();
    b.ban(
        BanSpec::prefix(c("203.0.113.0/24"))
            .by(Actor::Admin(4))
            .for_duration(Duration::from_secs(3600)),
    )
    .unwrap();
    let why = b.explain(addr);
    assert!(!why.admitted);
    assert_eq!(why.bans.len(), 2);
    assert!(
        why.bans
            .iter()
            .any(|r| r.key == BanKey::Prefix(c("203.0.113.0/24")))
    );
    b.lift(addr).unwrap();
    let why = b.explain(addr);
    assert!(!why.admitted, "the /24 still refuses it");
    assert_eq!(why.bans.len(), 1);
    let text = why.to_string();
    assert!(
        text.starts_with("203.0.113.7 is refused: 203.0.113.0/24 banned until "),
        "{text}"
    );
    assert!(text.contains("by Admin, reason admin"), "{text}");
    // A prefix explained shows itself and wider bans, not narrower ones.
    b.ban(ip("203.0.113.9")).unwrap();
    let why = b.explain(c("203.0.113.0/24"));
    assert_eq!(why.bans.len(), 1);
}

#[test]
fn test_explain_identity_allow_and_admin_prefix() {
    let b = Bouncer::builder()
        .allow(
            AllowList::new()
                .immune(c("10.20.0.0/16"), "infra")
                .exempt_budgets(c("192.0.2.200/32"), "lb"),
        )
        .try_build()
        .unwrap();
    let why = b.explain(ip("10.20.1.1"));
    assert_eq!(why.allow, Some(AllowKind::Immune));
    assert!(why.admitted);
    assert!(why.to_string().contains("allow-listed as immune"));
    assert_eq!(
        b.explain(ip("192.0.2.200")).allow,
        Some(AllowKind::ExemptBudgets)
    );
    let account = AccountKey(77);
    b.ban(BanSpec::key(account).permanent()).unwrap();
    let why = b.explain(account);
    assert!(!why.admitted);
    assert_eq!(why.bans[0].until, None);
    assert!(why.to_string().contains("banned permanently"));
    // An administrator prefix outside the automatic lengths.
    b.ban(BanSpec::prefix(c("198.18.0.0/15")).by(Actor::Admin(1)))
        .unwrap();
    assert!(!b.explain(ip("198.19.4.4")).admitted);
    assert_eq!(
        b.explain(ip("198.19.4.4")).bans[0].key,
        BanKey::Prefix(c("198.18.0.0/15"))
    );
}

#[test]
fn test_list_filters_and_pages() {
    let b = Bouncer::new();
    for i in 1..=7u8 {
        b.ban(IpAddr::from([198, 51, 100, i])).unwrap();
    }
    b.ban(
        BanSpec::prefix(c("2001:db8:1::/48"))
            .by(Actor::Admin(2))
            .permanent(),
    )
    .unwrap();
    let session = SessionKey::from_digest([4; 16]);
    b.ban(BanSpec::key(session).because(Reason::LOGOUT))
        .unwrap();
    let fp = FingerprintKey::from_digest([9; 16]);
    b.ban(BanSpec::key(BanKey::FingerprintIn(fp, c("192.0.2.0/24"))))
        .unwrap();
    assert_eq!(b.list(&Filter::all(), Page::first(100)).total, 10);
    assert_eq!(
        b.list(&Filter::all().family(Family::V6), Page::first(100))
            .total,
        1
    );
    assert_eq!(
        b.list(&Filter::all().permanent_only(), Page::first(100))
            .total,
        1
    );
    assert_eq!(
        b.list(&Filter::all().by(Actor::Admin(9)), Page::first(100))
            .total,
        1,
        "by kind"
    );
    assert_eq!(
        b.list(&Filter::all().because(Reason::LOGOUT), Page::first(100))
            .total,
        1
    );
    let soon = SystemTime::now() + Duration::from_secs(365 * 86_400);
    assert_eq!(
        b.list(&Filter::all().expiring_before(soon), Page::first(100))
            .total,
        9
    );
    let fps = b.list(&Filter::all().within(c("192.0.2.0/24")), Page::first(100));
    assert_eq!(
        fps.items[0].key,
        BanKey::FingerprintIn(fp, c("192.0.2.0/24")),
        "compound keys list as given"
    );
    // Paging: 7 addresses in pages of 3, ids increasing, no repeats.
    let mut page = Page::first(3);
    let mut ids = Vec::new();
    loop {
        let l = b.list(&Filter::all().within(c("198.51.100.0/24")), page);
        assert_eq!(l.total, 7);
        ids.extend(l.items.iter().map(|r| r.id));
        match l.next {
            Some(n) => page = n,
            None => break,
        }
    }
    assert_eq!(ids.len(), 7);
    assert!(ids.windows(2).all(|w| w[0] < w[1]));
}

#[test]
fn test_replace_allow_lifts_covered_bans_and_reports() {
    let sink = Arc::new(Sink::default());
    let b = Bouncer::builder()
        .event_sink(sink.clone())
        .try_build()
        .unwrap();
    b.ban(ip("10.20.3.4")).unwrap();
    b.ban(c("10.20.9.0/24")).unwrap();
    b.ban(BanSpec::prefix(c("10.20.128.0/17")).by(Actor::Admin(1)))
        .unwrap();
    b.ban(ip("10.30.0.1")).unwrap();
    let mut conn = b.door(ip("10.20.5.5")).unwrap();
    b.replace_allow(AllowList::new().immune(c("10.20.0.0/16"), "infra"))
        .unwrap();
    assert!(b.door(ip("10.20.3.4")).is_ok());
    assert!(b.door(ip("10.20.200.1")).is_ok());
    assert!(b.door(ip("10.30.0.1")).is_err(), "outside the new entry");
    assert!(
        b.ban(ip("10.20.3.4")).is_err(),
        "now refused as allow-listed"
    );
    assert!(conn.checkpoint().is_pass(), "live tickets are not revoked");
    let lifted = sink
        .0
        .lock()
        .unwrap()
        .iter()
        .filter(|e| e.0 == signals::BAN_LIFTED.id)
        .count();
    assert_eq!(lifted, 3);
    assert_eq!(b.list(&Filter::all(), Page::first(10)).total, 1);
    // Swapping again drops the old entries.
    b.replace_allow(AllowList::new()).unwrap();
    assert!(b.ban(ip("10.20.3.4")).is_ok());
    let mut too_many = AllowList::new();
    for i in 0..=65_536u32 {
        too_many = too_many.immune(Cidr::host(IpAddr::from(i.to_be_bytes())), "x");
    }
    assert!(b.replace_allow(too_many).is_err());
}

#[test]
fn test_replace_allow_seen_by_other_threads() {
    let b = Arc::new(Bouncer::new());
    b.ban(ip("10.1.1.1")).unwrap();
    let b2 = Arc::clone(&b);
    // The other thread reads the list once (caching it), then again after the swap.
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let (tx2, rx2) = std::sync::mpsc::channel::<bool>();
    let t = std::thread::spawn(move || {
        tx2.send(b2.door(ip("10.1.1.1")).is_ok()).unwrap();
        rx.recv().unwrap();
        tx2.send(b2.door(ip("10.1.1.1")).is_ok()).unwrap();
    });
    assert!(!rx2.recv().unwrap());
    b.replace_allow(AllowList::new().immune(c("10.1.0.0/16"), "x"))
        .unwrap();
    tx.send(()).unwrap();
    assert!(rx2.recv().unwrap());
    t.join().unwrap();
}

#[test]
fn test_health_reports_loads_tickets_and_maintainer() {
    let b = Bouncer::builder()
        .tickets(64)
        .ban_capacity(64)
        .budgets(Budgets::off())
        .try_build()
        .unwrap();
    let h = b.health();
    assert!(h.is_ok());
    assert_eq!(h.maintainer, MaintainerState::NotStarted);
    assert_eq!(h.posture, Posture::Normal);
    let held: Vec<_> = (0..60u8)
        .map(|i| b.door(IpAddr::from([192, 0, 2, i])).unwrap())
        .collect();
    let tag = b.door(ip("192.0.2.250")).unwrap().into_tag();
    let h = b.health();
    assert_eq!(h.tickets_live, 61);
    assert_eq!(h.tickets_detached, 1);
    assert!(!h.is_ok(), "registry above 90%");
    drop(held);
    b.release(tag);
    // One per /24, so nothing escalates.
    for i in 0..60u8 {
        b.ban(IpAddr::from([198, 51, i, 1])).unwrap();
    }
    let h = b.health();
    assert!(h.ban_load > 0.9 && !h.is_ok());
    b.set_posture(Posture::Strict);
    assert_eq!(b.health().posture, Posture::Strict);

    let m = Bouncer::builder().maintainer(true).try_build().unwrap();
    let state = m.health().maintainer;
    assert!(matches!(
        state,
        MaintainerState::Parked | MaintainerState::Running
    ));
    let _ = m.door(ip("192.0.2.1")).map(|t| {
        let _ = t.request(RequestId(1));
    });
}
