//! Sharing across nodes (0.5): deltas converge under every order and
//! repetition. Threats T-17, T-27; edge cases 62 to 64.

use std::{collections::BTreeSet, net::IpAddr, sync::Arc, time::Duration};

use bouncer_io::{
    AccountKey, Actor, AllowList, BanSpec, Bouncer, BouncerError, Budgets, Cidr, Delta, Filter,
    ImportError, NodeId, Page, Reason, RequestId, Sequence, SessionKey,
};
use clock_lib::ManualClock;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn node(id: u16, clock: &Arc<ManualClock>) -> Bouncer {
    Bouncer::builder()
        .node(NodeId(id))
        .clock(clock.clone())
        .budgets(Budgets::off())
        .try_build()
        .unwrap()
}

fn keys(b: &Bouncer) -> BTreeSet<String> {
    b.list(&Filter::all(), Page::first(1000))
        .items
        .iter()
        .map(|r| r.key.to_string())
        .collect()
}

#[test]
fn test_a_ban_on_one_node_refuses_on_another() {
    let clock = Arc::new(ManualClock::new());
    let a = node(1, &clock);
    let b = node(2, &clock);
    a.ban(ip("198.51.100.9")).unwrap();
    let delta = a.export_delta(Sequence::START).unwrap();
    let report = b.import(&delta, Actor::Channel(1)).unwrap();
    assert_eq!(report.applied, 2, "the ban and its offender record");
    assert!(b.door(ip("198.51.100.9")).is_err());
    let rec = &b.explain(ip("198.51.100.9")).bans[0];
    assert_eq!(rec.origin, Some(NodeId(1)));
    // Each keeps enforcing when the other is gone.
    drop(a);
    assert!(b.door(ip("198.51.100.9")).is_err());
    // Without a node id there is nothing to export.
    assert_eq!(
        Bouncer::new().export_delta(Sequence::START).err(),
        Some(BouncerError::NodeIdUnset)
    );
}

#[test]
fn test_deltas_converge_under_every_order() {
    let clock = Arc::new(ManualClock::new());
    let a = node(1, &clock);
    let c = node(3, &clock);
    let mut deltas: Vec<(Delta, u64)> = Vec::new();
    let mut since_a = Sequence::START;
    let mut since_c = Sequence::START;
    let take = |b: &Bouncer, since: &mut Sequence, from: u64, deltas: &mut Vec<(Delta, u64)>| {
        let d = b.export_delta(*since).unwrap();
        *since = d.last();
        deltas.push((d, from));
    };
    a.ban(ip("192.0.2.1")).unwrap();
    a.ban(ip("192.0.2.2")).unwrap();
    take(&a, &mut since_a, 1, &mut deltas);
    clock.advance(Duration::from_secs(2));
    clock.step_wall_forward(Duration::from_secs(2));
    c.ban(ip("192.0.2.3")).unwrap();
    c.ban(BanSpec::key(AccountKey(4))).unwrap();
    take(&c, &mut since_c, 3, &mut deltas);
    clock.advance(Duration::from_secs(2));
    clock.step_wall_forward(Duration::from_secs(2));
    a.lift(ip("192.0.2.1")).unwrap();
    take(&a, &mut since_a, 1, &mut deltas);
    // Every permutation, each delivered twice.
    let n = deltas.len();
    let mut seen: Option<BTreeSet<String>> = None;
    let mut perm: Vec<usize> = (0..n).collect();
    let mut perms = Vec::new();
    heap(&mut perm, n, &mut perms);
    for order in perms {
        let b = node(2, &clock);
        for &i in order.iter().chain(order.iter()) {
            let (d, from) = &deltas[i];
            let _ = b.import(d, Actor::Channel(*from)).unwrap();
        }
        let k = keys(&b);
        match &seen {
            Some(s) => assert_eq!(&k, s, "order {order:?}"),
            None => seen = Some(k),
        }
    }
    let s = seen.unwrap();
    assert!(s.contains("192.0.2.2") && s.contains("192.0.2.3"));
    assert!(
        !s.contains("192.0.2.1"),
        "the later lift wins in every order: {s:?}"
    );
}

fn heap(a: &mut Vec<usize>, k: usize, out: &mut Vec<Vec<usize>>) {
    if k <= 1 {
        out.push(a.clone());
        return;
    }
    for i in 0..k {
        heap(a, k - 1, out);
        if k % 2 == 0 {
            a.swap(i, k - 1);
        } else {
            a.swap(0, k - 1);
        }
    }
}

#[test]
fn test_revocation_on_one_node_stops_a_request_on_another() {
    let clock = Arc::new(ManualClock::new());
    let a = node(1, &clock);
    let b = node(2, &clock);
    let session = SessionKey::from_digest([8; 16]);
    let conn = b.door(ip("192.0.2.40")).unwrap();
    let mut req = conn.request(RequestId(1)).unwrap();
    assert!(req.bind_session(session).is_pass());
    a.revoke(session, Reason::LOGOUT).unwrap();
    let report = b
        .import(&a.export_delta(Sequence::START).unwrap(), Actor::Channel(1))
        .unwrap();
    assert_eq!(report.revocations, 1);
    assert!(req.checkpoint().is_deny(), "logged out everywhere");
}

#[test]
fn test_duplicate_and_future_format_deltas() {
    // Edge cases 62 and 63.
    let clock = Arc::new(ManualClock::new());
    let a = node(1, &clock);
    let b = node(2, &clock);
    a.ban(ip("203.0.113.1")).unwrap();
    a.revoke(AccountKey(3), Reason::ADMIN).unwrap();
    let d = a.export_delta(Sequence::START).unwrap();
    let first = b.import(&d, Actor::Channel(1)).unwrap();
    let again = b.import(&d, Actor::Channel(1)).unwrap();
    assert_eq!(again.applied + again.revocations, 0);
    assert_eq!(again.duplicates, first.applied + first.revocations);
    let mut bytes = d.as_bytes().to_vec();
    bytes[4] = 7;
    assert_eq!(
        Delta::from_bytes(&bytes).err(),
        Some(BouncerError::Import(ImportError::UnsupportedFormat(7)))
    );
    let mut flipped = d.as_bytes().to_vec();
    let mid = flipped.len() / 2;
    flipped[mid] ^= 1;
    assert!(matches!(
        Delta::from_bytes(&flipped),
        Err(BouncerError::Import(ImportError::Corrupt { .. }))
    ));
    assert!(matches!(
        Delta::from_bytes(&vec![0u8; 17 << 20]),
        Err(BouncerError::Import(ImportError::TooLarge))
    ));
}

#[test]
fn test_lift_older_than_a_local_ban_leaves_it() {
    // Edge case 64.
    let clock = Arc::new(ManualClock::new());
    let a = node(1, &clock);
    let b = node(2, &clock);
    let addr = ip("198.51.100.70");
    a.ban(addr).unwrap();
    a.lift(addr).unwrap();
    let lift = a.export_delta(Sequence::START).unwrap();
    clock.advance(Duration::from_secs(5));
    clock.step_wall_forward(Duration::from_secs(5));
    b.ban(addr).unwrap();
    let _ = b.import(&lift, Actor::App).unwrap();
    assert!(b.door(addr).is_err(), "the ban issued after the lift stays");
}

#[test]
fn test_import_cannot_touch_allowlist_and_foreign_lifts_refused() {
    // T-17.
    let clock = Arc::new(ManualClock::new());
    let a = node(1, &clock);
    let b = Bouncer::builder()
        .node(NodeId(2))
        .clock(clock.clone())
        .allow(AllowList::new().immune("10.20.0.0/16".parse::<Cidr>().unwrap(), "infra"))
        .try_build()
        .unwrap();
    a.ban(ip("10.20.1.1")).unwrap();
    let report = b
        .import(&a.export_delta(Sequence::START).unwrap(), Actor::Channel(1))
        .unwrap();
    assert!(report.rejected >= 1);
    assert!(b.door(ip("10.20.1.1")).is_ok());
    // A ban issued on node 2, lifted on node 1, delivered by channel 1.
    b.ban(ip("192.0.2.99")).unwrap();
    let c = node(3, &clock);
    let _ = c
        .import(&b.export_delta(Sequence::START).unwrap(), Actor::Channel(2))
        .unwrap();
    let _ = a
        .import(&b.export_delta(Sequence::START).unwrap(), Actor::Channel(2))
        .unwrap();
    a.lift(ip("192.0.2.99")).unwrap();
    let lift = a.export_delta(Sequence::START).unwrap();
    let report = c.import(&lift, Actor::Channel(1)).unwrap();
    assert!(report.rejected >= 1, "{report:?}");
    assert!(
        c.door(ip("192.0.2.99")).is_err(),
        "node 1 cannot lift node 2's ban"
    );
}

#[test]
fn test_node_a_day_ahead_cannot_poison_the_cluster() {
    // T-27: a node with a broken clock is one day ahead.
    let clock = Arc::new(ManualClock::new());
    let ahead = Arc::new(ManualClock::new());
    ahead.step_wall_forward(Duration::from_secs(86_400));
    let a = node(1, &clock);
    let b = node(2, &clock);
    let c = node(3, &ahead);
    a.ban(ip("198.51.100.1")).unwrap();
    let _ = b
        .import(&a.export_delta(Sequence::START).unwrap(), Actor::Channel(1))
        .unwrap();
    let _ = c
        .import(&a.export_delta(Sequence::START).unwrap(), Actor::Channel(1))
        .unwrap();
    // C lifts it with a stamp a day in the future, and bans something.
    c.ban(ip("198.51.100.2")).unwrap();
    let report = b
        .import(&c.export_delta(Sequence::START).unwrap(), Actor::Channel(3))
        .unwrap();
    assert!(report.rejected >= 1);
    assert!(
        b.door(ip("198.51.100.2")).is_ok(),
        "a future-stamped ban is refused"
    );
    assert!(b.door(ip("198.51.100.1")).is_err());
}

#[test]
fn test_old_since_exports_everything() {
    let clock = Arc::new(ManualClock::new());
    let a = node(1, &clock);
    a.ban(ip("192.0.2.5")).unwrap();
    let snap = a.export_snapshot().unwrap();
    let b = node(2, &clock);
    let report = b.import(&snap, Actor::Channel(1)).unwrap();
    assert!(report.applied >= 1);
    assert!(b.door(ip("192.0.2.5")).is_err());
    assert!(
        a.export_delta(a.export_delta(Sequence::START).unwrap().last())
            .unwrap()
            .as_bytes()
            .len()
            < 64
    );
}
