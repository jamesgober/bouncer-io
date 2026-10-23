//! Counters (feature `metrics`).
#![cfg(feature = "metrics")]

use std::net::IpAddr;

use bouncer_io::{Bouncer, Budgets, Collected, Reason, RequestId, StrikeKind};

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[test]
fn test_metrics_count_door_checkpoints_bans_and_revocations() {
    let b = Bouncer::builder()
        .budgets(Budgets::off())
        .try_build()
        .unwrap();
    let mut conn = b.door(ip("192.0.2.1")).unwrap();
    for _ in 0..10 {
        assert!(conn.checkpoint().is_pass());
    }
    b.ban(ip("198.51.100.1")).unwrap();
    assert!(b.door(ip("198.51.100.1")).is_err());
    let mut req = conn.request(RequestId(1)).unwrap();
    let _ = req.strike(StrikeKind::Malformed);
    b.revoke(RequestId(1), Reason::ADMIN).unwrap();
    assert!(req.checkpoint().is_deny());
    let _ = req.deny_and_eject(&mut Collected::new());
    assert!(req.before_commit().is_deny());
    drop(req);
    let m = b.metrics();
    assert_eq!(m.admitted, 1);
    assert_eq!(m.refused_ban, 1);
    assert_eq!(m.bans_added, 1);
    assert_eq!(m.bans_active, 1);
    assert_eq!(m.revocations, 1);
    assert_eq!(m.strikes, 1);
    assert_eq!(m.denials, 1);
    assert_eq!(m.commits_blocked, 1);
    assert!(m.checkpoints_slow >= 1);
    // The connection's fast checks reach the counter when it is dropped.
    drop(conn);
    assert!(b.metrics().checkpoints_fast >= 9, "{:?}", b.metrics());
}
