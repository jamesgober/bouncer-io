//! Posture, lane and tenant budgets, and identity throttles (0.5).

use std::{
    net::IpAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use bouncer_io::{
    AccountKey, Bouncer, Budgets, DenialCode, Directive, Enforcement, Event, EventSink, LaneClass,
    Posture, Rate, Reason, RequestId, SessionKey, StrikeKind, StrikeOutcome, TenantKey, Verdict,
    signals,
};
use clock_lib::ManualClock;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn code(v: Verdict) -> Option<DenialCode> {
    match v {
        Verdict::Deny(d) => Some(d.code),
        _ => None,
    }
}

#[derive(Default)]
struct Sink(Mutex<Vec<u32>>);
impl EventSink for Sink {
    fn event(&self, e: &Event<'_>) {
        self.0.lock().unwrap().push(e.signal.id);
    }
}

#[test]
fn test_strict_posture_halves_door_rate_and_concurrency() {
    let clock = Arc::new(ManualClock::new());
    let b = Bouncer::builder()
        .clock(clock.clone())
        .budgets(
            Budgets::off()
                .door_rate(Rate::per_second(8).burst(8), Rate::per_second(10_000))
                .door_concurrency(1_000, 10_000),
        )
        .try_build()
        .unwrap();
    let admitted = |b: &Bouncer, addr: &str| {
        let mut held = Vec::new();
        while let Ok(t) = b.door(ip(addr)) {
            held.push(t);
            if held.len() > 100 {
                break;
            }
        }
        held.len()
    };
    assert_eq!(admitted(&b, "198.51.100.1"), 8);
    b.set_posture(Posture::Strict);
    assert_eq!(b.posture(), Posture::Strict);
    assert_eq!(
        admitted(&b, "198.51.100.2"),
        4,
        "each admission costs two tokens"
    );
    b.set_posture(Posture::Normal);
    assert_eq!(admitted(&b, "198.51.100.3"), 8);

    let b = Bouncer::builder()
        .budgets(Budgets::off().door_concurrency(6, 1_000))
        .strict_budget_divisor(3)
        .try_build()
        .unwrap();
    b.set_posture(Posture::Strict);
    assert_eq!(admitted(&b, "198.51.100.4"), 2, "concurrency 6 / 3");
}

#[test]
fn test_strict_posture_enforces_strict_kinds_and_reports() {
    let sink = Arc::new(Sink::default());
    let b = Bouncer::builder()
        .budgets(Budgets::off())
        .enforcement(Enforcement::observe_all().strict(&[StrikeKind::Malformed]))
        .event_sink(sink.clone())
        .try_build()
        .unwrap();
    let conn = b.door(ip("203.0.113.1")).unwrap();
    let mut last = conn.strike(StrikeKind::Malformed);
    for _ in 1..5 {
        last = conn.strike(StrikeKind::Malformed);
    }
    assert!(
        matches!(last, StrikeOutcome::ThresholdObserved { .. }),
        "{last:?}"
    );
    b.set_posture(Posture::Strict);
    let conn = b.door(ip("203.0.113.2")).unwrap();
    let mut last = conn.strike(StrikeKind::Malformed);
    for _ in 1..5 {
        last = conn.strike(StrikeKind::Malformed);
    }
    assert!(matches!(last, StrikeOutcome::Banned(_)), "{last:?}");
    b.set_posture(Posture::Strict); // no change, no event
    let changes = sink
        .0
        .lock()
        .unwrap()
        .iter()
        .filter(|&&id| id == signals::POSTURE_CHANGED.id)
        .count();
    assert_eq!(changes, 1);
}

#[test]
fn test_strict_revokes_unauthenticated_requests_only_when_asked() {
    for revoke in [false, true] {
        let b = Bouncer::builder()
            .budgets(Budgets::off())
            .strict_revokes_unauthenticated(revoke)
            .try_build()
            .unwrap();
        let mut conn = b.door(ip("192.0.2.1")).unwrap();
        let mut anonymous = conn.request(RequestId(1)).unwrap();
        let mut signed_in = conn.request(RequestId(2)).unwrap();
        assert!(
            signed_in
                .bind_session(SessionKey::from_digest([1; 16]))
                .is_pass()
        );
        b.set_posture(Posture::Strict);
        assert_eq!(anonymous.checkpoint().is_deny(), revoke);
        assert!(signed_in.checkpoint().is_pass());
        assert!(conn.checkpoint().is_pass(), "connections are not revoked");
        assert!(conn.request(RequestId(3)).is_ok());
    }
    assert!(
        Bouncer::builder()
            .strict_budget_divisor(0)
            .try_build()
            .is_err()
    );
}

#[test]
fn test_lane_budget_per_session_else_client() {
    let clock = Arc::new(ManualClock::new());
    let b = Bouncer::builder()
        .clock(clock.clone())
        .budgets(Budgets::off().lane_rate(LaneClass::Auth, Rate::per_second(2)))
        .try_build()
        .unwrap();
    let conn = b.door(ip("192.0.2.10")).unwrap();
    let lane = |id: u128, session: Option<u8>| {
        let mut r = conn.request(RequestId(id)).unwrap();
        if let Some(s) = session {
            assert!(r.bind_session(SessionKey::from_digest([s; 16])).is_pass());
        }
        code(r.bind_lane(LaneClass::Auth))
    };
    assert_eq!(lane(1, None), None);
    assert_eq!(lane(2, None), None);
    assert_eq!(
        lane(3, None),
        Some(DenialCode::TooManyRequests),
        "the client's lane is spent"
    );
    assert_eq!(lane(4, Some(1)), None, "a session has its own lane budget");
    assert_eq!(lane(5, Some(1)), None);
    assert_eq!(lane(6, Some(1)), Some(DenialCode::TooManyRequests));
    assert_eq!(lane(7, Some(2)), None);
    clock.advance(Duration::from_secs(1));
    assert_eq!(lane(8, Some(1)), None, "recovered");
    // Another lane, no budget.
    let mut r = conn.request(RequestId(9)).unwrap();
    assert!(r.bind_lane(LaneClass::Bulk).is_pass());
}

#[test]
fn test_lane_denial_keeps_connection_and_reports() {
    let sink = Arc::new(Sink::default());
    let b = Bouncer::builder()
        .budgets(Budgets::off().lane_rate(LaneClass::Write, Rate::per_second(1)))
        .event_sink(sink.clone())
        .try_build()
        .unwrap();
    let mut conn = b.door(ip("192.0.2.11")).unwrap();
    let mut first = conn.request(RequestId(1)).unwrap();
    assert!(first.bind_lane(LaneClass::Write).is_pass());
    let mut second = conn.request(RequestId(2)).unwrap();
    assert!(second.bind_lane(LaneClass::Write).is_deny());
    assert_eq!(
        code(second.checkpoint()),
        Some(DenialCode::TooManyRequests),
        "stays denied"
    );
    assert!(conn.checkpoint().is_pass());
    assert!(first.checkpoint().is_pass());
    assert!(sink.0.lock().unwrap().contains(&signals::BUDGET_REFUSED.id));
}

#[test]
fn test_tenant_rate_plans_and_in_flight() {
    let clock = Arc::new(ManualClock::new());
    let b = Bouncer::builder()
        .clock(clock.clone())
        .budgets(
            Budgets::off()
                .tenant_rate(Rate::per_second(2))
                .tenant_plan(TenantKey(7), Rate::per_second(5))
                .tenant_in_flight(3),
        )
        .try_build()
        .unwrap();
    let conn = b.door(ip("192.0.2.20")).unwrap();
    let bind = |id: u128, tenant: u64| {
        let mut r = conn.request(RequestId(id)).unwrap();
        let v = r.bind_tenant(TenantKey(tenant));
        (r, code(v))
    };
    // Default rate 2 per second.
    let (a, va) = bind(1, 1);
    let (_b2, vb) = bind(2, 1);
    let (_c, vc) = bind(3, 1);
    assert_eq!(
        (va, vb, vc),
        (None, None, Some(DenialCode::TooManyRequests))
    );
    drop(a);
    // Tenant 7's plan: 5 per second, but at most 3 in flight.
    let mut held = Vec::new();
    for id in 10..13 {
        let (r, v) = bind(id, 7);
        assert_eq!(v, None);
        held.push(r);
    }
    let (_r, v) = bind(13, 7);
    assert_eq!(v, Some(DenialCode::TooManyRequests), "in flight");
    held.pop();
    let (_r, v) = bind(14, 7);
    assert_eq!(v, None, "a released ticket returns its slot");
    let (_r, v) = bind(15, 7);
    assert_eq!(
        v,
        Some(DenialCode::TooManyRequests),
        "rate (5 per second) spent"
    );
    clock.advance(Duration::from_secs(1));
    let (_r, v) = bind(16, 1);
    assert_eq!(v, None);
}

#[test]
fn test_identity_throttles_divide_lane_and_tenant() {
    let clock = Arc::new(ManualClock::new());
    let b = Bouncer::builder()
        .clock(clock.clone())
        .budgets(
            Budgets::off()
                .lane_rate(LaneClass::Normal, Rate::per_second(8))
                .tenant_rate(Rate::per_second(8)),
        )
        .try_build()
        .unwrap();
    let conn = b.door(ip("192.0.2.30")).unwrap();
    b.apply(Directive::throttle(AccountKey(5), 4, Duration::from_secs(60)).because(Reason::POLICY))
        .unwrap();
    b.apply(Directive::throttle(
        TenantKey(9),
        8,
        Duration::from_secs(60),
    ))
    .unwrap();
    // One session, 8 lane tokens. Bound to the throttled account, each
    // request costs 4: two pass. Without the account, all 8 would.
    let lane = |id: u128, account: bool| {
        let mut r = conn.request(RequestId(id)).unwrap();
        assert!(r.bind_session(SessionKey::from_digest([1; 16])).is_pass());
        if account {
            assert!(r.bind_account(AccountKey(5)).is_pass());
        }
        r.bind_lane(LaneClass::Normal).is_pass()
    };
    let ok = (0..8).filter(|&id| lane(id, true)).count();
    assert_eq!(ok, 2);
    clock.advance(Duration::from_secs(1));
    let ok = (10..18).filter(|&id| lane(id, false)).count();
    assert_eq!(ok, 8, "the session alone is not throttled");
    let mut r = conn.request(RequestId(100)).unwrap();
    assert!(r.bind_tenant(TenantKey(9)).is_pass(), "8 tokens, cost 8");
    let mut r = conn.request(RequestId(101)).unwrap();
    assert!(r.bind_tenant(TenantKey(9)).is_deny());
    // Connections and requests are not throttle targets.
    assert!(
        b.apply(Directive::throttle(conn.conn(), 2, Duration::from_secs(1)))
            .is_err()
    );
}
