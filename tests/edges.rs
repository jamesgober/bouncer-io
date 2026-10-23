//! Edge cases 53, 55, 58, 65, 66, and 67 (0.5).

use std::{
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use bouncer_io::{
    BanSpec, Bouncer, Budgets, CloseKind, ConnId, Directive, DurationPolicy, Ejector, Event,
    EventSink, MaintainerState, Reason, RequestId, RevokeMode, SessionKey,
};
use clock_lib::ManualClock;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn length(b: &Bouncer, addr: IpAddr) -> u64 {
    let r = &b.explain(addr).bans[0];
    r.until.unwrap().duration_since(r.issued).unwrap().as_secs()
}

#[test]
fn test_duration_arithmetic_at_the_limits() {
    // Edge case 53: at `step_cap`, at `max`, with factor 1, with no jitter.
    let clock = Arc::new(ManualClock::new());
    let run = |policy: DurationPolicy, rounds: usize| -> Vec<u64> {
        let b = Bouncer::builder()
            .clock(clock.clone())
            .durations(policy.jitter(Duration::ZERO))
            .try_build()
            .unwrap();
        let addr = ip("192.0.2.9");
        (0..rounds)
            .map(|_| {
                b.ban(addr).unwrap();
                let l = length(&b, addr);
                clock.advance(Duration::from_secs(l + 1));
                l
            })
            .collect()
    };
    let base = DurationPolicy::default().base(Duration::from_secs(10));
    assert_eq!(run(base.factor(1), 4), vec![10, 10, 10, 10]);
    assert_eq!(run(base.step_cap(2), 5), vec![10, 20, 40, 40, 40]);
    assert_eq!(
        run(base.max(Duration::from_secs(30)), 4),
        vec![10, 20, 30, 30]
    );
}

#[test]
fn test_monotonic_expiry_ignores_the_wall_clock() {
    // Edge cases 55 and 58: a manual clock past the end admits; wall steps
    // (a leap second, an NTP step) change nothing in process.
    let clock = Arc::new(ManualClock::new());
    let b = Bouncer::builder().clock(clock.clone()).try_build().unwrap();
    let addr = ip("198.51.100.3");
    b.ban(BanSpec::address(addr).for_duration(Duration::from_secs(60)))
        .unwrap();
    clock.step_wall_forward(Duration::from_secs(86_400));
    assert!(
        b.door(addr).is_err(),
        "a wall jump forward does not expire it"
    );
    clock.step_wall_back(Duration::from_secs(2 * 86_400));
    assert!(b.door(addr).is_err());
    clock.advance(Duration::from_secs(61));
    assert!(b.door(addr).is_ok(), "monotonic time ends it");
}

#[test]
fn test_hammering_one_shard_while_banning_and_lifting() {
    // Edge case 65: 32 threads on one shard, one thread banning and lifting.
    let b = Arc::new(
        Bouncer::builder()
            .shards(1)
            .tickets(4096)
            .budgets(Budgets::off())
            .try_build()
            .unwrap(),
    );
    let stop = Arc::new(AtomicBool::new(false));
    let checks = Arc::new(AtomicU64::new(0));
    let mut workers = Vec::new();
    for t in 0..32u8 {
        let (b, stop, checks) = (Arc::clone(&b), Arc::clone(&stop), Arc::clone(&checks));
        workers.push(std::thread::spawn(move || {
            let addr = IpAddr::from([192, 0, 2, t]);
            while !stop.load(Ordering::Relaxed) {
                let mut conn = b.door(addr).expect("never banned");
                for id in 0..8u128 {
                    let mut req = conn.request(RequestId(id)).unwrap();
                    assert!(req.checkpoint().is_pass());
                    assert!(req.before_commit().is_pass());
                }
                assert!(conn.checkpoint().is_pass());
                checks.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }
    let started = Instant::now();
    let mut ops = 0u32;
    while started.elapsed() < Duration::from_millis(500) {
        let addr = IpAddr::from([198, 51, (ops >> 8) as u8, ops as u8]);
        b.ban(addr).unwrap();
        assert!(b.door(addr).is_err(), "refused once ban returns");
        b.lift(addr).unwrap();
        assert!(b.door(addr).is_ok());
        ops += 1;
    }
    stop.store(true, Ordering::Relaxed);
    for w in workers {
        w.join().unwrap();
    }
    assert!(ops > 100 && checks.load(Ordering::Relaxed) > 100);
}

/// An ejector that panics on the maintainer thread only.
struct PanicsOnMaintainer;
impl Ejector for PanicsOnMaintainer {
    fn eject(&self, _conn: ConnId, _kind: CloseKind) {
        if std::thread::current().name() == Some("bouncer-maintainer") {
            panic!("ejector failed on the maintainer");
        }
    }
}

#[test]
fn test_maintainer_death_leaves_enforcement_and_maintain() {
    // Edge case 66.
    let b = Bouncer::builder()
        .maintainer(true)
        .ejector(Arc::new(PanicsOnMaintainer))
        .try_build()
        .unwrap();
    let session = SessionKey::from_digest([6; 16]);
    let conn = b.door(ip("192.0.2.66")).unwrap();
    let mut req = conn.request(RequestId(1)).unwrap();
    assert!(req.bind_session(session).is_pass());
    b.apply(
        Directive::revoke(session)
            .because(Reason::ADMIN)
            .eject_now(),
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while b.health().maintainer != MaintainerState::Stopped && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(b.health().maintainer, MaintainerState::Stopped);
    assert!(!b.health().is_ok());
    // Enforcement does not depend on the thread.
    assert!(req.checkpoint().is_deny());
    b.ban(ip("198.51.100.66")).unwrap();
    assert!(b.door(ip("198.51.100.66")).is_err());
    let _ = b.maintain(b.now());
    let _ = RevokeMode::EjectNow;
}

/// A sink that blocks (against its contract).
struct Slow;
impl EventSink for Slow {
    fn event(&self, _e: &Event<'_>) {
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn test_blocking_sink_never_slows_checkpoints() {
    // Edge case 67.
    let b = Bouncer::builder()
        .event_sink(Arc::new(Slow))
        .budgets(Budgets::off())
        .try_build()
        .unwrap();
    let mut conn = b.door(ip("192.0.2.67")).unwrap();
    let mut req = conn.request(RequestId(1)).unwrap();
    let started = Instant::now();
    for _ in 0..1_000_000 {
        assert!(req.checkpoint().is_pass());
    }
    assert!(conn.checkpoint().is_pass());
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "checkpoints never call the sink: {:?}",
        started.elapsed()
    );
}
