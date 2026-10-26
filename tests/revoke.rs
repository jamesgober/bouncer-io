//! In-flight revocation, tags, egress, binds, strikes, directives, and
//! maintenance: edge cases 20 and 27 to 41, threats T-1 (strikes), T-6, T-7
//! (in-process), T-11 to T-14, T-26 (dev/PLAN.md sections 8 and 12.5).

use std::{
    net::IpAddr,
    sync::{
        Arc, Barrier, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use bouncer_io::{
    AccountKey, Actor, AllowList, BanKey, BanKeys, BanSpec, Bouncer, BouncerError, Budgets, Cidr,
    CloseKind, ConnId, DenialCode, Directive, Ejector, Enforcement, Event, EventSink,
    FingerprintKey, IgnoredBecause, Provenance, Rate, Reason, Refusal, RequestId, RevocationEpoch,
    SessionKey, StrikeKind, StrikeOutcome, Target, TenantKey, Verdict, signals,
};
use clock_lib::ManualClock;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn c(s: &str) -> Cidr {
    s.parse().unwrap()
}

fn plain() -> Bouncer {
    Bouncer::builder()
        .budgets(Budgets::off())
        .seed([4; 32])
        .try_build()
        .unwrap()
}

fn denied(v: Verdict) -> Option<DenialCode> {
    v.denial().map(|d| d.code)
}

#[derive(Default)]
struct Events(Mutex<Vec<(u32, bouncer_io::Mode)>>);
impl EventSink for Events {
    fn event(&self, e: &Event<'_>) {
        self.0.lock().unwrap().push((e.signal.id, e.mode));
    }
}
impl Events {
    fn count(&self, id: u32) -> usize {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|(i, _)| *i == id)
            .count()
    }
}

#[derive(Default)]
struct Kills(Mutex<Vec<ConnId>>);
impl Ejector for Kills {
    fn eject(&self, conn: ConnId, _kind: CloseKind) {
        self.0.lock().unwrap().push(conn);
    }
}

// ---- Revocation by every target ------------------------------------------------

#[test]
fn test_revoke_every_target_denies_at_checkpoint() {
    let b = plain();
    let session = SessionKey::from_digest([1; 16]);
    let fp = FingerprintKey::from_digest([2; 16]);
    let targets: [Target; 7] = [
        Target::Connection(ConnId(0)), // replaced below with the live connection's id
        Target::Request(RequestId(77)),
        Target::Session(session),
        Target::Account(AccountKey(5)),
        Target::Tenant(TenantKey(9)),
        Target::Source(c("198.51.100.0/24")),
        Target::Fingerprint(fp),
    ];
    for target in targets {
        let mut conn = b.door(ip("198.51.100.20")).unwrap();
        assert!(conn.bind_fingerprint(fp).is_pass());
        let mut req = conn.request(RequestId(77)).unwrap();
        assert!(req.bind_session(session).is_pass());
        assert!(req.bind_account(AccountKey(5)).is_pass());
        assert!(req.bind_tenant(TenantKey(9)).is_pass());
        assert!(req.checkpoint().is_pass());
        let target = match target {
            Target::Connection(_) => Target::Connection(conn.conn()),
            t => t,
        };
        b.revoke(target, Reason::ADMIN).unwrap();
        assert_eq!(
            denied(req.checkpoint()),
            Some(DenialCode::Forbidden),
            "{target:?}"
        );
        assert!(req.checkpoint().is_deny(), "stays denied: {target:?}");
        assert!(req.before_commit().is_deny(), "{target:?}");
        assert!(req.is_cancelled(), "{target:?}");
        // The request's revocation takes its connection with it.
        assert!(
            conn.checkpoint().is_deny(),
            "connection ejected too: {target:?}"
        );
        drop(req);
        drop(conn);
        assert_eq!(
            b.maintain(b.now()).reclaimed,
            1,
            "entry reclaimed once nothing needs it"
        );
    }
}

#[test]
fn test_revoke_request_keep_connection() {
    // Edge case 37.
    let b = plain();
    let mut conn = b.door(ip("192.0.2.1")).unwrap();
    let mut r1 = conn.request(RequestId(1)).unwrap();
    b.apply(Directive::revoke(RequestId(1)).keep_connection())
        .unwrap();
    assert!(r1.checkpoint().is_deny());
    assert!(conn.checkpoint().is_pass(), "the connection continues");
    let mut r2 = conn.request(RequestId(2)).unwrap();
    assert!(r2.checkpoint().is_pass(), "later requests unaffected");
}

#[test]
fn test_revoke_deny_with_not_found() {
    let b = plain();
    let conn = b.door(ip("192.0.2.1")).unwrap();
    let mut r = conn.request(RequestId(1)).unwrap();
    b.apply(Directive::revoke(RequestId(1)).deny_with(DenialCode::NotFound))
        .unwrap();
    assert_eq!(denied(r.checkpoint()), Some(DenialCode::NotFound));
}

#[test]
fn test_revoke_twice_one_entry_strongest_code() {
    // Edge case 33.
    let b = plain();
    let conn = b.door(ip("192.0.2.1")).unwrap();
    let mut r = conn.request(RequestId(1)).unwrap();
    b.apply(Directive::revoke(RequestId(1)).deny_with(DenialCode::NotFound))
        .unwrap();
    b.apply(Directive::revoke(RequestId(1)).deny_with(DenialCode::Forbidden))
        .unwrap();
    assert_eq!(denied(r.checkpoint()), Some(DenialCode::Forbidden));
    drop(r);
    drop(conn);
    assert_eq!(
        b.maintain(b.now()).reclaimed,
        1,
        "one entry for both revocations"
    );
}

#[test]
fn test_revoke_never_issued_connection_reclaimed() {
    // Edge case 32.
    let b = plain();
    let receipt = b.revoke(ConnId(123_456), Reason::ADMIN).unwrap();
    assert!(receipt.epoch > 0);
    let mut live = b.door(ip("192.0.2.1")).unwrap();
    assert!(live.checkpoint().is_pass());
    assert_eq!(b.maintain(b.now()).reclaimed, 1);
}

#[test]
fn test_revoke_source_covering_trusted_proxy() {
    // Edge case 38.
    let b = Bouncer::builder()
        .trusted_proxies(&[c("198.51.100.1/32")])
        .budgets(Budgets::off())
        .try_build()
        .unwrap();
    let mut hop = b.door(ip("198.51.100.1")).unwrap();
    let mut inside = hop.request(RequestId(1)).unwrap();
    assert!(
        inside
            .bind_client(ip("198.51.100.50"), Provenance::ForwardedHeader)
            .is_pass()
    );
    let mut outside = hop.request(RequestId(2)).unwrap();
    assert!(
        outside
            .bind_client(ip("203.0.113.5"), Provenance::ForwardedHeader)
            .is_pass()
    );
    b.apply(Directive::revoke(c("198.51.100.0/24")).keep_connection())
        .unwrap();
    assert!(
        inside.checkpoint().is_deny(),
        "real client inside the prefix"
    );
    assert!(outside.checkpoint().is_pass());
    assert!(
        hop.checkpoint().is_pass(),
        "the proxy hop itself is not revoked"
    );
    // A prefix that is entirely a trusted proxy is refused.
    assert_eq!(
        b.revoke(c("198.51.100.1/32"), Reason::ADMIN).err(),
        Some(BouncerError::TrustedProxyTarget)
    );
}

#[test]
fn test_revoke_allowlisted_source_refused_for_automation_only() {
    let b = Bouncer::builder()
        .allow(AllowList::new().immune(c("10.0.0.0/8"), "infra"))
        .budgets(Budgets::off())
        .try_build()
        .unwrap();
    let r = b.apply(Directive::revoke(c("10.1.0.0/16")).by(Actor::Policy(1)));
    assert!(matches!(r, Err(BouncerError::AllowListed { .. })));
    assert!(
        b.revoke(c("10.1.0.0/16"), Reason::ADMIN).is_ok(),
        "an administrator can"
    );
}

#[test]
fn test_issue_after_revoke_sees_it() {
    let b = plain();
    b.revoke(c("192.0.2.0/24"), Reason::ADMIN).unwrap();
    let mut conn = b.door(ip("192.0.2.5")).unwrap();
    assert!(
        conn.checkpoint().is_deny(),
        "a source revocation reaches tickets issued after it"
    );
    let mut other = b.door(ip("192.0.3.5")).unwrap();
    assert!(other.checkpoint().is_pass());
}

// ---- Binds ------------------------------------------------------------------------

#[test]
fn test_bind_twice_denied_first_kept() {
    // Edge case 20.
    let b = plain();
    let conn = b.door(ip("192.0.2.1")).unwrap();
    let mut r = conn.request(RequestId(1)).unwrap();
    let first = SessionKey::from_digest([1; 16]);
    assert!(r.bind_session(first).is_pass());
    assert!(r.bind_session(SessionKey::from_digest([2; 16])).is_deny());
    b.revoke(first, Reason::LOGOUT).unwrap();
    assert!(
        r.checkpoint().is_deny(),
        "the first session is the one bound"
    );
}

#[test]
fn test_bind_after_revoke_and_ban_checks() {
    let b = plain();
    let s = SessionKey::from_digest([3; 16]);
    b.revoke(s, Reason::LOGOUT).unwrap();
    let conn = b.door(ip("192.0.2.1")).unwrap();
    let mut r = conn.request(RequestId(1)).unwrap();
    assert!(
        r.bind_session(s).is_deny(),
        "a revoked session is denied at bind"
    );
    // The denied bind took its connection with it; a new connection.
    assert_eq!(
        conn.request(RequestId(2)).err(),
        Some(BouncerError::Revoked)
    );
    b.ban(BanSpec::key(AccountKey(8))).unwrap();
    let conn2 = b.door(ip("192.0.2.2")).unwrap();
    let mut r2 = conn2.request(RequestId(2)).unwrap();
    assert_eq!(
        denied(r2.bind_account(AccountKey(8))),
        Some(DenialCode::Forbidden)
    );
}

#[test]
fn test_bind_fingerprint_compound_ban() {
    // Threat T-11: automation bans a fingerprint only within a prefix.
    let b = plain();
    let fp = FingerprintKey::from_digest([6; 16]);
    assert_eq!(
        b.ban(BanSpec::key(fp).by(Actor::Local)).err(),
        Some(BouncerError::InvalidTarget)
    );
    b.ban(BanSpec::key(BanKey::FingerprintIn(fp, c("203.0.113.0/24"))).by(Actor::Local))
        .unwrap();
    let mut inside = b.door(ip("203.0.113.9")).unwrap();
    assert!(inside.bind_fingerprint(fp).is_deny());
    let mut elsewhere = b.door(ip("198.51.100.9")).unwrap();
    assert!(
        elsewhere.bind_fingerprint(fp).is_pass(),
        "the same browser build elsewhere is fine"
    );
}

// ---- Tags and egress ----------------------------------------------------------------

#[test]
fn test_tags_request_egress_release() {
    // Edge cases 27 and 28.
    let b = plain();
    let conn = b.door(ip("192.0.2.1")).unwrap();
    let id = conn.conn();
    let tag = conn.into_tag();
    let mut req = b.request(tag, RequestId(1)).unwrap();
    assert!(b.egress(tag).is_pass());
    assert!(b.egress(req.tag()).is_pass());
    b.revoke(id, Reason::ADMIN).unwrap();
    assert!(b.egress(tag).is_deny());
    assert!(req.checkpoint().is_deny());
    drop(req);
    assert!(b.release(tag));
    assert!(!b.release(tag), "second release");
    assert_eq!(
        b.request(tag, RequestId(2)).err(),
        Some(BouncerError::Stale)
    );
    assert!(b.egress(tag).is_deny(), "a released tag fails closed");
    assert!(
        b.egress(bouncer_io::TicketTag::from_raw(u64::MAX))
            .is_deny()
    );
}

#[test]
fn test_egress_after_revoke_writes_only_denial() {
    // Threat T-7 (in process): a transport streaming 10 MiB in 16 KiB
    // chunks checks egress before each write; another thread revokes the
    // connection mid-stream. After `revoke` returns, at most the chunk whose
    // check had already passed leaves, then only the denial.
    const CHUNK: usize = 16 * 1024;
    const CHUNKS: usize = 640;
    for round in 0..50u64 {
        let b = Arc::new(plain());
        let conn = b.door(ip("192.0.2.1")).unwrap();
        let id = conn.conn();
        let tag = conn.into_tag();
        let written = Arc::new(AtomicU64::new(0));
        let writer = {
            let (b, written) = (Arc::clone(&b), Arc::clone(&written));
            std::thread::spawn(move || {
                let mut out: Vec<u8> = Vec::with_capacity(CHUNK * CHUNKS);
                for n in 0..CHUNKS {
                    if b.egress(tag).is_deny() {
                        out.extend_from_slice(b"DENIED");
                        return (out, true);
                    }
                    out.extend(std::iter::repeat_n((n % 251) as u8, CHUNK));
                    written.fetch_add(1, Ordering::SeqCst);
                }
                (out, false)
            })
        };
        let at = 20 + (round as usize * 11) % 400;
        while written.load(Ordering::SeqCst) < at as u64 && !writer.is_finished() {
            std::hint::spin_loop();
        }
        b.revoke(id, Reason::ADMIN).unwrap();
        let after_revoke = written.load(Ordering::SeqCst);
        let (out, denied) = writer.join().unwrap();
        let chunks = (out.len() / CHUNK) as u64;
        if after_revoke < CHUNKS as u64 {
            assert!(denied, "round {round}: the stream was cut");
            assert!(out.ends_with(b"DENIED"));
            assert!(
                chunks <= after_revoke + 1,
                "round {round}: {chunks} chunks left, {after_revoke} when revoke returned"
            );
        }
        b.release(tag);
    }
}

#[test]
fn test_egress_connection_tag_sees_latest_request_session_revocation() {
    // Edge case 41.
    let b = plain();
    let tag = b.door(ip("192.0.2.1")).unwrap().into_tag();
    let mut req = b.request(tag, RequestId(1)).unwrap();
    let s = SessionKey::from_digest([7; 16]);
    assert!(req.bind_session(s).is_pass());
    assert!(b.egress(tag).is_pass());
    b.revoke(s, Reason::LOGOUT).unwrap();
    assert!(
        b.egress(tag).is_deny(),
        "the pipeline never checked; the transport did"
    );
    drop(req);
    b.release(tag);
}

#[test]
fn test_release_of_handle_ticket_by_tag_refused() {
    let b = plain();
    let conn = b.door(ip("192.0.2.1")).unwrap();
    assert!(
        !b.release(conn.tag()),
        "only detached tickets are released by tag"
    );
    let mut conn = conn;
    assert!(conn.checkpoint().is_pass());
}

// ---- Ordering under concurrency -------------------------------------------------------

#[test]
fn test_no_checkpoint_after_revoke_returned_passes() {
    // Threat T-6: 8 threads checkpoint continuously; a revoker revokes their
    // sessions one by one. Any checkpoint that starts after the revoke of its
    // session returned must deny.
    let b = plain();
    let threads = 8;
    let revoked: Arc<Vec<AtomicBool>> =
        Arc::new((0..threads).map(|_| AtomicBool::new(false)).collect());
    let barrier = Arc::new(Barrier::new(threads + 1));
    let checks = Arc::new(AtomicU64::new(0));
    let handles: Vec<_> = (0..threads)
        .map(|t| {
            let (b, revoked, barrier, checks) = (
                b.clone(),
                Arc::clone(&revoked),
                Arc::clone(&barrier),
                Arc::clone(&checks),
            );
            std::thread::spawn(move || {
                let conn = b.door(IpAddr::from([192, 0, 2, t as u8 + 1])).unwrap();
                let mut req = conn.request(RequestId(t as u128)).unwrap();
                assert!(
                    req.bind_session(SessionKey::from_digest([t as u8; 16]))
                        .is_pass()
                );
                barrier.wait();
                loop {
                    let was_revoked = revoked[t].load(Ordering::SeqCst);
                    let v = req.before_commit();
                    checks.fetch_add(1, Ordering::Relaxed);
                    if was_revoked {
                        assert!(v.is_deny(), "thread {t}: passed after revoke returned");
                        break;
                    }
                }
            })
        })
        .collect();
    barrier.wait();
    for t in 0..threads {
        std::thread::sleep(Duration::from_millis(2));
        b.revoke(SessionKey::from_digest([t as u8; 16]), Reason::LOGOUT)
            .unwrap();
        revoked[t].store(true, Ordering::SeqCst);
    }
    for h in handles {
        h.join().unwrap();
    }
    assert!(checks.load(Ordering::Relaxed) > threads as u64);
}

// ---- Table full, eject-now, idle tickets --------------------------------------------

#[test]
fn test_revocation_table_full_still_reaches_live_tickets() {
    // Edge case 35, threat T-13.
    let b = Bouncer::builder()
        .revocation_capacity(4)
        .budgets(Budgets::off())
        .try_build()
        .unwrap();
    for i in 0..4u64 {
        b.revoke(ConnId(900 + i), Reason::ADMIN).unwrap();
    }
    let conn = b.door(ip("192.0.2.1")).unwrap();
    let mut r = conn.request(RequestId(1)).unwrap();
    let mut err = None;
    for i in 4..64u64 {
        if let Err(e) = b.revoke(ConnId(900 + i), Reason::ADMIN) {
            err = Some(e);
            break;
        }
    }
    assert!(
        matches!(err, Some(BouncerError::RevocationTableFull { .. })),
        "{err:?}"
    );
    assert!(matches!(
        b.revoke(conn.conn(), Reason::ADMIN),
        Err(BouncerError::RevocationTableFull { .. })
    ));
    assert!(
        r.checkpoint().is_deny(),
        "the direct sweep flagged the live ticket"
    );
}

#[test]
fn test_eject_now_closes_idle_connections() {
    // FR-30.
    let kills = Arc::new(Kills::default());
    let b = Bouncer::builder()
        .ejector(kills.clone())
        .budgets(Budgets::off())
        .try_build()
        .unwrap();
    let idle = b.door(ip("192.0.2.1")).unwrap();
    let other = b.door(ip("192.0.2.2")).unwrap();
    let r = b.apply(Directive::revoke(idle.conn()).eject_now()).unwrap();
    assert_eq!(r.revocation.unwrap().matched_live, Some(1));
    assert_eq!(*kills.0.lock().unwrap(), vec![idle.conn()]);
    drop(other);
}

#[test]
fn test_idle_ticket_checked_on_its_behalf_and_reported() {
    // Edge case 36, threat T-26.
    let clock = Arc::new(ManualClock::new());
    let kills = Arc::new(Kills::default());
    let events = Arc::new(Events::default());
    let b = Bouncer::builder()
        .clock(clock.clone())
        .ejector(kills.clone())
        .event_sink(events.clone())
        .max_unchecked(Duration::from_secs(30))
        .budgets(Budgets::off())
        .try_build()
        .unwrap();
    let ws = b.door(ip("192.0.2.1")).unwrap(); // a parked WebSocket: never checks
    let s = SessionKey::from_digest([9; 16]);
    let mut req = ws.request(RequestId(1)).unwrap();
    assert!(req.bind_session(s).is_pass());
    b.revoke(s, Reason::LOGOUT).unwrap();
    let first = b.maintain(b.now());
    assert_eq!(first.idle_checked, 0, "not idle yet");
    assert!(first.next_due.is_some());
    clock.advance(Duration::from_secs(31));
    let second = b.maintain(b.now());
    assert!(second.idle_checked >= 1);
    assert_eq!(*kills.0.lock().unwrap(), vec![ws.conn()]);
    assert!(events.count(signals::CHECKPOINT_MISSING.id) >= 1);
    assert!(req.checkpoint().is_deny());
    drop(req);
    drop(ws);
    let third = b.maintain(b.now());
    // Once both tickets carry the revoked flag, the entry is no longer needed.
    assert_eq!(second.reclaimed + third.reclaimed, 1);
    assert_eq!(third.next_due, None);
}

#[test]
fn test_maintainer_thread_parks_and_cleans_up() {
    // NFR-8: with nothing pending the thread does not wake; it is unparked
    // by revocations.
    let b = Bouncer::builder()
        .maintainer(true)
        .budgets(Budgets::off())
        .try_build()
        .unwrap();
    b.revoke(AccountKey(1), Reason::ADMIN).unwrap();
    let mut done = false;
    for _ in 0..200 {
        std::thread::sleep(Duration::from_millis(5));
        if b.maintain(b.now()).next_due.is_none() {
            done = true;
            break;
        }
    }
    assert!(done, "the entry was reclaimed");
    drop(b); // stops the thread
}

#[test]
fn test_connection_dropped_with_live_request_after_revocation() {
    // Edge case 39-style: counts and state stay consistent.
    let b = plain();
    let conn = b.door(ip("192.0.2.1")).unwrap();
    let mut req = conn.request(RequestId(1)).unwrap();
    assert!(req.bind_tenant(TenantKey(4)).is_pass());
    b.revoke(TenantKey(4), Reason::ADMIN).unwrap();
    drop(conn);
    assert!(req.checkpoint().is_deny());
    drop(req);
    assert_eq!(b.maintain(b.now()).reclaimed, 1);
}

// ---- Strikes ----------------------------------------------------------------------

#[test]
fn test_strikes_observe_by_default_then_enforce() {
    let events = Arc::new(Events::default());
    let b = Bouncer::builder()
        .event_sink(events.clone())
        .budgets(Budgets::off())
        .try_build()
        .unwrap();
    let mut conn = b.door(ip("198.51.100.1")).unwrap();
    let outcomes: Vec<_> = (0..6).map(|_| conn.strike(StrikeKind::Malformed)).collect();
    assert!(matches!(
        outcomes[4],
        StrikeOutcome::ThresholdObserved {
            would_ban: BanKey::Address(_)
        }
    ));
    assert!(conn.checkpoint().is_pass(), "observe mode does nothing");
    assert!(b.door(ip("198.51.100.1")).is_ok());
    assert_eq!(events.count(signals::STRIKE.id), 6);
    let observed = events
        .0
        .lock()
        .unwrap()
        .iter()
        .filter(|(i, m)| *i == signals::THRESHOLD_REACHED.id && *m == bouncer_io::Mode::Observe)
        .count();
    assert_eq!(observed, 1);

    let b = Bouncer::builder()
        .enforcement(Enforcement::observe_all().enforce(StrikeKind::LoginFailed))
        .budgets(Budgets::off())
        .try_build()
        .unwrap();
    let mut conn = b.door(ip("198.51.100.2")).unwrap();
    let mut last = conn.strike(StrikeKind::LoginFailed);
    for _ in 1..5 {
        last = conn.strike(StrikeKind::LoginFailed);
    }
    assert!(matches!(last, StrikeOutcome::Banned(_)));
    assert!(conn.checkpoint().is_deny());
    assert!(matches!(
        b.door(ip("198.51.100.2")),
        Err(Refusal::Banned { .. })
    ));
}

#[test]
fn test_strike_on_proxy_hop_ignored_and_real_client_struck() {
    // Threat T-1 (strike part).
    let b = Bouncer::builder()
        .trusted_proxies(&[c("10.0.0.1/32")])
        .enforcement(Enforcement::enforce_all())
        .budgets(Budgets::off())
        .try_build()
        .unwrap();
    let hop = b.door(ip("10.0.0.1")).unwrap();
    assert_eq!(
        hop.strike(StrikeKind::Malformed),
        StrikeOutcome::Ignored(IgnoredBecause::TrustedProxy)
    );
    let pending = hop.request(RequestId(1)).unwrap();
    assert_eq!(
        pending.strike(StrikeKind::Malformed),
        StrikeOutcome::Ignored(IgnoredBecause::PendingClient)
    );
    let mut client = hop.request(RequestId(2)).unwrap();
    assert!(
        client
            .bind_client(ip("203.0.113.40"), Provenance::ForwardedHeader)
            .is_pass()
    );
    let mut last = client.strike(StrikeKind::Malformed);
    for _ in 1..5 {
        last = client.strike(StrikeKind::Malformed);
    }
    assert!(matches!(last, StrikeOutcome::Banned(_)));
    assert!(
        b.door(ip("203.0.113.40")).is_err(),
        "the real client is banned"
    );
    assert!(b.door(ip("10.0.0.1")).is_ok(), "the proxy never is");
}

#[test]
fn test_strike_on_allowlisted_ignored_and_decoy_definitive() {
    let b = Bouncer::builder()
        .allow(AllowList::new().immune(c("10.9.0.0/16"), "infra"))
        .budgets(Budgets::off())
        .try_build()
        .unwrap();
    let infra = b.door(ip("10.9.1.1")).unwrap();
    assert_eq!(
        infra.strike(StrikeKind::Malformed),
        StrikeOutcome::Ignored(IgnoredBecause::AllowListed)
    );
    let mut attacker = b.door(ip("198.51.100.99")).unwrap();
    assert!(
        matches!(
            attacker.strike(StrikeKind::DecoyTouched),
            StrikeOutcome::Banned(_)
        ),
        "definitive in observe mode too"
    );
    assert!(attacker.checkpoint().is_deny());
    assert!(b.door(ip("198.51.100.99")).is_err());
}

// ---- Directives ---------------------------------------------------------------------

#[test]
fn test_apply_low_confidence_ban_becomes_throttle() {
    let b = Bouncer::builder()
        .budgets(Budgets::off().door_rate(Rate::per_second(8).burst(8), Rate::per_second(1000)))
        .try_build()
        .unwrap();
    let a = b
        .apply(
            Directive::ban(ip("198.51.100.5"))
                .by(Actor::Policy(1))
                .confidence(10),
        )
        .unwrap();
    assert!(a.downgraded && a.throttled && a.ban.is_none());
    let admitted = (0..8)
        .filter(|_| b.door(ip("198.51.100.5")).is_ok())
        .count();
    assert!(admitted < 8, "throttled, not banned: {admitted}");
    assert!(admitted > 0);
}

#[test]
fn test_apply_revoke_and_ban_connection_bans_its_keys() {
    let b = plain();
    let conn = b.door(ip("198.51.100.6")).unwrap();
    let mut req = conn.request(RequestId(1)).unwrap();
    assert!(req.bind_account(AccountKey(77)).is_pass());
    let applied = b
        .apply(
            Directive::revoke_and_ban(RequestId(1))
                .by(Actor::Admin(2))
                .ban_keys(BanKeys::SOURCE | BanKeys::ACCOUNT),
        )
        .unwrap();
    assert_eq!(applied.bans, 2);
    assert!(req.checkpoint().is_deny());
    assert!(
        b.door(ip("198.51.100.6")).is_err(),
        "remembered at the door"
    );
    let other = b.door(ip("192.0.2.9")).unwrap();
    let mut r2 = other.request(RequestId(2)).unwrap();
    assert!(
        r2.bind_account(AccountKey(77)).is_deny(),
        "the account is banned everywhere"
    );
}

#[test]
fn test_apply_lift_and_invalid_targets() {
    let b = plain();
    b.ban(ip("198.51.100.7")).unwrap();
    let a = b.apply(Directive::lift(ip("198.51.100.7"))).unwrap();
    assert_eq!(a.lifted.unwrap().removed, 1);
    assert_eq!(
        b.apply(Directive::lift(ConnId(1))).err(),
        Some(BouncerError::InvalidTarget)
    );
    // Identity throttles work from 0.5; connections and requests are never
    // throttle targets.
    assert!(
        b.apply(Directive::throttle(
            SessionKey::from_digest([1; 16]),
            4,
            Duration::from_secs(10)
        ))
        .unwrap()
        .throttled
    );
    assert_eq!(
        b.apply(Directive::throttle(
            RequestId(1),
            4,
            Duration::from_secs(10)
        ))
        .err(),
        Some(BouncerError::InvalidTarget)
    );
}

// ---- Budgets at the door ----------------------------------------------------------------

#[test]
fn test_door_budgets_rate_and_concurrency() {
    let b = Bouncer::builder()
        .budgets(
            Budgets::off()
                .door_concurrency(2, 100)
                .door_rate(Rate::per_second(100), Rate::per_second(1000)),
        )
        .try_build()
        .unwrap();
    let a = b.door(ip("192.0.2.1")).unwrap();
    let a2 = b.door(ip("192.0.2.1")).unwrap();
    assert!(matches!(
        b.door(ip("192.0.2.1")),
        Err(Refusal::OverBudget { .. })
    ));
    drop(a);
    let a3 = b.door(ip("192.0.2.1")).unwrap();
    drop((a2, a3));
    let rate = Bouncer::builder()
        .budgets(Budgets::off().door_rate(Rate::per_second(1).burst(3), Rate::per_second(1000)))
        .try_build()
        .unwrap();
    let ok = (0..10)
        .filter(|_| rate.door(ip("192.0.2.2")).is_ok())
        .count();
    assert_eq!(ok, 3);
}

#[test]
fn test_budget_exempt_and_proxy_hops_not_charged() {
    let b = Bouncer::builder()
        .allow(AllowList::new().exempt_budgets(c("192.0.2.200/32"), "health checks"))
        .trusted_proxies(&[c("10.0.0.1/32")])
        .budgets(Budgets::off().door_concurrency(1, 100))
        .try_build()
        .unwrap();
    let held: Vec<_> = (0..5).map(|_| b.door(ip("192.0.2.200")).unwrap()).collect();
    let hops: Vec<_> = (0..5).map(|_| b.door(ip("10.0.0.1")).unwrap()).collect();
    // The PROXY client is charged: its second connection is over budget.
    let mut h1 = b.door(ip("10.0.0.1")).unwrap();
    assert!(
        h1.bind_client(ip("203.0.113.1"), Provenance::ProxyProtocol)
            .is_pass()
    );
    let mut h2 = b.door(ip("10.0.0.1")).unwrap();
    assert_eq!(
        denied(h2.bind_client(ip("203.0.113.1"), Provenance::ProxyProtocol)),
        Some(DenialCode::TooManyRequests)
    );
    drop(h1);
    let mut h3 = b.door(ip("10.0.0.1")).unwrap();
    assert!(
        h3.bind_client(ip("203.0.113.1"), Provenance::ProxyProtocol)
            .is_pass(),
        "released with the connection"
    );
    drop((held, hops));
}

// ---- Events and the shared epoch ---------------------------------------------------------

#[test]
fn test_events_reported_for_actions() {
    let events = Arc::new(Events::default());
    let b = Bouncer::builder()
        .event_sink(events.clone())
        .budgets(Budgets::off())
        .try_build()
        .unwrap();
    b.ban(ip("198.51.100.8")).unwrap();
    let _ = b.door(ip("198.51.100.8"));
    let tag = b.door(ip("192.0.2.1")).unwrap().into_tag();
    let conn = ConnId(b.request(tag, RequestId(1)).unwrap().conn().0);
    b.revoke(conn, Reason::ADMIN).unwrap();
    assert!(b.egress(tag).is_deny());
    b.lift(ip("198.51.100.8")).unwrap();
    for (signal, name) in [
        (signals::BAN_ADDED, "ban.added"),
        (signals::DOOR_REFUSED_BAN, "door.refused.ban"),
        (signals::REVOKE_APPLIED, "revoke.applied"),
        (signals::EGRESS_BLOCKED, "egress.blocked"),
        (signals::BAN_LIFTED, "ban.lifted"),
    ] {
        assert!(events.count(signal.id) >= 1, "{name}");
    }
    b.release(tag);
}

#[test]
fn test_shared_epoch_word() {
    let epoch = Arc::new(RevocationEpoch::new());
    let b = Bouncer::builder()
        .epoch(epoch.clone())
        .budgets(Budgets::off())
        .try_build()
        .unwrap();
    let before = epoch.current();
    b.revoke(AccountKey(1), Reason::ADMIN).unwrap();
    assert_eq!(epoch.current(), before + 1);
}
