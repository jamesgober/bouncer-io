//! The 0.10 API: `?` on the door, bans and lifts by key with every option
//! through a directive, and plug-ins passed by value or as a shared handle.

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bouncer_io::{
    Actor, ActorKind, BanKey, Bouncer, BouncerError, Cidr, CloseKind, ConnectionId, Directive,
    Ejector, Event, EventSink, Filter, FingerprintKey, Page, Reason, Refusal, Target,
};

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn c(s: &str) -> Cidr {
    s.parse().unwrap()
}

fn accept(bouncer: &Bouncer, peer: IpAddr) -> Result<ConnectionId, BouncerError> {
    Ok(bouncer.door(peer)?.connection())
}

#[test]
fn test_door_refusal_with_question_mark_is_bouncer_error_refused() {
    let b = Bouncer::new();
    assert!(accept(&b, ip("192.0.2.1")).is_ok());
    b.ban(ip("192.0.2.1")).unwrap();
    let err = accept(&b, ip("192.0.2.1")).unwrap_err();
    assert!(
        matches!(err, BouncerError::Refused(Refusal::Banned { .. })),
        "{err:?}"
    );
    // The message is the refusal's own.
    let refusal = b.door(ip("192.0.2.1")).unwrap_err();
    assert_eq!(err.to_string(), refusal.to_string());
}

#[test]
fn test_ban_by_key_is_by_the_application_with_the_policy_duration() {
    let b = Bouncer::new();
    let id = b.ban(ip("198.51.100.7")).unwrap();
    let listed = b.list(&Filter::all(), Page::first(10));
    assert_eq!(listed.items.len(), 1);
    let record = &listed.items[0];
    assert_eq!(record.id, id);
    assert_eq!(record.actor, ActorKind::App);
    assert!(record.until.is_some(), "timed by the duration policy");
}

#[test]
fn test_directive_ban_sets_what_ban_by_key_cannot() {
    let b = Bouncer::new();
    let applied = b
        .apply(
            Directive::ban(c("203.0.113.0/24"))
                .by(Actor::Admin(3))
                .because(Reason::POLICY)
                .permanent(),
        )
        .unwrap();
    let id = applied.ban.expect("a ban id");
    let record = b
        .list(&Filter::all(), Page::first(10))
        .items
        .into_iter()
        .find(|r| r.id == id)
        .unwrap();
    assert_eq!(record.actor, ActorKind::Admin);
    assert_eq!(record.reason, Reason::POLICY);
    assert_eq!(record.until, None, "permanent");
    assert!(b.door(ip("203.0.113.9")).is_err());
}

#[test]
fn test_directive_ban_of_a_host_length_prefix_is_the_address_ban() {
    // `Directive::ban(Cidr /32)` and `ban(address)` store the same key, so a
    // lift of either removes it.
    let b = Bouncer::new();
    b.apply(Directive::ban(c("192.0.2.44/32")).by(Actor::Admin(1)))
        .unwrap();
    assert!(b.door(ip("192.0.2.44")).is_err());
    assert_eq!(b.lift(ip("192.0.2.44")).unwrap().removed, 1);
    assert!(b.door(ip("192.0.2.44")).is_ok());
}

#[test]
fn test_directive_lift_carries_actor_and_reason() {
    let b = Bouncer::new();
    b.ban(ip("198.51.100.8")).unwrap();
    let applied = b
        .apply(
            Directive::lift(ip("198.51.100.8"))
                .by(Actor::Admin(9))
                .because(Reason::ADMIN),
        )
        .unwrap();
    assert_eq!(applied.lifted.map(|l| l.removed), Some(1));
    assert!(b.door(ip("198.51.100.8")).is_ok());
}

#[test]
fn test_directive_bans_and_lifts_a_fingerprint_within_a_prefix() {
    let b = Bouncer::new();
    let fp = FingerprintKey::from_digest([7; 16]);
    let within = c("192.0.2.0/24");
    let key = BanKey::FingerprintIn(fp, within);
    let applied = b
        .apply(Directive::ban(key).by(Actor::Local).because(Reason::POLICY))
        .unwrap();
    assert!(applied.ban.is_some());
    let shown = b.explain(key);
    assert_eq!(shown.bans.len(), 1);
    assert_eq!(shown.bans[0].actor, ActorKind::Local);

    // A client with that fingerprint inside the prefix is refused at the
    // bind; outside it, it is not.
    let inside = b.door(ip("192.0.2.9")).unwrap();
    let mut req = inside.request(bouncer_io::RequestId(1)).unwrap();
    assert!(req.bind_fingerprint(fp).is_deny());
    let outside = b.door(ip("198.51.100.9")).unwrap();
    let mut req = outside.request(bouncer_io::RequestId(2)).unwrap();
    assert!(req.bind_fingerprint(fp).is_pass());

    let applied = b.apply(Directive::lift(key).by(Actor::Admin(1))).unwrap();
    assert_eq!(applied.lifted.map(|l| l.removed), Some(1));
    assert!(b.explain(key).bans.is_empty());
}

#[test]
fn test_fingerprint_within_a_prefix_is_not_a_revocation_or_throttle_target() {
    let b = Bouncer::new();
    let key = Target::FingerprintIn(FingerprintKey::from_digest([8; 16]), c("192.0.2.0/24"));
    assert_eq!(
        b.revoke(key, Reason::ADMIN).unwrap_err(),
        BouncerError::InvalidTarget
    );
    assert_eq!(
        b.apply(Directive::revoke(key)).unwrap_err(),
        BouncerError::InvalidTarget
    );
    assert_eq!(
        b.apply(Directive::throttle(key, 4, Duration::from_secs(60)))
            .unwrap_err(),
        BouncerError::InvalidTarget
    );
}

#[derive(Default)]
struct Count(AtomicUsize);

impl EventSink for Count {
    fn event(&self, _event: &Event<'_>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

#[derive(Default)]
struct Kills(AtomicUsize);

impl Ejector for Kills {
    fn eject(&self, _conn: ConnectionId, _kind: CloseKind) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

#[test]
fn test_builder_takes_plug_ins_by_value() {
    let b = Bouncer::builder()
        .event_sink(Count::default())
        .ejector(Kills::default())
        .build()
        .unwrap();
    b.ban(ip("192.0.2.70")).unwrap();
    assert!(b.door(ip("192.0.2.70")).is_err());
}

#[test]
fn test_builder_keeps_a_shared_handle_working() {
    // gateway-io keeps an `Arc` of its ejector to attach the transport later,
    // and reads its sink's counters: the builder takes a clone of each.
    let sink = Arc::new(Count::default());
    let kills = Arc::new(Kills::default());
    let b = Bouncer::builder()
        .event_sink(sink.clone())
        .ejector(kills.clone())
        .maintainer(false)
        .build()
        .unwrap();
    let conn = b.door(ip("192.0.2.80")).unwrap();
    b.apply(Directive::revoke(conn.connection()).eject_now())
        .unwrap();
    assert!(
        sink.0.load(Ordering::Relaxed) > 0,
        "events reach the kept sink"
    );
    assert_eq!(
        kills.0.load(Ordering::Relaxed),
        1,
        "the kept ejector closed it"
    );
}
