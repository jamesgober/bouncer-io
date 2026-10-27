//! Threat T-18: digests never reach logs or events. Every printable value a
//! deployment can log while a session and a fingerprint are banned, bound,
//! revoked, and explained is checked for the digest bytes (dev/PLAN.md
//! section 8).

use std::{
    net::IpAddr,
    sync::{Arc, Mutex},
};

use bouncer_io::{
    Actor, BanKey, BanSpec, Bouncer, Budgets, Cidr, Event, EventSink, Filter, FingerprintKey, Page,
    Reason, RequestId, SessionKey,
};

const SESSION: [u8; 16] = [
    0xc3, 0x5e, 0x91, 0x2f, 0x7a, 0x04, 0xd8, 0x66, 0x1b, 0xe2, 0x49, 0xb0, 0x3c, 0x85, 0xf7, 0x12,
];
const FINGERPRINT: [u8; 16] = [
    0x9d, 0x27, 0xe4, 0x58, 0x0f, 0xa1, 0x6c, 0xb3, 0x45, 0xde, 0x80, 0x17, 0xfa, 0x39, 0x62, 0xcb,
];

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[derive(Default)]
struct Printed(Mutex<Vec<String>>);
impl EventSink for Printed {
    fn event(&self, e: &Event<'_>) {
        self.0.lock().unwrap().push(format!("{e:?}"));
    }
}

/// Any three bytes in a row of either digest, in hex (both cases, with and
/// without separators) or as the decimal list `Debug` prints for an array.
fn leaks(text: &str) -> Option<String> {
    let lower = text.to_lowercase();
    for digest in [SESSION, FINGERPRINT] {
        for w in digest.windows(3) {
            let hex = format!("{:02x}{:02x}{:02x}", w[0], w[1], w[2]);
            let spaced = format!("{:02x} {:02x} {:02x}", w[0], w[1], w[2]);
            let listed = format!("{:#04x}, {:#04x}, {:#04x}", w[0], w[1], w[2]);
            let decimal = format!("{}, {}, {}", w[0], w[1], w[2]);
            for needle in [hex, spaced, listed, decimal] {
                if lower.contains(&needle) {
                    return Some(needle);
                }
            }
        }
    }
    None
}

fn assert_clean(what: &str, text: &str) {
    if let Some(needle) = leaks(text) {
        panic!("{what} prints digest bytes ({needle}): {text}");
    }
}

#[test]
fn test_debug_never_prints_key_bytes() {
    let sink = Arc::new(Printed::default());
    let b = Bouncer::builder()
        .budgets(Budgets::off())
        .event_sink(sink.clone())
        .seed([3; 32])
        .try_build()
        .unwrap();
    let session = SessionKey::from_digest(SESSION);
    let fp = FingerprintKey::from_digest(FINGERPRINT);
    let prefix: Cidr = "203.0.113.0/24".parse().unwrap();

    let mut shown = vec![
        format!("{session:?} {session}"),
        format!("{fp:?} {fp}"),
        format!(
            "{:?} {}",
            BanKey::Session(session),
            BanKey::Session(session)
        ),
        format!(
            "{:?} {}",
            BanKey::FingerprintIn(fp, prefix),
            BanKey::FingerprintIn(fp, prefix)
        ),
        format!("{:?}", BanSpec::key(session)),
    ];

    // A refused automated fingerprint ban: the error.
    let refused = b.ban(BanSpec::key(fp).by(Actor::Local)).unwrap_err();
    shown.push(format!("{refused} {refused:?}"));

    b.ban(BanSpec::key(session)).unwrap();
    b.ban(BanSpec::key(BanKey::FingerprintIn(fp, prefix)).by(Actor::Local))
        .unwrap();

    // Binds that are refused, a revocation in flight, and the tickets.
    let conn = b.door(ip("203.0.113.9")).unwrap();
    let mut req = conn.request(RequestId(1)).unwrap();
    let v = req.bind_session(session);
    shown.push(format!("{v:?} {req:?} {conn:?}"));
    let mut fp_conn = b.door(ip("203.0.113.10")).unwrap();
    let v = fp_conn.bind_fingerprint(fp);
    shown.push(format!("{v:?} {fp_conn:?}"));
    let mut other = b.door(ip("198.51.100.9")).unwrap();
    assert!(other.bind_fingerprint(fp).is_pass());
    let _ = b.revoke(fp, Reason::ADMIN);
    shown.push(format!("{:?} {other:?}", other.checkpoint()));

    // What an operator reads back.
    shown.push(format!("{:?}", b.explain(session)));
    shown.push(format!(
        "{:?}",
        b.explain(BanKey::FingerprintIn(fp, prefix))
    ));
    shown.push(format!("{:?}", b.list(&Filter::all(), Page::first(100))));
    shown.push(format!("{b:?} {:?}", b.health()));
    let _ = b.maintain(b.now());

    let events = sink.0.lock().unwrap().clone();
    assert!(
        events.len() >= 3,
        "the bans and the revocation are reported: {events:?}"
    );
    for (i, e) in events.iter().enumerate() {
        assert_clean(&format!("event {i}"), e);
    }
    for (i, s) in shown.iter().enumerate() {
        assert_clean(&format!("value {i}"), s);
    }
}
