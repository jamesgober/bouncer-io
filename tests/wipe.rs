//! Wipe, replace, eject: edge cases 30 and 42 to 47 and threats T-8
//! (byte-identical denials), T-21, T-22, T-23. An inspecting global
//! allocator checks that every block a `Collected` frees is all zero,
//! including the old blocks left behind by growth.
//!
//! Integration tests are separate crates, so `unsafe` is allowed here for the
//! allocator shim (dev/DIRECTIVES.md: test crates may inspect the allocator).

use std::{
    alloc::{GlobalAlloc, Layout, System},
    io::Write,
    net::IpAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use bouncer_io::{
    Bouncer, Budgets, CloseKind, Collected, ConnId, Denial, DenialCode, DenialFormat, Directive,
    Ejector, Enforcement, Event, EventSink, EvidenceValue, FormatError, Reason, RequestId,
    StrikeKind, signals,
};

/// Block sizes that only the tests' `Collected` buffers use: a small buffer
/// doubling to 9896 bytes, and one growing from 16 KiB to 1 MiB.
const WATCHED: [usize; 11] = [
    1237, 2474, 4948, 9896, 16_411, 32_822, 65_644, 131_288, 262_576, 525_152, 1_050_304,
];

struct Inspecting;

static FREED_WATCHED: AtomicUsize = AtomicUsize::new(0);
static FREED_DIRTY: AtomicUsize = AtomicUsize::new(0);

// SAFETY: forwards to the system allocator; before freeing a watched block it
// reads the block, which the caller still owns until `dealloc` returns.
unsafe impl GlobalAlloc for Inspecting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: same contract as the caller's.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: same contract as the caller's.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if WATCHED.contains(&layout.size()) {
            // SAFETY: `ptr` is valid for `layout.size()` bytes until freed.
            let bytes = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
            FREED_WATCHED.fetch_add(1, Ordering::SeqCst);
            if bytes.iter().any(|&b| b != 0) {
                FREED_DIRTY.fetch_add(1, Ordering::SeqCst);
            }
        }
        // SAFETY: same contract as the caller's.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: Inspecting = Inspecting;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

/// An HTTP-style formatter that depends only on the code and the message.
struct Http;
impl DenialFormat for Http {
    fn format(&self, d: &Denial, out: &mut Collected) -> Result<(), FormatError> {
        let status = match d.code {
            DenialCode::Forbidden => "403 Forbidden",
            DenialCode::NotFound => "404 Not Found",
            DenialCode::TooManyRequests => "429 Too Many Requests",
            DenialCode::Unauthorized => "401 Unauthorized",
            _ => "503 Service Unavailable",
        };
        write!(
            out,
            "HTTP/1.1 {status}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            d.message.len(),
            d.message
        )
        .map_err(|_| FormatError::TooLarge)
    }
}

struct Huge;
impl DenialFormat for Huge {
    fn format(&self, _d: &Denial, out: &mut Collected) -> Result<(), FormatError> {
        out.extend_from_slice(&[b'x'; 4000])
            .map_err(|_| FormatError::TooLarge)
    }
}

struct Refusing;
impl DenialFormat for Refusing {
    fn format(&self, _d: &Denial, _out: &mut Collected) -> Result<(), FormatError> {
        Err(FormatError::Unsupported)
    }
}

/// A formatter that panics.
struct Panicking;
impl DenialFormat for Panicking {
    fn format(&self, _d: &Denial, _out: &mut Collected) -> Result<(), FormatError> {
        panic!("formatter bug");
    }
}

/// A formatter during which another revocation of the same request lands.
struct RevokedMeanwhile<'a> {
    bouncer: &'a Bouncer,
    calls: AtomicUsize,
}
impl DenialFormat for RevokedMeanwhile<'_> {
    fn format(&self, d: &Denial, out: &mut Collected) -> Result<(), FormatError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.bouncer
            .apply(Directive::revoke(RequestId(30)).deny_with(DenialCode::Forbidden))
            .unwrap();
        write!(out, "{:?}", d.code).map_err(|_| FormatError::TooLarge)
    }
}

/// Wipe-and-eject events: whether each noted an ejection.
#[derive(Default)]
struct Noted(Mutex<Vec<(u32, Option<bool>)>>);
impl EventSink for Noted {
    fn event(&self, e: &Event<'_>) {
        let ejected = e.evidence.pairs().iter().find_map(|(k, v)| match (k, v) {
            (&"ejected", EvidenceValue::Flag(f)) => Some(*f),
            _ => None,
        });
        self.0.lock().unwrap().push((e.signal.id, ejected));
    }
}

#[derive(Default)]
struct Kills(Mutex<Vec<(ConnId, CloseKind)>>);
impl Ejector for Kills {
    fn eject(&self, conn: ConnId, kind: CloseKind) {
        self.0.lock().unwrap().push((conn, kind));
    }
}

/// One test function, so no other test frees watched blocks meanwhile.
#[test]
fn test_wipe_replace_eject() {
    // ---- T-22, T-23, edge case 43: every freed block is all zero ----
    {
        let mut c = Collected::with_capacity(WATCHED[0], WATCHED[3]).unwrap();
        let secret = vec![0x5a_u8; 1200];
        c.extend_from_slice(&secret).unwrap();
        for _ in 0..6 {
            c.extend_from_slice(&secret).unwrap(); // grows 1237 -> 2474 -> 4948 -> 9896
        }
        assert_eq!(c.capacity(), WATCHED[3]);
        drop(c);
        let mut c = Collected::with_capacity(WATCHED[0], WATCHED[0]).unwrap();
        c.extend_from_slice(&secret).unwrap();
        c.wipe();
        drop(c);
        // Edge case 43: from 16 KiB to 1 MiB, six blocks left behind.
        let mut big = Collected::with_capacity(WATCHED[4], WATCHED[10]).unwrap();
        let chunk = vec![0xa7_u8; 16_000];
        while big.len() + chunk.len() <= WATCHED[10] {
            big.extend_from_slice(&chunk).unwrap();
        }
        assert_eq!(big.capacity(), WATCHED[10]);
        drop(big);
    }
    assert!(
        FREED_WATCHED.load(Ordering::SeqCst) >= 12,
        "growth and drops freed the watched blocks"
    );
    assert_eq!(
        FREED_DIRTY.load(Ordering::SeqCst),
        0,
        "a freed Collected block held response bytes"
    );

    // ---- deny_and_eject: wipe, format, eject ----
    let kills = Arc::new(Kills::default());
    let b = Bouncer::builder()
        .budgets(Budgets::off())
        .denial_format(Arc::new(Http))
        .ejector(kills.clone())
        .try_build()
        .unwrap();
    let conn = b.door(ip("192.0.2.1")).unwrap();
    let conn_id = conn.conn();
    let mut req = conn.request(RequestId(1)).unwrap();
    let mut reply = Collected::new();
    reply
        .extend_from_slice(b"account 4711 balance 1204.00")
        .unwrap();
    b.revoke(RequestId(1), Reason::ADMIN).unwrap();
    assert!(req.checkpoint().is_deny());
    let out = req.deny_and_eject(&mut reply);
    assert!(out.wiped && out.formatted && out.ejected);
    let revoked_bytes = reply.as_slice().to_vec();
    assert!(revoked_bytes.starts_with(b"HTTP/1.1 403 Forbidden"));
    assert!(
        !revoked_bytes.windows(4).any(|w| w == b"4711"),
        "nothing of the original response is left"
    );
    assert_eq!(kills.0.lock().unwrap().len(), 1);
    assert_eq!(kills.0.lock().unwrap()[0].0, conn_id);
    // Edge case 47: with a denial to flush, the transport gets a deadline
    // (it aborts without the denial once it passes); without one, an abort.
    assert_eq!(
        kills.0.lock().unwrap()[0].1,
        CloseKind::AfterFlush {
            deadline: Duration::from_millis(100)
        }
    );
    // A second call: event only, no second format or eject.
    let again = req.deny_and_eject(&mut reply);
    assert!(again.wiped && !again.formatted && !again.ejected);
    assert!(reply.is_empty());
    assert_eq!(kills.0.lock().unwrap().len(), 1);

    // ---- T-8, T-21: a revoked request's denial equals an ordinary one ----
    let conn2 = b.door(ip("192.0.2.2")).unwrap();
    let mut proactive = conn2.request(RequestId(2)).unwrap();
    let mut reply2 = Collected::new();
    let out2 = proactive.deny_and_eject(&mut reply2); // denied by the handler itself
    assert!(out2.formatted);
    assert_eq!(
        reply2.as_slice(),
        &revoked_bytes[..],
        "denials reveal nothing about the reason"
    );
    let banned = Bouncer::builder()
        .budgets(Budgets::off())
        .denial_format(Arc::new(Http))
        .enforcement(Enforcement::enforce_all())
        .try_build()
        .unwrap();
    let c3 = banned.door(ip("198.51.100.3")).unwrap();
    let mut r3 = c3.request(RequestId(3)).unwrap();
    for _ in 0..5 {
        let _ = r3.strike(StrikeKind::Malformed);
    }
    assert!(r3.checkpoint().is_deny());
    let mut reply3 = Collected::new();
    let out3 = r3.deny_and_eject(&mut reply3);
    assert!(out3.remembered, "the strike ban is in ban memory");
    assert_eq!(
        reply3.as_slice(),
        &revoked_bytes[..],
        "a strike denial looks the same too"
    );

    // ---- edge case 44: a formatter that fails or overflows ----
    for format in [Arc::new(Huge) as Arc<dyn DenialFormat>, Arc::new(Refusing)] {
        let b = Bouncer::builder()
            .budgets(Budgets::off())
            .denial_format(format)
            .ejector(kills.clone())
            .try_build()
            .unwrap();
        let conn = b.door(ip("192.0.2.9")).unwrap();
        let mut req = conn.request(RequestId(9)).unwrap();
        let mut reply = Collected::new();
        reply.extend_from_slice(b"secret").unwrap();
        let before = kills.0.lock().unwrap().len();
        let out = req.deny_and_eject(&mut reply);
        assert!(
            out.wiped && !out.formatted && out.ejected,
            "no denial bytes, the eject proceeds"
        );
        assert!(reply.is_empty());
        assert_eq!(kills.0.lock().unwrap().len(), before + 1);
        assert_eq!(kills.0.lock().unwrap()[before].1, CloseKind::Abort);
    }

    // ---- edge case 46, no ejector: the caller closes; the event notes it ----
    let noted = Arc::new(Noted::default());
    let b = Bouncer::builder()
        .budgets(Budgets::off())
        .event_sink(noted.clone())
        .try_build()
        .unwrap();
    let conn = b.door(ip("192.0.2.10")).unwrap();
    let mut req = conn.request(RequestId(10)).unwrap();
    let out = req.deny_and_eject(&mut Collected::new());
    assert!(!out.ejected && !out.formatted);
    assert!(req.checkpoint().is_deny());
    assert!(
        noted
            .0
            .lock()
            .unwrap()
            .contains(&(signals::DENIAL_WIPE_EJECT.id, Some(false))),
        "the event says the connection was not ejected"
    );

    // ---- edge case 45: a formatter that panics ----
    let b = Bouncer::builder()
        .budgets(Budgets::off())
        .ejector(kills.clone())
        .try_build()
        .unwrap();
    let conn = b.door(ip("192.0.2.45")).unwrap();
    let mut req = conn.request(RequestId(45)).unwrap();
    let mut reply = Collected::new();
    reply.extend_from_slice(b"account 4545").unwrap();
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        req.deny_and_eject_with(&mut reply, &Panicking)
    }));
    assert!(panicked.is_err());
    assert!(reply.is_empty(), "wiped before the formatter ran");
    assert!(
        req.checkpoint().is_deny(),
        "revoked before the formatter ran"
    );
    drop(req);
    let mut conn = conn;
    assert!(conn.checkpoint().is_deny(), "and its connection");

    // ---- edge case 30: a second revocation while deny_and_eject runs ----
    let noted = Arc::new(Noted::default());
    let b = Bouncer::builder()
        .budgets(Budgets::off())
        .event_sink(noted.clone())
        .ejector(kills.clone())
        .try_build()
        .unwrap();
    let conn = b.door(ip("192.0.2.30")).unwrap();
    let mut req = conn.request(RequestId(30)).unwrap();
    b.apply(Directive::revoke(RequestId(30)).deny_with(DenialCode::TooManyRequests))
        .unwrap();
    assert!(req.checkpoint().is_deny());
    let format = RevokedMeanwhile {
        bouncer: &b,
        calls: AtomicUsize::new(0),
    };
    let mut reply = Collected::new();
    let before = kills.0.lock().unwrap().len();
    let out = req.deny_and_eject_with(&mut reply, &format);
    assert!(out.formatted && out.ejected);
    assert_eq!(format.calls.load(Ordering::SeqCst), 1, "formatted once");
    assert_eq!(reply.as_slice(), b"TooManyRequests", "no second format");
    assert_eq!(kills.0.lock().unwrap().len(), before + 1, "ejected once");
    let revokes = noted
        .0
        .lock()
        .unwrap()
        .iter()
        .filter(|e| e.0 == signals::REVOKE_APPLIED.id)
        .count();
    assert_eq!(revokes, 2, "the second revocation is recorded");
    assert!(
        matches!(req.checkpoint(), bouncer_io::Verdict::Deny(d) if d.code == DenialCode::Forbidden),
        "the stronger code applies from then on"
    );

    // ---- keep_connection: the denial is formatted, the connection stays ----
    let b = Bouncer::builder()
        .budgets(Budgets::off())
        .denial_format(Arc::new(Http))
        .ejector(kills.clone())
        .try_build()
        .unwrap();
    let mut conn = b.door(ip("192.0.2.11")).unwrap();
    let mut req = conn.request(RequestId(11)).unwrap();
    b.apply(Directive::revoke(RequestId(11)).keep_connection())
        .unwrap();
    assert!(req.checkpoint().is_deny());
    let before = kills.0.lock().unwrap().len();
    let mut reply = Collected::new();
    let out = req.deny_and_eject(&mut reply);
    assert!(out.formatted && !out.ejected);
    assert_eq!(kills.0.lock().unwrap().len(), before);
    drop(req);
    assert!(conn.checkpoint().is_pass(), "the connection carries on");
}
