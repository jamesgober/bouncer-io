//! bouncer behind a real HTTP server: serve-net over net-io, with bouncer as
//! the gate at the door and on every write, and as a checkpoint before each
//! reply. The 0.8 exit tests from a client's side.

#![cfg(feature = "net-io")]

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::{Mutex, mpsc};
use std::time::{Duration, Instant};

use bouncer_io::{Bouncer, Reason, RequestId, SessionKey, Ticket, TicketTag};
use serve_net::{
    Checkpoint, CheckpointAt, Envelope, HeadAction, HttpHead, HttpReply, HttpRequest, HttpService,
    ListenerSpec, Outcome, Running, Server, Verdict,
};

const WAIT: Duration = Duration::from_secs(5);

/// Judges the request's ticket before its reply leaves.
struct Guard(Bouncer);

impl Checkpoint for Guard {
    fn check(&self, env: &Envelope, at: CheckpointAt) -> Verdict {
        if at == CheckpointAt::BeforeReply && env.user_word() != 0 {
            if let bouncer_io::Verdict::Deny(d) =
                self.0.egress(TicketTag::from_raw(env.user_word()))
            {
                return Verdict::Deny {
                    status: d.code.http_status(),
                };
            }
        }
        Verdict::Pass
    }
}

/// A logged-in page: the `session` header names the session. When `hold` is
/// set, the handler reports in and waits, so a test can revoke mid-request.
struct App {
    bouncer: Bouncer,
    requests: Mutex<HashMap<u64, Ticket>>,
    hold: Option<(mpsc::Sender<()>, Mutex<mpsc::Receiver<()>>)>,
}

fn session(n: u8) -> SessionKey {
    SessionKey::from_digest([n; 16])
}

impl HttpService for App {
    fn head(&self, head: &HttpHead<'_>, env: &mut Envelope) -> HeadAction {
        let Some(n) = head.header_str("session").and_then(|s| s.parse().ok()) else {
            return HeadAction::Proceed;
        };
        // serve-net carries the tag bouncer gave the connection at the door.
        let tag = TicketTag::from(env.gate_tag());
        let id = RequestId(u128::from(env.seq().get()));
        let Ok(mut request) = self.bouncer.request(tag, id) else {
            return HeadAction::refuse(503);
        };
        if request.bind_session(session(n)).is_deny() {
            return HeadAction::refuse(403);
        }
        env.set_user_word(request.tag().get());
        self.requests
            .lock()
            .unwrap()
            .insert(env.user_word(), request);
        HeadAction::Proceed
    }

    fn call(&self, _request: &HttpRequest<'_>, _env: &Envelope, reply: &mut HttpReply) -> Outcome {
        if let Some((entered, go)) = &self.hold {
            let _ = entered.send(());
            let _ = go.lock().unwrap().recv_timeout(WAIT);
        }
        reply.text(200, "account balance: 1234");
        Outcome::Done
    }

    fn done(&self, env: &Envelope, _finished: &serve_net::Finished) {
        self.requests.lock().unwrap().remove(&env.user_word());
    }
}

type Hold = (mpsc::Receiver<()>, mpsc::Sender<()>);

fn serve(bouncer: &Bouncer, hold: bool) -> (Running, SocketAddr, Option<Hold>) {
    let (held, hold) = if hold {
        let (entered_tx, entered_rx) = mpsc::channel();
        let (go_tx, go_rx) = mpsc::channel();
        (
            Some((entered_tx, Mutex::new(go_rx))),
            Some((entered_rx, go_tx)),
        )
    } else {
        (None, None)
    };
    let running = Server::builder()
        .listener(ListenerSpec::tcp("web", "127.0.0.1:0"))
        .gate(bouncer.clone())
        .checkpoint(Guard(bouncer.clone()))
        .serve(App {
            bouncer: bouncer.clone(),
            requests: Mutex::default(),
            hold: held,
        })
        .expect("serve");
    let addr = running.local_addr().expect("address");
    (running, addr, hold)
}

fn client(addr: SocketAddr) -> TcpStream {
    let c = TcpStream::connect(addr).expect("connect");
    c.set_read_timeout(Some(WAIT)).expect("timeout");
    c
}

fn get(session: u8) -> Vec<u8> {
    format!(
        "GET /account HTTP/1.1\r\nHost: localhost\r\nsession: {session}\r\nConnection: close\r\n\r\n"
    )
    .into_bytes()
}

fn eventually(mut f: impl FnMut() -> bool) -> bool {
    let until = Instant::now() + WAIT;
    while Instant::now() < until {
        if f() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    f()
}

fn response(c: &mut TcpStream) -> String {
    let mut got = Vec::new();
    let _ = c.read_to_end(&mut got);
    String::from_utf8_lossy(&got).into_owned()
}

/// What a refused browser reads. The reset can reach it before `connect`
/// returns, and then the connect is what reports it.
fn refused(addr: SocketAddr, sent: &[u8]) -> String {
    let mut c = match TcpStream::connect(addr) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => return String::new(),
        Err(e) => panic!("connect: {e}"),
    };
    c.set_read_timeout(Some(WAIT)).expect("timeout");
    let _ = c.write_all(sent);
    response(&mut c)
}

#[test]
fn test_serve_net_banned_browser_is_refused_at_the_door() {
    let bouncer = Bouncer::new();
    let (running, addr, _) = serve(&bouncer, false);

    let mut c = client(addr);
    c.write_all(&get(1)).expect("write");
    let page = response(&mut c);
    assert!(page.starts_with("HTTP/1.1 200"), "{page}");
    assert!(page.contains("account balance"));

    bouncer
        .ban("127.0.0.1".parse::<IpAddr>().unwrap())
        .expect("ban");
    let page = refused(addr, &get(1));
    assert!(page.is_empty(), "a banned browser reads nothing: {page}");
    drop(running);
}

#[test]
fn test_serve_net_session_revoked_mid_request_gets_the_generic_denial() {
    let bouncer = Bouncer::new();
    let (running, addr, hold) = serve(&bouncer, true);
    let (entered, go) = hold.unwrap();
    let mut c = client(addr);
    c.write_all(&get(2)).expect("write");
    entered.recv_timeout(WAIT).expect("the handler is running");

    bouncer.revoke(session(2), Reason::ADMIN).expect("revoke");
    go.send(()).expect("go");
    let page = response(&mut c);
    assert!(page.starts_with("HTTP/1.1 403"), "{page}");
    assert!(!page.contains("balance"), "nothing of the page: {page}");
    // The connection is gone: the read above ended, and so did its ticket.
    assert!(eventually(|| bouncer.health().tickets_live == 0));
    drop(running);
}

#[test]
fn test_serve_net_denial_code_reaches_the_browser_as_its_status() {
    // A revocation that says "too many requests" answers 429, not 403.
    let bouncer = Bouncer::new();
    let (running, addr, hold) = serve(&bouncer, true);
    let (entered, go) = hold.unwrap();
    let mut c = client(addr);
    c.write_all(&get(5)).expect("write");
    entered.recv_timeout(WAIT).expect("the handler is running");

    bouncer
        .apply(
            bouncer_io::Directive::revoke(session(5))
                .deny_with(bouncer_io::DenialCode::TooManyRequests),
        )
        .expect("revoke");
    go.send(()).expect("go");
    let page = response(&mut c);
    assert!(page.starts_with("HTTP/1.1 429"), "{page}");
    assert!(!page.contains("balance"), "nothing of the page: {page}");
    drop(running);
}

#[test]
fn test_serve_net_revoked_session_is_refused_on_its_next_request() {
    let bouncer = Bouncer::new();
    let (running, addr, _) = serve(&bouncer, false);
    bouncer
        .ban(bouncer_io::BanKey::Session(session(3)))
        .expect("ban");
    let mut c = client(addr);
    c.write_all(&get(3)).expect("write");
    let page = response(&mut c);
    assert!(page.starts_with("HTTP/1.1 403"), "{page}");
    assert!(!page.contains("balance"));
    drop(running);
}

#[test]
fn test_serve_net_keep_alive_requests_each_reach_the_connection_ticket() {
    // serve-net hands the gate's tag to every request of a connection, so a
    // later request on a kept-alive connection is judged like the first, and
    // a revocation between them reaches the next.
    let bouncer = Bouncer::new();
    let (running, addr, _) = serve(&bouncer, false);
    let mut c = client(addr);
    let keep = |n: u8| {
        format!("GET /account HTTP/1.1\r\nHost: localhost\r\nsession: {n}\r\n\r\n").into_bytes()
    };
    let read_one = |c: &mut TcpStream| {
        let mut got = Vec::new();
        let mut buf = [0u8; 1024];
        while !String::from_utf8_lossy(&got).contains("\r\n\r\n") {
            let n = c.read(&mut buf).expect("read");
            assert!(n > 0, "closed early: {}", String::from_utf8_lossy(&got));
            got.extend_from_slice(&buf[..n]);
        }
        String::from_utf8_lossy(&got).into_owned()
    };
    for _ in 0..3 {
        c.write_all(&keep(6)).expect("write");
        let page = read_one(&mut c);
        assert!(page.starts_with("HTTP/1.1 200"), "{page}");
    }
    assert!(
        eventually(|| bouncer.health().tickets_live == 1),
        "one connection, no requests left"
    );
    // The revocation takes the session's latest request, and with it the
    // idle connection: the next request is refused (403 or 503) or finds the
    // connection closed, never served.
    bouncer.revoke(session(6), Reason::ADMIN).expect("revoke");
    let _ = c.write_all(&keep(6));
    let page = response(&mut c);
    assert!(!page.starts_with("HTTP/1.1 200"), "{page}");
    assert!(!page.contains("balance"), "nothing of the page: {page}");
    drop(running);
}

#[test]
fn test_serve_net_releases_tickets_after_a_clean_request() {
    let bouncer = Bouncer::new();
    let (running, addr, _) = serve(&bouncer, false);
    for _ in 0..20 {
        let mut c = client(addr);
        c.write_all(&get(4)).expect("write");
        assert!(response(&mut c).starts_with("HTTP/1.1 200"));
    }
    assert!(eventually(|| bouncer.health().tickets_live == 0));
    drop(running);
}

/// A login page: a wrong password is a strike against the client the PROXY
/// header named, and a 401.
struct Login {
    bouncer: Bouncer,
}

impl HttpService for Login {
    fn head(&self, head: &HttpHead<'_>, env: &mut Envelope) -> HeadAction {
        let tag = TicketTag::from(env.gate_tag());
        let id = RequestId(u128::from(env.seq().get()));
        let Ok(request) = self.bouncer.request(tag, id) else {
            return HeadAction::refuse(503);
        };
        if head.header_str("password") != Some("right") {
            let _ = request.strike(bouncer_io::StrikeKind::LoginFailed);
            return HeadAction::refuse(401);
        }
        HeadAction::Proceed
    }

    fn call(&self, _request: &HttpRequest<'_>, _env: &Envelope, reply: &mut HttpReply) -> Outcome {
        reply.text(200, "welcome");
        Outcome::Done
    }
}

#[test]
fn test_serve_net_credential_stuffing_behind_a_proxy_bans_the_48() {
    // The replay's credential stuffing trace through a real server: every
    // attempt a new TCP connection from the proxy, its PROXY header naming
    // a new /64 of one /48; a client of another /48 behind the same proxy
    // logs in throughout.
    let bouncer = Bouncer::builder()
        .trusted_proxies(&["127.0.0.1/32".parse().unwrap()])
        .budgets(bouncer_io::Budgets::off())
        .enforcement(
            bouncer_io::Enforcement::observe_all().enforce(bouncer_io::StrikeKind::LoginFailed),
        )
        .build()
        .expect("bouncer");
    let trusted = serve_net::net_io::TrustedProxies::parse("127.0.0.1").expect("proxies");
    let running = Server::builder()
        .listener(
            ListenerSpec::tcp("edge", "127.0.0.1:0").ingress(serve_net::Ingress::Proxy(
                serve_net::ProxySource::proxy_protocol(
                    serve_net::net_io::ProxyVersions::V1,
                    trusted,
                ),
            )),
        )
        .gate(bouncer.clone())
        .serve(Login {
            bouncer: bouncer.clone(),
        })
        .expect("serve");
    let addr = running.local_addr().expect("address");
    let attempt = |client: &str, password: &str| {
        let sent = format!(
            "PROXY TCP6 {client} ::1 40000 80\r\nGET /login HTTP/1.1\r\nHost: localhost\r\npassword: {password}\r\nConnection: close\r\n\r\n"
        );
        refused(addr, sent.as_bytes())
    };
    assert!(attempt("2001:db8:78::1", "right").starts_with("HTTP/1.1 200"));
    let mut through = 0;
    for i in 0..200u16 {
        // A new /64 every time, over sixteen /56s.
        let client = format!("2001:db8:77:{:x}::1", ((i % 16) << 8) | (i / 16));
        if attempt(&client, "wrong").starts_with("HTTP/1.1 401") {
            through += 1;
        }
        if i % 20 == 0 {
            assert!(
                attempt("2001:db8:78::1", "right").starts_with("HTTP/1.1 200"),
                "the innocent behind the same proxy is served"
            );
        }
    }
    eprintln!("stuffing through serve-net: {through} of 200 attempts reached the login page");
    assert!(through <= 80, "{through} attempts reached the login page");
    assert!(
        attempt("2001:db8:77:ffff::9", "right").is_empty(),
        "the /48 is refused after its PROXY header"
    );
    assert!(
        bouncer
            .door("2001:db8:77:ffff::9".parse().unwrap())
            .is_err()
    );
    assert!(attempt("2001:db8:78::2", "right").starts_with("HTTP/1.1 200"));
    drop(running);
}
