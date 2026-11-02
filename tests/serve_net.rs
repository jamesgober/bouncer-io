//! bouncer behind a real HTTP server: serve-net over net-io, with bouncer as
//! the gate at the door and on every write, and as a checkpoint before each
//! reply. The 0.8 exit tests from a client's side.

#![cfg(feature = "net-io")]

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use bouncer_io::{Bouncer, ConnectionGate, Reason, RequestId, SessionKey, Ticket, TicketTag};
use net_io::{AdmitStage, Admitted, CloseReason, ConnectionInfo, Denial, Gate, WriteCheck};
use serve_net::{
    Checkpoint, CheckpointAt, Envelope, HeadAction, HttpHead, HttpReply, HttpRequest, HttpService,
    ListenerSpec, Outcome, Running, Server, Verdict,
};

const WAIT: Duration = Duration::from_secs(5);

/// serve-net's envelope names a connection by id; bouncer's requests hang
/// off the connection's tag. This remembers one from the other.
#[derive(Clone)]
struct Door {
    bouncer: Bouncer,
    tags: Arc<Mutex<HashMap<u64, TicketTag>>>,
}

impl Gate for Door {
    type Ticket = ConnectionGate;

    fn admit(
        &self,
        info: &ConnectionInfo,
        stage: AdmitStage,
    ) -> Result<Admitted<ConnectionGate>, net_io::Refusal> {
        let admitted = self.bouncer.admit(info, stage)?;
        self.tags
            .lock()
            .unwrap()
            .insert(info.id.get(), admitted.ticket.tag());
        Ok(admitted)
    }

    fn readmit(
        &self,
        gate: &mut ConnectionGate,
        info: &ConnectionInfo,
    ) -> Result<(), net_io::Refusal> {
        self.bouncer.readmit(gate, info)
    }

    fn check(&self, gate: &mut ConnectionGate, write: &WriteCheck) -> Result<(), Denial> {
        self.bouncer.check(gate, write)
    }

    fn closed(&self, gate: ConnectionGate, info: &ConnectionInfo, reason: CloseReason) {
        self.tags.lock().unwrap().remove(&info.id.get());
        self.bouncer.closed(gate, info, reason);
    }
}

/// Judges the request's ticket before its reply leaves.
struct Guard(Bouncer);

impl Checkpoint for Guard {
    fn check(&self, env: &Envelope, at: CheckpointAt) -> Verdict {
        if at == CheckpointAt::BeforeReply
            && env.user_word() != 0
            && self
                .0
                .egress(TicketTag::from_raw(env.user_word()))
                .is_deny()
        {
            return Verdict::Deny { status: 403 };
        }
        Verdict::Pass
    }
}

/// A logged-in page: the `session` header names the session. When `hold` is
/// set, the handler reports in and waits, so a test can revoke mid-request.
struct App {
    door: Door,
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
        let bouncer = &self.door.bouncer;
        let tag = self
            .door
            .tags
            .lock()
            .unwrap()
            .get(&env.connection().get())
            .copied();
        let id = RequestId(u128::from(env.seq().get()));
        let Some(Ok(mut request)) = tag.map(|t| bouncer.request(t, id)) else {
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
    let door = Door {
        bouncer: bouncer.clone(),
        tags: Arc::default(),
    };
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
        .gate(door.clone())
        .checkpoint(Guard(bouncer.clone()))
        .serve(App {
            door,
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
    let mut c = client(addr);
    let _ = c.write_all(&get(1));
    let page = response(&mut c);
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
