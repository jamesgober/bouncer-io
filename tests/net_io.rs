//! bouncer as net-io's gate, over loopback: the 0.8 exit tests.
//!
//! A banned client is refused at the door; a request whose session is
//! revoked before its response starts gets the generic denial and its
//! connection is closed; a streamed response cut by revocation leaks at most
//! the chunk in flight; every refusal is the same close on the wire (T-8); a
//! slow reader is aborted without waiting for it (edge case 47).

#![cfg(feature = "net-io")]

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use bouncer_io::{Bouncer, Reason, RequestId, SessionKey, Ticket, TicketTag};
use net_io::{
    CloseReason, ConnectionInfo, GateTag, Input, ListenerSpec, Output, Server, ServerBuilder,
    Session, SessionContext, Step,
};

const WAIT: Duration = Duration::from_secs(5);
const CHUNK: usize = 1000;

fn session_key() -> SessionKey {
    SessionKey::from_digest([7; 16])
}

/// A line protocol: `open` starts a request bound to the session (nothing
/// is written), `chunk` writes one chunk of its response, `end` ends it,
/// `flood` writes for as long as the client takes it.
struct Paced {
    bouncer: Bouncer,
    conn: TicketTag,
    request: Option<Ticket>,
    next: u128,
    flood: bool,
    opened: mpsc::Sender<()>,
}

impl Session for Paced {
    fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
        let mut write = false;
        while let Some(end) = input.bytes().iter().position(|&b| b == b'\n') {
            let line = input.bytes()[..end].to_vec();
            input.consume(end + 1);
            match line.as_slice() {
                b"open" => {
                    self.next += 1;
                    let Ok(mut request) = self.bouncer.request(self.conn, RequestId(self.next))
                    else {
                        return Step::Abort;
                    };
                    if !request.bind_session(session_key()).is_pass() {
                        return Step::Abort;
                    }
                    cx.output()
                        .begin_tagged_response(GateTag::from(request.tag()));
                    self.request = Some(request);
                    let _ = self.opened.send(());
                }
                b"chunk" => {
                    if cx.output().push(&[b'c'; CHUNK]).is_err() {
                        return Step::Abort;
                    }
                    write = true;
                }
                b"end" => {
                    cx.output().end_response();
                    self.request = None;
                }
                b"flood" => {
                    self.flood = true;
                    let _ = cx.output().push(&[b'f'; CHUNK]);
                    write = true;
                }
                _ => return Step::Abort,
            }
        }
        if write { Step::Write } else { Step::Read }
    }

    fn on_writable(&mut self, cx: &mut SessionContext<'_>) -> Step {
        if !self.flood {
            return Step::Read;
        }
        while cx.output().push(&[b'f'; CHUNK]).is_ok() {}
        Step::Write
    }

    fn on_denied(&mut self, code: u16, output: &mut Output) {
        let _ = output.push(format!("denied {code}\n").as_bytes());
    }
}

fn server(bouncer: &Bouncer) -> (Server, SocketAddr, mpsc::Receiver<()>) {
    let (tx, rx) = mpsc::channel();
    let b = bouncer.clone();
    let server = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0"))
        .workers(2)
        .sessions(move |info: &ConnectionInfo| Paced {
            bouncer: b.clone(),
            conn: TicketTag::from(info.gate),
            request: None,
            next: 0,
            flood: false,
            opened: tx.clone(),
        })
        .gate(bouncer.clone())
        .build()
        .expect("build");
    server.open_door().expect("open");
    let addr = server.listeners()[0].local.socket_addr().expect("tcp");
    (server, addr, rx)
}

fn client(addr: SocketAddr) -> TcpStream {
    let c = TcpStream::connect(addr).expect("connect");
    c.set_read_timeout(Some(WAIT)).expect("timeout");
    c
}

/// Everything a refused client sees. The reset can reach it before `connect`
/// returns, and then the connect is what reports it.
fn refused(addr: SocketAddr, sent: &[u8]) -> (Vec<u8>, Result<(), std::io::ErrorKind>) {
    let mut c = match TcpStream::connect(addr) {
        Ok(c) => c,
        Err(e) => return (Vec::new(), Err(e.kind())),
    };
    c.set_read_timeout(Some(WAIT)).expect("timeout");
    let _ = c.write_all(sent);
    let mut got = Vec::new();
    let r = c.read_to_end(&mut got);
    (got, r.map(|_| ()).map_err(|e| e.kind()))
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

#[test]
fn test_net_io_banned_client_is_refused_at_the_door() {
    let bouncer = Bouncer::new();
    let (server, addr, _rx) = server(&bouncer);

    // Before the ban: admitted, and a chunk comes back.
    let mut c = client(addr);
    c.write_all(b"chunk\n").expect("write");
    let mut got = [0u8; CHUNK];
    c.read_exact(&mut got).expect("read");
    drop(c);

    bouncer
        .ban("127.0.0.1".parse::<IpAddr>().unwrap())
        .expect("ban");
    let refused_before = server.stats().refused;
    let (got, _) = refused(addr, b"chunk\n");
    assert!(got.is_empty(), "a refused client reads nothing: {got:?}");
    assert!(eventually(|| server.stats().refused > refused_before));
}

#[test]
fn test_net_io_revoked_session_gets_the_generic_denial_and_is_closed() {
    let bouncer = Bouncer::new();
    let (server, addr, rx) = server(&bouncer);
    let mut c = client(addr);
    c.write_all(b"open\n").expect("write");
    rx.recv_timeout(WAIT).expect("request opened");

    bouncer
        .revoke(session_key(), Reason::ADMIN)
        .expect("revoke");
    c.write_all(b"chunk\n").expect("write");
    let mut got = Vec::new();
    let _ = c.read_to_end(&mut got);
    assert_eq!(
        got, b"denied 5\n",
        "the generic denial and nothing of the body"
    );
    assert!(eventually(|| server
        .stats()
        .closed_for(CloseReason::EgressDenied(0))
        == 1));
}

#[test]
fn test_net_io_stream_cut_by_revocation_leaks_at_most_one_chunk() {
    let bouncer = Bouncer::new();
    let (server, addr, rx) = server(&bouncer);
    let mut c = client(addr);
    c.write_all(b"open\nchunk\n").expect("write");
    rx.recv_timeout(WAIT).expect("request opened");
    let mut first = [0u8; CHUNK];
    c.read_exact(&mut first).expect("first chunk");

    bouncer
        .revoke(session_key(), Reason::ADMIN)
        .expect("revoke");
    for _ in 0..8 {
        if c.write_all(b"chunk\n").is_err() {
            break;
        }
    }
    let mut rest = Vec::new();
    let _ = c.read_to_end(&mut rest);
    assert!(
        rest.is_empty(),
        "nothing after the revocation: {} bytes",
        rest.len()
    );
    assert!(eventually(|| server.stats().egress_denied == 1));
}

#[test]
fn test_net_io_close_releases_the_connection_ticket() {
    let bouncer = Bouncer::new();
    let (server, addr, _rx) = server(&bouncer);
    let mut c = client(addr);
    c.write_all(b"chunk\n").expect("write");
    let mut got = [0u8; CHUNK];
    c.read_exact(&mut got).expect("read");
    assert_eq!(bouncer.health().tickets_live, 1);
    drop(c);
    assert!(eventually(|| bouncer.health().tickets_live == 0));
    drop(server);
}

#[test]
fn test_net_io_ejector_closes_an_idle_connection() {
    let ejector = std::sync::Arc::new(bouncer_io::NetIoEjector::new());
    let bouncer = Bouncer::builder()
        .ejector(ejector.clone())
        .try_build()
        .expect("bouncer");
    let (server, addr, _rx) = server(&bouncer);
    assert!(ejector.attach(server.handle()));
    let mut c = client(addr);
    c.write_all(b"chunk\n").expect("write");
    let mut got = [0u8; CHUNK];
    c.read_exact(&mut got).expect("read");

    // The connection is idle: no write will cross the gate, so only an
    // ejection closes it.
    bouncer
        .apply(bouncer_io::Directive::revoke("127.0.0.1".parse::<IpAddr>().unwrap()).eject_now())
        .expect("apply");
    let mut rest = Vec::new();
    let _ = c.read_to_end(&mut rest);
    assert!(rest.is_empty());
    assert!(eventually(|| server
        .stats()
        .closed_for(CloseReason::Killed(bouncer_io::EJECTED))
        == 1));
}

#[test]
fn test_net_io_readmit_binds_the_proxied_client_and_refuses_a_banned_one() {
    use net_io::{AdmitStage, Gate};
    let proxy = bouncer_io::Cidr::new("192.0.2.1".parse().unwrap(), 32).unwrap();
    let bouncer = Bouncer::builder()
        .trusted_proxies(&[proxy])
        .try_build()
        .expect("bouncer");
    bouncer
        .ban("203.0.113.9".parse::<IpAddr>().unwrap())
        .expect("ban");

    let mut info = ConnectionInfo::for_testing("192.0.2.1:40000".parse().unwrap());
    let mut admitted = bouncer
        .admit(&info, AdmitStage::Accept)
        .expect("proxy admitted");
    info.real_peer = Some("198.51.100.4:5000".parse().unwrap());
    assert!(bouncer.readmit(&mut admitted.ticket, &info).is_ok());
    assert_eq!(
        admitted.ticket.ticket().source(),
        Some("198.51.100.4".parse().unwrap())
    );

    let mut info = ConnectionInfo::for_testing("192.0.2.1:40001".parse().unwrap());
    let mut admitted = bouncer
        .admit(&info, AdmitStage::Accept)
        .expect("proxy admitted");
    info.real_peer = Some("203.0.113.9:5000".parse().unwrap());
    assert_eq!(
        bouncer
            .readmit(&mut admitted.ticket, &info)
            .map_err(|r| r.code()),
        Err(bouncer_io::REFUSED)
    );
}

#[test]
fn test_net_io_misbehaviour_close_is_a_strike() {
    use net_io::{AdmitStage, Direction, Gate};
    let bouncer = Bouncer::new();
    let info = ConnectionInfo::for_testing("198.51.100.20:40000".parse().unwrap());
    let admitted = bouncer.admit(&info, AdmitStage::Accept).expect("admitted");
    bouncer.closed(
        admitted.ticket,
        &info,
        CloseReason::SlowPeer {
            direction: Direction::In,
        },
    );
    let ex = bouncer.explain("198.51.100.20".parse::<IpAddr>().unwrap());
    assert!(
        ex.strikes.iter().any(|s| s.count > 0),
        "a slow peer close counts as a strike: {ex:?}"
    );
    assert_eq!(bouncer.health().tickets_live, 0);
}

#[test]
fn test_net_io_every_refusal_is_the_same_close() {
    // T-8 on the wire: a peer cannot tell a ban from a spent budget.
    use bouncer_io::Budgets;
    let bouncer = Bouncer::builder()
        .budgets(Budgets::off().door_concurrency(1, 1))
        .try_build()
        .expect("bouncer");
    let (server, addr, _rx) = server(&bouncer);
    let mut held = client(addr);
    held.write_all(b"chunk\n").expect("write");
    let mut got = [0u8; CHUNK];
    held.read_exact(&mut got).expect("read");

    // Nothing is sent: a write can take the reset, leaving the read a plain
    // end of stream.
    let over_budget = refused(addr, b"");
    bouncer
        .ban("127.0.0.1".parse::<IpAddr>().unwrap())
        .expect("ban");
    let banned = refused(addr, b"");
    assert_eq!(over_budget, banned, "one close for every reason");
    assert!(banned.0.is_empty(), "a refused client reads nothing");
    assert!(eventually(|| server.stats().refused == 2));
}

#[test]
fn test_net_io_slow_reader_is_aborted_without_waiting_for_it() {
    // Edge case 47: a client that stopped reading with output pending holds
    // no write for the gate to deny; an ejection closes it all the same,
    // and the client is not waited for.
    let ejector = std::sync::Arc::new(bouncer_io::NetIoEjector::new());
    let bouncer = Bouncer::builder()
        .ejector(ejector.clone())
        .try_build()
        .expect("bouncer");
    let (server, addr, _rx) = server(&bouncer);
    assert!(ejector.attach(server.handle()));
    let mut c = client(addr);
    c.write_all(b"flood\n").expect("write");
    let mut first = [0u8; CHUNK];
    c.read_exact(&mut first).expect("read");
    // Stop reading until the server's socket buffers fill: sent stops moving.
    let mut sent = server.stats().bytes_out;
    let mut still = 0;
    while still < 40 {
        std::thread::sleep(Duration::from_millis(5));
        let now = server.stats().bytes_out;
        still = if now == sent { still + 1 } else { 0 };
        sent = now;
    }

    let start = Instant::now();
    bouncer
        .apply(bouncer_io::Directive::revoke("127.0.0.1".parse::<IpAddr>().unwrap()).eject_now())
        .expect("apply");
    assert!(eventually(|| server
        .stats()
        .closed_for(CloseReason::Killed(bouncer_io::EJECTED))
        == 1));
    assert!(start.elapsed() < WAIT, "closed without the client reading");
}
