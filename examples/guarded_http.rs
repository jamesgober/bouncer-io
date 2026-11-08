//! A small site behind bouncer: serve-net over net-io, with bouncer as the
//! gate at the door and on every write, and as a checkpoint before each reply.
//!
//! ```text
//! cargo run --example guarded_http --features net-io -- 127.0.0.1:8080 127.0.0.1:8081
//! ```
//!
//! Open the first address in a browser: `/login` starts a session and
//! `/account` shows a page bound to it. The second address is the
//! administrator's: `/ban?ip=127.0.0.1`, `/lift?ip=127.0.0.1`, and
//! `/revoke?session=1`. Press Enter to stop.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bouncer_io::{Actor, Bouncer, Directive, Reason, RequestId, SessionKey, Ticket, TicketTag};
use serve_net::{
    Checkpoint, CheckpointAt, Envelope, HeadAction, HttpHead, HttpReply, HttpRequest, HttpService,
    ListenerSpec, Outcome, Server, Verdict,
};

/// Judges the request's ticket before its reply leaves.
struct Guard(Bouncer);

impl Checkpoint for Guard {
    fn check(&self, env: &Envelope, at: CheckpointAt) -> Verdict {
        if at == CheckpointAt::BeforeReply && env.user_word() != 0 {
            // The denial's own status: 403 for a revocation, 429 or 503 when
            // the directive said so.
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

struct Site {
    bouncer: Bouncer,
    requests: Mutex<HashMap<u64, Ticket>>,
    sessions: AtomicU64,
}

fn session_key(number: u64) -> SessionKey {
    let mut digest = [0u8; 16];
    digest[..8].copy_from_slice(&number.to_be_bytes());
    SessionKey::from_digest(digest)
}

fn session_of(cookie: &str) -> Option<u64> {
    cookie
        .split(';')
        .find_map(|c| c.trim().strip_prefix("session="))
        .and_then(|n| n.parse().ok())
}

impl HttpService for Site {
    fn head(&self, head: &HttpHead<'_>, env: &mut Envelope) -> HeadAction {
        let Some(number) = head.header_str("cookie").and_then(session_of) else {
            return HeadAction::Proceed;
        };
        // The envelope carries the tag bouncer gave the connection at the door.
        let tag = TicketTag::from(env.gate_tag());
        let id = RequestId(u128::from(env.seq().get()));
        let Ok(mut request) = self.bouncer.request(tag, id) else {
            return HeadAction::refuse(503);
        };
        if request.bind_session(session_key(number)).is_deny() {
            return HeadAction::refuse(403);
        }
        env.set_user_word(request.tag().get());
        if let Ok(mut requests) = self.requests.lock() {
            requests.insert(env.user_word(), request);
        }
        HeadAction::Proceed
    }

    fn call(&self, request: &HttpRequest<'_>, env: &Envelope, reply: &mut HttpReply) -> Outcome {
        match request.path() {
            "/login" => {
                let number = self.sessions.fetch_add(1, Ordering::Relaxed) + 1;
                reply.header("set-cookie", format!("session={number}; Path=/"));
                reply.html(
                    200,
                    &format!(
                        "<!doctype html><title>Logged in</title><p>Session {number}. <a href=/account>Account</a>"
                    ),
                );
            }
            "/account" if env.user_word() != 0 => {
                reply.html(
                    200,
                    "<!doctype html><title>Account</title><h1>Your account</h1>",
                );
            }
            _ => {
                reply.html(
                    200,
                    "<!doctype html><title>Home</title><h1>Behind bouncer</h1><a href=/login>Log in</a>",
                );
            }
        }
        Outcome::Done
    }

    fn done(&self, env: &Envelope, _finished: &serve_net::Finished) {
        if let Ok(mut requests) = self.requests.lock() {
            requests.remove(&env.user_word());
        }
    }
}

fn admin(addr: &str, bouncer: Bouncer) -> Result<serve_net::Running, serve_net::ServeError> {
    serve_net::http(addr, move |req, reply| {
        let query = req.query().unwrap_or("");
        let ip = query
            .strip_prefix("ip=")
            .and_then(|s| s.parse::<IpAddr>().ok());
        let session = query.strip_prefix("session=").and_then(|s| s.parse().ok());
        let done = match (req.path(), ip, session) {
            // The door and whatever this address already has open.
            ("/ban", Some(ip), _) => bouncer
                .apply(Directive::revoke_and_ban(ip).by(Actor::Admin(1)))
                .is_ok(),
            ("/lift", Some(ip), _) => bouncer.lift(ip).is_ok(),
            ("/revoke", _, Some(n)) => bouncer.revoke(session_key(n), Reason::ADMIN).is_ok(),
            _ => false,
        };
        reply.text(
            if done { 200 } else { 400 },
            if done { "done" } else { "no" },
        );
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let site_addr = args.next().unwrap_or_else(|| "127.0.0.1:8080".to_owned());
    let admin_addr = args.next().unwrap_or_else(|| "127.0.0.1:8081".to_owned());
    let bouncer = Bouncer::new();
    let site = Server::builder()
        .listener(ListenerSpec::tcp("web", site_addr.as_str()))
        .gate(bouncer.clone())
        .checkpoint(Guard(bouncer.clone()))
        .serve(Site {
            bouncer: bouncer.clone(),
            requests: Mutex::default(),
            sessions: AtomicU64::new(0),
        })?;
    let control = admin(&admin_addr, bouncer)?;
    println!("site on http://{site_addr}/, administrator on http://{admin_addr}/");
    println!("press Enter to stop");
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    control.drain(Duration::from_secs(1));
    site.drain(Duration::from_secs(1));
    Ok(())
}
