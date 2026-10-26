//! Arbitrary sequences of bans, lifts, door checks, requests, revocations,
//! and checkpoints, compared with a plain model: the door refuses exactly the
//! banned addresses, and a checkpoint denies exactly the requests whose
//! session or connection was revoked.

#![no_main]

use std::net::IpAddr;

use bouncer_io::{
    Bouncer, Budgets, Directive, EscalationPolicy, Reason, RequestId, SessionKey, Ticket,
};
use libfuzzer_sys::fuzz_target;

const ADDRS: usize = 8;
const SESSIONS: usize = 4;

fn addr(i: usize) -> IpAddr {
    IpAddr::from([192, 0, 2, i as u8 + 1])
}

fn session(i: usize) -> SessionKey {
    SessionKey::from_digest([i as u8 + 1; 16])
}

struct Live {
    conn: Ticket,
    req: Ticket,
    addr: usize,
    session: usize,
    revoked: bool,
}

fuzz_target!(|data: &[u8]| {
    // Escalation off: the model bans exactly the addresses it was told to.
    let b = Bouncer::builder()
        .budgets(Budgets::off())
        .escalation(EscalationPolicy::default().off())
        .tickets(256)
        .ban_capacity(64)
        .try_build()
        .unwrap();
    let mut banned = [false; ADDRS];
    let mut revoked_sessions = [false; SESSIONS];
    let mut live: Vec<Live> = Vec::new();
    for pair in data.chunks(2).take(256) {
        let (op, arg) = (pair[0] % 7, usize::from(*pair.get(1).unwrap_or(&0)));
        match op {
            0 => {
                let a = arg % ADDRS;
                if b.ban(addr(a)).is_ok() {
                    banned[a] = true;
                }
            }
            1 => {
                let a = arg % ADDRS;
                let lifted = b.lift(addr(a)).is_ok();
                assert_eq!(lifted, banned[a], "lift of {a}");
                banned[a] = false;
            }
            2 => {
                let a = arg % ADDRS;
                let s = (arg / ADDRS) % SESSIONS;
                match b.door(addr(a)) {
                    Ok(conn) => {
                        assert!(!banned[a], "banned address {a} admitted");
                        if live.len() < 64 {
                            let Ok(mut req) = conn.request(RequestId(live.len() as u128)) else {
                                continue;
                            };
                            // A revocation stops running work; once maintenance has
                            // reclaimed it, a new bind of the session passes (keeping
                            // the session out for good is a ban or the gate's job).
                            let bound = req.bind_session(session(s));
                            if bound.is_deny() {
                                assert!(
                                    revoked_sessions[s],
                                    "bind of session {s} denied without a revocation"
                                );
                            }
                            let revoked = bound.is_deny();
                            live.push(Live {
                                conn,
                                req,
                                addr: a,
                                session: s,
                                revoked,
                            });
                        }
                    }
                    Err(_) => assert!(banned[a], "address {a} refused without a ban"),
                }
            }
            3 => {
                let s = arg % SESSIONS;
                let _ = b.apply(
                    Directive::revoke(session(s))
                        .because(Reason::LOGOUT)
                        .keep_connection(),
                );
                revoked_sessions[s] = true;
                for l in live.iter_mut().filter(|l| l.session == s) {
                    l.revoked = true;
                }
            }
            4 => {
                if !live.is_empty() {
                    let i = arg % live.len();
                    let conn = live[i].conn.conn();
                    let _ = b.revoke(conn, Reason::ADMIN);
                    live[i].revoked = true;
                }
            }
            5 => {
                for l in live.iter_mut() {
                    let v = l.req.checkpoint();
                    assert_eq!(
                        v.is_deny(),
                        l.revoked,
                        "request at {} session {}",
                        l.addr,
                        l.session
                    );
                }
            }
            _ => {
                if !live.is_empty() {
                    let i = arg % live.len();
                    live.swap_remove(i);
                }
                let _ = b.maintain(b.now());
            }
        }
    }
});
