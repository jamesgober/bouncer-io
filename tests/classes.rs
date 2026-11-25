//! Budget classes (0.12, D-148): a budget a long-lived ticket charges once
//! per unit of work, keyed by account, else session, else client.

use std::{net::IpAddr, sync::Arc, time::Duration};

use bouncer_io::{
    AccountKey, AllowList, Bouncer, BudgetClass, Budgets, Cidr, DenialCode, Directive, Rate,
    Reason, RequestId, SessionKey, Verdict,
};
use clock_lib::ManualClock;

const MESSAGES: BudgetClass = BudgetClass(1);
const OTHER: BudgetClass = BudgetClass(2);

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn code(v: Verdict) -> Option<DenialCode> {
    match v {
        Verdict::Deny(d) => Some(d.code),
        _ => None,
    }
}

fn with(budgets: Budgets) -> (Bouncer, Arc<ManualClock>) {
    let clock = Arc::new(ManualClock::new());
    let b = Bouncer::builder()
        .clock(clock.clone())
        .budgets(budgets)
        .build()
        .unwrap();
    (b, clock)
}

#[test]
fn test_a_long_lived_ticket_charges_a_class_per_message_and_stays_open() {
    let (b, clock) = with(Budgets::off().class_rate(MESSAGES, Rate::per_second(3)));
    let mut socket = b.door(ip("192.0.2.1")).unwrap();
    assert!(socket.bind_account(AccountKey(1)).is_pass());
    for _ in 0..3 {
        assert!(socket.charge(MESSAGES).is_pass());
    }
    assert_eq!(
        code(socket.charge(MESSAGES)),
        Some(DenialCode::TooManyRequests),
        "the fourth message in a second is over"
    );
    assert!(socket.checkpoint().is_pass(), "the socket stays live");
    assert!(b.egress(socket.tag()).is_pass());
    clock.advance(Duration::from_secs(1));
    assert!(socket.charge(MESSAGES).is_pass(), "the budget recovers");
}

#[test]
fn test_a_class_is_keyed_by_account_then_session_then_client() {
    let (b, _clock) = with(Budgets::off().class_rate(MESSAGES, Rate::per_minute(1)));
    // Two connections of one account share its budget.
    let mut a1 = b.door(ip("192.0.2.2")).unwrap();
    let mut a2 = b.door(ip("192.0.2.3")).unwrap();
    assert!(a1.bind_account(AccountKey(2)).is_pass());
    assert!(a2.bind_account(AccountKey(2)).is_pass());
    assert!(a1.charge(MESSAGES).is_pass());
    assert!(
        a2.charge(MESSAGES).is_deny(),
        "the account's budget is spent"
    );
    // The account goes ahead of the session.
    let mut a3 = b.door(ip("192.0.2.4")).unwrap();
    assert!(a3.bind_session(SessionKey::from_digest([1; 16])).is_pass());
    assert!(a3.bind_account(AccountKey(2)).is_pass());
    assert!(a3.charge(MESSAGES).is_deny());
    // Another account has its own.
    let mut other = b.door(ip("192.0.2.2")).unwrap();
    assert!(other.bind_account(AccountKey(3)).is_pass());
    assert!(other.charge(MESSAGES).is_pass());
    // No account: the session.
    let mut s = b.door(ip("192.0.2.2")).unwrap();
    assert!(s.bind_session(SessionKey::from_digest([2; 16])).is_pass());
    assert!(s.charge(MESSAGES).is_pass());
    // Neither: the client, shared by its connections.
    let mut c1 = b.door(ip("192.0.2.9")).unwrap();
    let mut c2 = b.door(ip("192.0.2.9")).unwrap();
    assert!(c1.charge(MESSAGES).is_pass());
    assert!(c2.charge(MESSAGES).is_deny());
    // Classes are separate, and a class with no rate passes.
    let mut c3 = b.door(ip("192.0.2.9")).unwrap();
    assert!(c3.charge(OTHER).is_pass());
    assert!(c3.charge(OTHER).is_pass());
}

#[test]
fn test_a_class_counts_units_and_refuses_more_than_its_burst() {
    let (b, _clock) = with(Budgets::off().class_rate(MESSAGES, Rate::per_second(100)));
    let mut socket = b.door(ip("192.0.2.10")).unwrap();
    assert!(socket.bind_account(AccountKey(10)).is_pass());
    assert!(socket.charge_n(MESSAGES, 101).is_deny(), "never fits");
    assert!(socket.charge_n(MESSAGES, 60).is_pass());
    assert!(socket.charge_n(MESSAGES, 60).is_deny());
    assert!(socket.charge_n(MESSAGES, 40).is_pass());
}

#[test]
fn test_a_throttle_multiplies_a_class_charge() {
    let (b, _clock) = with(Budgets::off().class_rate(MESSAGES, Rate::per_second(8)));
    b.apply(
        Directive::throttle(AccountKey(11), 4, Duration::from_secs(60)).because(Reason::POLICY),
    )
    .unwrap();
    let mut socket = b.door(ip("192.0.2.11")).unwrap();
    assert!(socket.bind_account(AccountKey(11)).is_pass());
    assert!(socket.charge(MESSAGES).is_pass());
    assert!(socket.charge(MESSAGES).is_pass());
    assert!(
        socket.charge(MESSAGES).is_deny(),
        "two messages cost the eight"
    );
}

#[test]
fn test_a_revoked_ticket_gets_its_revocation_not_a_budget_answer() {
    let (b, _clock) = with(Budgets::off().class_rate(MESSAGES, Rate::per_second(8)));
    let mut socket = b.door(ip("192.0.2.12")).unwrap();
    let session = SessionKey::from_digest([12; 16]);
    assert!(socket.bind_session(session).is_pass());
    b.revoke(session, Reason::LOGOUT).unwrap();
    let got = code(socket.charge(MESSAGES));
    assert!(
        got.is_some() && got != Some(DenialCode::TooManyRequests),
        "{got:?}"
    );
}

#[test]
fn test_an_allow_listed_source_is_not_charged_a_class() {
    let b = Bouncer::builder()
        .budgets(Budgets::off().class_rate(MESSAGES, Rate::per_minute(1)))
        .allow(AllowList::new().exempt_budgets("10.0.0.0/8".parse::<Cidr>().unwrap(), "ops"))
        .build()
        .unwrap();
    let mut socket = b.door(ip("10.1.2.3")).unwrap();
    for _ in 0..10 {
        assert!(socket.charge(MESSAGES).is_pass());
    }
}

#[test]
fn test_a_full_class_table_refuses_rather_than_lets_a_key_through_uncounted() {
    // Every slot on the path holds a key that has not recovered: a new key
    // is refused, never charged nowhere (as D-144 for concurrency).
    let (b, _clock) = with(
        Budgets::off()
            .class_rate(MESSAGES, Rate::per_minute(1))
            .capacity(1),
    );
    let conn = b.door(ip("192.0.2.13")).unwrap();
    let mut refused = 0;
    for i in 0..256u128 {
        let mut r = conn.request(RequestId(i)).unwrap();
        assert!(r.bind_account(AccountKey(1_000 + i)).is_pass());
        if r.charge(MESSAGES).is_deny() {
            refused += 1;
        }
    }
    assert!(refused > 0, "a full table refused new keys");
    assert!(refused < 256, "the keys that fit were charged");
}

#[test]
fn test_class_budgets_are_validated() {
    let mut many = Budgets::off();
    for c in 0..65u16 {
        many = many.class_rate(BudgetClass(c), Rate::per_second(1));
    }
    assert!(
        Bouncer::builder().budgets(many).build().is_err(),
        "64 at most"
    );
    let mut set = Budgets::off();
    for _ in 0..100 {
        set = set.class_rate(MESSAGES, Rate::per_second(1));
    }
    assert!(
        Bouncer::builder().budgets(set).build().is_ok(),
        "setting a class again replaces it"
    );
}
