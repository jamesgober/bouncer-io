//! Persistence (0.5): bans, lifts, and offender memory survive a restart.
//! Threats T-15, T-16, T-19; edge cases 58, 59, 62, and 63.

use std::{
    io::{BufRead, BufReader},
    net::IpAddr,
    path::PathBuf,
    process::{Command, Stdio},
    sync::{Arc, Mutex},
    time::Duration,
};

use bouncer_io::{
    AccountKey, Actor, BanKey, BanSpec, Bouncer, BouncerError, Cidr, DurationPolicy,
    FilePersistence, FingerprintKey, LoadFailure, PersistError, Persistence, SessionKey,
};
use clock_lib::ManualClock;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn c(s: &str) -> Cidr {
    s.parse().unwrap()
}

/// The snapshot and the journal.
type Files = (Option<Vec<u8>>, Vec<u8>);

/// A store shared between bouncers, to stand for a restart.
#[derive(Clone, Default)]
struct Shared(Arc<Mutex<Files>>);

impl Persistence for Shared {
    fn load(&mut self) -> Result<Option<Vec<u8>>, PersistError> {
        Ok(self.0.lock().unwrap().0.clone())
    }
    fn journal(&mut self) -> Result<Vec<u8>, PersistError> {
        Ok(self.0.lock().unwrap().1.clone())
    }
    fn append(&mut self, records: &[u8]) -> Result<(), PersistError> {
        self.0.lock().unwrap().1.extend_from_slice(records);
        Ok(())
    }
    fn sync(&mut self) -> Result<(), PersistError> {
        Ok(())
    }
    fn replace_snapshot(&mut self, snapshot: &[u8]) -> Result<(), PersistError> {
        let mut g = self.0.lock().unwrap();
        g.0 = Some(snapshot.to_vec());
        g.1.clear();
        Ok(())
    }
}

fn with(store: &Shared, clock: &Arc<ManualClock>) -> Bouncer {
    Bouncer::builder()
        .persistence(Box::new(store.clone()))
        .clock(clock.clone())
        .try_build()
        .unwrap()
}

#[test]
fn test_bans_lifts_and_offences_survive_restart() {
    let store = Shared::default();
    let clock = Arc::new(ManualClock::new());
    let fp = FingerprintKey::from_digest([3; 16]);
    {
        let b = with(&store, &clock);
        b.ban(ip("198.51.100.1")).unwrap();
        b.ban(ip("198.51.100.2")).unwrap();
        b.ban(
            BanSpec::prefix(c("2001:db8:9::/48"))
                .by(Actor::Admin(1))
                .permanent(),
        )
        .unwrap();
        b.ban(BanSpec::prefix(c("10.200.0.0/14")).by(Actor::Admin(1)))
            .unwrap();
        b.ban(BanSpec::key(AccountKey(9))).unwrap();
        b.ban(BanSpec::key(SessionKey::from_digest([4; 16])))
            .unwrap();
        b.ban(BanSpec::key(BanKey::FingerprintIn(fp, c("192.0.2.0/24"))))
            .unwrap();
        b.lift(ip("198.51.100.2")).unwrap();
        // Dropping flushes what is queued.
    }
    let b = with(&store, &clock);
    assert!(b.door(ip("198.51.100.1")).is_err());
    assert!(b.door(ip("198.51.100.2")).is_ok(), "the lift survived too");
    assert!(b.door(ip("2001:db8:9:1::1")).is_err());
    assert!(b.door(ip("10.201.3.4")).is_err(), "an administrator prefix");
    assert!(!b.explain(AccountKey(9)).admitted);
    assert!(!b.explain(SessionKey::from_digest([4; 16])).admitted);
    let mut conn = b.door(ip("192.0.2.9")).unwrap();
    assert!(conn.bind_fingerprint(fp).is_deny(), "a compound key");
    assert!(
        b.explain(ip("198.51.100.1")).offender.is_some(),
        "offender memory"
    );
    assert_eq!(
        b.explain(ip("2001:db8:9::1")).bans[0].until,
        None,
        "still permanent"
    );
}

#[test]
fn test_offences_survive_so_the_next_ban_is_longer() {
    let store = Shared::default();
    let clock = Arc::new(ManualClock::new());
    let policy = DurationPolicy::default()
        .base(Duration::from_secs(100))
        .jitter(Duration::ZERO);
    let build = || {
        Bouncer::builder()
            .persistence(Box::new(store.clone()))
            .clock(clock.clone())
            .durations(policy)
            .try_build()
            .unwrap()
    };
    let addr = ip("192.0.2.50");
    {
        let b = build();
        b.ban(addr).unwrap();
    }
    clock.advance(Duration::from_secs(200));
    clock.step_wall_forward(Duration::from_secs(200));
    let b = build();
    assert!(b.door(addr).is_ok(), "expired across the restart");
    b.ban(addr).unwrap();
    let r = &b.explain(addr).bans[0];
    assert_eq!(
        r.until.unwrap().duration_since(r.issued).unwrap().as_secs(),
        200
    );
}

/// Counts `persist.wall_jump` events.
#[derive(Default)]
struct Jumps(std::sync::atomic::AtomicU32);
impl bouncer_io::EventSink for Jumps {
    fn event(&self, e: &bouncer_io::Event<'_>) {
        if e.signal == bouncer_io::signals::PERSIST_WALL_JUMP {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

#[test]
fn test_wall_clock_steps_never_lengthen_and_strict_keeps() {
    // T-19; edge cases 58 and 59 (the jump is reported).
    for (step_back, strict, banned_after) in [
        (true, false, true),
        (false, false, false),
        (false, true, true),
    ] {
        let store = Shared::default();
        let clock = Arc::new(ManualClock::new());
        let addr = ip("203.0.113.5");
        {
            let b = Bouncer::builder()
                .persistence(Box::new(store.clone()))
                .clock(clock.clone())
                .try_build()
                .unwrap();
            b.ban(BanSpec::address(addr).for_duration(Duration::from_secs(3600)))
                .unwrap();
        }
        if step_back {
            clock.step_wall_back(Duration::from_secs(86_400));
        } else {
            clock.step_wall_forward(Duration::from_secs(86_400));
        }
        let jumps = Arc::new(Jumps::default());
        let b = Bouncer::builder()
            .persistence(Box::new(store.clone()))
            .clock(clock.clone())
            .strict_wall_jump(strict)
            .event_sink(jumps.clone())
            .try_build()
            .unwrap();
        assert_eq!(
            b.door(addr).is_err(),
            banned_after,
            "back {step_back} strict {strict}"
        );
        assert_eq!(
            jumps.0.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "a day's step is reported (back {step_back})"
        );
        if banned_after {
            let r = &b.explain(addr).bans[0];
            let left = r.until.unwrap().duration_since(r.issued).unwrap();
            assert!(
                left <= Duration::from_secs(3600),
                "never longer than issued: {left:?}"
            );
        }
    }
}

#[test]
fn test_snapshot_tampered_byte_refused() {
    // T-15, edge case 63.
    let store = Shared::default();
    let clock = Arc::new(ManualClock::new());
    let key = [42u8; 32];
    {
        let b = Bouncer::builder()
            .persistence(Box::new(store.clone()))
            .mac_key(key)
            .clock(clock.clone())
            .try_build()
            .unwrap();
        b.ban(ip("192.0.2.77")).unwrap();
        b.flush().unwrap();
    }
    // Compact so the ban sits in the snapshot, then tamper with it.
    {
        let b = Bouncer::builder()
            .persistence(Box::new(store.clone()))
            .mac_key(key)
            .clock(clock.clone())
            .try_build()
            .unwrap();
        assert!(b.door(ip("192.0.2.77")).is_err());
    }
    let open = |k: Option<[u8; 32]>, policy| {
        let mut builder = Bouncer::builder()
            .persistence(Box::new(store.clone()))
            .clock(clock.clone())
            .on_load_failure(policy);
        if let Some(k) = k {
            builder = builder.mac_key(k);
        }
        builder.try_build()
    };
    assert!(matches!(
        open(None, LoadFailure::Refuse),
        Err(BouncerError::Persist(PersistError::Mac))
    ));
    assert!(matches!(
        open(Some([1; 32]), LoadFailure::Refuse),
        Err(BouncerError::Persist(PersistError::Mac))
    ));
    {
        let mut g = store.0.lock().unwrap();
        let snap = g.0.as_mut().unwrap();
        let at = snap.len() / 2;
        snap[at] ^= 0x01;
    }
    assert!(matches!(
        open(Some(key), LoadFailure::Refuse),
        Err(BouncerError::Persist(_))
    ));
    // LoadEmpty starts without the bans, knowingly.
    let b = open(Some(key), LoadFailure::LoadEmpty).unwrap();
    assert!(b.door(ip("192.0.2.77")).is_ok());
    drop(b);
    // ... and leaves a clean store behind.
    assert!(open(Some(key), LoadFailure::Refuse).is_ok());
}

#[test]
fn test_torn_journal_tail_and_damaged_middle() {
    // The torn tail rule (edge case 62, a damaged middle, is in src/persist.rs).
    let store = Shared::default();
    let clock = Arc::new(ManualClock::new());
    {
        let b = with(&store, &clock);
        b.ban(ip("192.0.2.1")).unwrap();
        b.flush().unwrap();
        b.ban(ip("192.0.2.2")).unwrap();
        b.flush().unwrap();
    }
    {
        let mut g = store.0.lock().unwrap();
        let n = g.1.len();
        g.1.truncate(n - 5);
    }
    let b = with(&store, &clock);
    assert!(b.door(ip("192.0.2.1")).is_err(), "the whole batch survives");
    assert!(b.door(ip("192.0.2.2")).is_ok(), "the torn batch is lost");
    b.ban(ip("192.0.2.3")).unwrap();
    drop(b);
    // New records after a damaged tail are not swallowed by it.
    let b = with(&store, &clock);
    assert!(b.door(ip("192.0.2.3")).is_err());
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("bouncer-io-test-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn test_file_persistence_restart_and_corruption() {
    let dir = temp_dir("file");
    {
        let b = Bouncer::builder()
            .persistence(Box::new(FilePersistence::open(&dir, "bans").unwrap()))
            .try_build()
            .unwrap();
        b.ban(ip("198.51.100.44")).unwrap();
        b.flush().unwrap();
    }
    let open = || {
        Bouncer::builder()
            .persistence(Box::new(FilePersistence::open(&dir, "bans").unwrap()))
            .try_build()
    };
    assert!(open().unwrap().door(ip("198.51.100.44")).is_err());
    assert!(dir.join("bans").exists());
    // A corrupt snapshot refuses to start by default.
    let path = dir.join("bans");
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[10] ^= 0xff;
    std::fs::write(&path, &bytes).unwrap();
    assert!(matches!(open(), Err(BouncerError::Persist(_))));
    assert!(FilePersistence::open(&dir.join("missing"), "bans").is_err());
    assert!(FilePersistence::open(&dir, "../x").is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

/// The child half of the kill test: bans and flushes until killed, printing
/// each flushed address.
#[test]
#[ignore = "run by test_kill_during_writes_always_loads_cleanly"]
fn kill_child() {
    let Ok(dir) = std::env::var("BOUNCER_KILL_DIR") else {
        return;
    };
    let b = Bouncer::builder()
        .persistence(Box::new(
            FilePersistence::open(dir.as_ref(), "bans").unwrap(),
        ))
        .budgets(bouncer_io::Budgets::off())
        .try_build()
        .unwrap();
    // Runs until the parent kills it.
    let mut i = 0u32;
    loop {
        let addr = IpAddr::from((0x0a00_0000 | (i & 0x00ff_ffff)).to_be_bytes());
        // Spread over /24s so nothing escalates.
        let addr = match addr {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                IpAddr::from([o[0], o[3], o[2], o[1]])
            }
            v6 => v6,
        };
        b.ban(addr).unwrap();
        if i % 7 == 0 {
            b.flush().unwrap();
            println!("flushed {i}");
        }
        i = i.wrapping_add(1);
    }
}

#[test]
fn test_kill_during_writes_always_loads_cleanly() {
    // T-16: kill the writer at random points; the store always loads, and
    // keeps everything that was flushed before the kill.
    let exe = std::env::current_exe().unwrap();
    let mut seed: u64 = 0x2545_f491_4f6c_dd1d;
    // 12 rounds in an ordinary run; BOUNCER_KILL_ROUNDS=1000 before a release.
    let rounds: u32 = std::env::var("BOUNCER_KILL_ROUNDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(12);
    let mut checked = 0;
    for round in 0..rounds {
        let dir = temp_dir(&format!("kill{round}"));
        let mut child = Command::new(&exe)
            .args([
                "--exact",
                "kill_child",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("BOUNCER_KILL_DIR", &dir)
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let lines_before_kill = 5 + (seed % 60) as usize;
        let stdout = child.stdout.take().unwrap();
        let mut reader = BufReader::new(stdout);
        let mut last = None;
        let mut line = String::new();
        for _ in 0..lines_before_kill {
            line.clear();
            if reader.read_line(&mut line).unwrap() == 0 {
                break;
            }
            if let Some(n) = line.trim().strip_prefix("flushed ") {
                last = n.parse::<u32>().ok();
            }
        }
        child.kill().unwrap();
        let _ = child.wait();
        let b = Bouncer::builder()
            .persistence(Box::new(FilePersistence::open(&dir, "bans").unwrap()))
            .try_build()
            .expect("the store loads after a kill");
        if let Some(n) = last {
            let addr = IpAddr::from((0x0a00_0000 | (n & 0x00ff_ffff)).to_be_bytes());
            let addr = match addr {
                IpAddr::V4(v4) => {
                    let o = v4.octets();
                    IpAddr::from([o[0], o[3], o[2], o[1]])
                }
                v6 => v6,
            };
            assert!(b.door(addr).is_err(), "round {round}: flushed ban {n} lost");
            checked += 1;
        }
        drop(b);
        let _ = std::fs::remove_dir_all(&dir);
    }
    assert!(
        checked * 6 >= rounds * 5,
        "the child must have run: {checked} of {rounds} rounds checked"
    );
}
