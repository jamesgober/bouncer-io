//! NFR-13: the soak. Connections at a paced 100,000 a second from about a
//! million addresses, with bans added (each expiring after 30 seconds) and
//! lifted continuously, and sessions revoked from another thread while
//! their requests run. It checks that no revocation is missed and that
//! live heap memory stays flat once the tables are warm (no growth past the
//! configured tables).
//!
//! Integration tests are separate crates, so `unsafe` is allowed here for the
//! allocator shim (dev/DIRECTIVES.md: test crates may inspect the allocator).
//!
//! `BOUNCER_SOAK_SECS=86400 cargo test --release --test soak -- --ignored --nocapture`
//! (the 0.7 run); without the variable it runs for 60 seconds.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicIsize, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use bouncer_io::{
    BanSpec, Bouncer, ConnId, LiftSpec, MaintainerState, Provenance, Reason, Refusal, RequestId,
    SessionKey,
};

struct Live;

static LIVE_BYTES: AtomicIsize = AtomicIsize::new(0);

// SAFETY: every call is forwarded unchanged to the system allocator; the
// shim only counts the bytes live.
unsafe impl GlobalAlloc for Live {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: same contract as the caller's.
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            LIVE_BYTES.fetch_add(layout.size() as isize, Ordering::Relaxed);
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE_BYTES.fetch_sub(layout.size() as isize, Ordering::Relaxed);
        // SAFETY: same contract as the caller's.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: same contract as the caller's.
        let p = unsafe { System.realloc(ptr, layout, new_size) };
        if !p.is_null() {
            LIVE_BYTES.fetch_add(
                new_size as isize - layout.size() as isize,
                Ordering::Relaxed,
            );
        }
        p
    }
}

#[global_allocator]
static GLOBAL: Live = Live;

const WORKERS: u64 = 4;
const CONNECTIONS_PER_SECOND: u64 = 100_000;

/// A small, fast generator (xorshift64*), seeded per thread.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// An address in 10.0.0.0/12: about a million clients.
    fn client(&mut self) -> IpAddr {
        IpAddr::from((0x0a00_0000 | (self.next() as u32 & 0x000f_ffff)).to_be_bytes())
    }

    /// An address in 10.15.0.0/16, the part of the population the bans
    /// fall on (256 of the 4,096 /24s).
    fn offender(&mut self) -> IpAddr {
        IpAddr::from((0x0a0f_0000 | (self.next() as u32 & 0xffff)).to_be_bytes())
    }
}

fn session(n: u64) -> SessionKey {
    let mut d = [0u8; 16];
    d[..8].copy_from_slice(&n.to_le_bytes());
    d[8] = 0x50;
    SessionKey::from_digest(d)
}

#[derive(Default)]
struct Counts {
    connections: AtomicU64,
    refused: AtomicU64,
    refused_banned: AtomicU64,
    bans: AtomicU64,
    lifts: AtomicU64,
    revocations: AtomicU64,
    missed: AtomicU64,
}

#[test]
#[ignore = "the soak; run with --release -- --ignored, BOUNCER_SOAK_SECS sets its length"]
fn soak_connections_bans_and_revocations() {
    let secs: u64 = std::env::var("BOUNCER_SOAK_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(60);
    let run_for = Duration::from_secs(secs);
    let b = Bouncer::builder()
        .tickets(1 << 16)
        .ban_capacity(1 << 17)
        .maintainer(true)
        .try_build()
        .unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let counts = Arc::new(Counts::default());
    let start = Instant::now();
    let mut threads = Vec::new();

    // Connections, paced to the target rate.
    for w in 0..WORKERS {
        let (b, stop, counts) = (b.clone(), Arc::clone(&stop), Arc::clone(&counts));
        threads.push(std::thread::spawn(move || {
            let mut rng = Rng(0x9e37_79b9_7f4a_7c15 ^ (w + 1));
            let per_thread = CONNECTIONS_PER_SECOND / WORKERS;
            let begin = Instant::now();
            let mut n: u64 = 0;
            while !stop.load(Ordering::Relaxed) {
                let due = begin + Duration::from_nanos(n * 1_000_000_000 / per_thread);
                let now = Instant::now();
                if now < due {
                    std::thread::sleep(due - now);
                }
                for _ in 0..64 {
                    let id = ConnId((w << 48) | n);
                    n += 1;
                    match b.door_at(id, rng.client(), Provenance::Socket, b.now()) {
                        Ok(conn) => {
                            if let Ok(mut req) = conn.request(RequestId(u128::from(n))) {
                                let _ = req.bind_session(session(rng.next() & 0xffff));
                                let _ = req.checkpoint();
                            }
                            counts.connections.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(r) => {
                            counts.refused.fetch_add(1, Ordering::Relaxed);
                            if matches!(r, Refusal::Banned { .. }) {
                                counts.refused_banned.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
            }
        }));
    }

    // Bans that expire after 30 seconds, about 1,000 a second; every tenth
    // is lifted early.
    {
        let (b, stop, counts) = (b.clone(), Arc::clone(&stop), Arc::clone(&counts));
        threads.push(std::thread::spawn(move || {
            let mut rng = Rng(0x5eed);
            let mut recent: Vec<IpAddr> = Vec::with_capacity(16);
            while !stop.load(Ordering::Relaxed) {
                let addr = rng.offender();
                let spec = BanSpec::address(addr).for_duration(Duration::from_secs(30));
                if b.ban(spec).is_ok() {
                    counts.bans.fetch_add(1, Ordering::Relaxed);
                    recent.push(addr);
                }
                if recent.len() == 10 {
                    if b.lift(LiftSpec::key(recent[0])).is_ok() {
                        counts.lifts.fetch_add(1, Ordering::Relaxed);
                    }
                    recent.clear();
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }));
    }

    // Revocations from another thread while the request runs: once the
    // revoker has published that a session is revoked, the request's next
    // checkpoint must deny.
    let ready = Arc::new(AtomicU64::new(0));
    let revoked = Arc::new(AtomicU64::new(0));
    {
        let (b, stop, counts, ready, revoked) = (
            b.clone(),
            Arc::clone(&stop),
            Arc::clone(&counts),
            Arc::clone(&ready),
            Arc::clone(&revoked),
        );
        threads.push(std::thread::spawn(move || {
            let mut k = 0u64;
            while !stop.load(Ordering::Relaxed) {
                k += 1;
                while ready.load(Ordering::SeqCst) < k {
                    if stop.load(Ordering::Relaxed) {
                        return;
                    }
                    std::thread::yield_now();
                }
                b.revoke(session((1 << 40) | k), Reason::LOGOUT).unwrap();
                revoked.store(k, Ordering::SeqCst);
                counts.revocations.fetch_add(1, Ordering::Relaxed);
                std::thread::sleep(Duration::from_millis(1));
            }
        }));
    }
    {
        let (b, stop, counts, ready, revoked) = (
            b.clone(),
            Arc::clone(&stop),
            Arc::clone(&counts),
            Arc::clone(&ready),
            Arc::clone(&revoked),
        );
        threads.push(std::thread::spawn(move || {
            let mut k = 0u64;
            while !stop.load(Ordering::Relaxed) {
                k += 1;
                // Revoking a request's session flags its connection too, so
                // each round has a connection of its own, from a /48 of its
                // own (so the door budgets never refuse the probe).
                let peer = IpAddr::from([0x2001, 0xdb8, (k & 0xffff) as u16, 0, 0, 0, 0, 1]);
                let conn = b.door(peer).unwrap();
                let mut req = conn.request(RequestId(u128::from(k))).unwrap();
                assert!(req.bind_session(session((1 << 40) | k)).is_pass());
                ready.store(k, Ordering::SeqCst);
                loop {
                    let done = revoked.load(Ordering::SeqCst) >= k;
                    let v = req.checkpoint();
                    if done {
                        if v.is_pass() {
                            counts.missed.fetch_add(1, Ordering::Relaxed);
                        }
                        break;
                    }
                    if stop.load(Ordering::Relaxed) {
                        return;
                    }
                    std::hint::spin_loop();
                }
            }
        }));
    }

    // Samples: one every interval, 24 over the run (at least a second).
    let interval = (run_for / 24).max(Duration::from_secs(1));
    let mut samples: Vec<isize> = Vec::new();
    let mut last_conns = 0u64;
    println!(
        "{:>8} {:>10} {:>9} {:>9} {:>9} {:>9} {:>10} {:>12}",
        "secs", "conn/s", "refused", "banned", "bans", "lifts", "revokes", "live heap"
    );
    while start.elapsed() < run_for {
        std::thread::sleep(interval);
        let conns = counts.connections.load(Ordering::Relaxed);
        let heap = LIVE_BYTES.load(Ordering::Relaxed);
        samples.push(heap);
        println!(
            "{:>8} {:>10} {:>9} {:>9} {:>9} {:>9} {:>10} {:>12}",
            start.elapsed().as_secs(),
            (conns - last_conns) / interval.as_secs().max(1),
            counts.refused.load(Ordering::Relaxed),
            counts.refused_banned.load(Ordering::Relaxed),
            counts.bans.load(Ordering::Relaxed),
            counts.lifts.load(Ordering::Relaxed),
            counts.revocations.load(Ordering::Relaxed),
            heap
        );
        last_conns = conns;
        // The budget tables run full with a million clients (idle slots
        // are reclaimed); tickets, revocations, and bans must not.
        let h = b.health();
        assert!(
            h.maintainer == MaintainerState::Parked || h.maintainer == MaintainerState::Running,
            "health: {h:?}"
        );
        assert!(h.tickets_live < h.tickets_capacity / 2, "health: {h:?}");
        assert!(h.revocation_load < 0.5 && h.ban_load < 0.5, "health: {h:?}");
    }
    stop.store(true, Ordering::Relaxed);
    for t in threads {
        t.join().unwrap();
    }

    assert_eq!(
        counts.missed.load(Ordering::Relaxed),
        0,
        "missed revocations"
    );
    assert!(counts.revocations.load(Ordering::Relaxed) > 0);
    // Flat memory: after the first quarter, no sample exceeds the warm
    // maximum by more than 5% plus 1 MiB. Warming takes about 11 minutes at
    // these rates: the ban table reaches its steady load of 30 seconds of
    // bans, and the sharing log and lift tombstones (65,536 records each)
    // fill.
    let warm = samples.len().div_ceil(4).max(1);
    let warm_max = samples[..warm].iter().copied().max().unwrap();
    let later_max = samples[warm..].iter().copied().max().unwrap_or(warm_max);
    let bound = warm_max + warm_max / 20 + (1 << 20);
    assert!(
        later_max <= bound,
        "live heap grew: warm {warm_max}, later {later_max}"
    );
}
