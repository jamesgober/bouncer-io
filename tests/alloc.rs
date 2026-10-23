//! No allocation on the door, checkpoint, request, and bind paths (NFR-7),
//! proven with a counting global allocator.
//!
//! Integration tests are separate crates, so `unsafe` is allowed here for the
//! allocator shim (dev/DIRECTIVES.md: test crates may inspect the allocator).

use std::{
    alloc::{GlobalAlloc, Layout, System},
    net::IpAddr,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

use bouncer_io::{Bouncer, Cidr, Provenance, RequestId};

struct Counting;

static COUNTING: AtomicBool = AtomicBool::new(false);
static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

// SAFETY: every call is forwarded unchanged to the system allocator; the
// shim only counts.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if COUNTING.load(Ordering::Relaxed) {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        // SAFETY: same contract as the caller's.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: same contract as the caller's.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if COUNTING.load(Ordering::Relaxed) {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        // SAFETY: same contract as the caller's.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

fn counted<T>(f: impl FnOnce() -> T) -> (T, usize) {
    ALLOCATIONS.store(0, Ordering::Relaxed);
    COUNTING.store(true, Ordering::Relaxed);
    let out = f();
    COUNTING.store(false, Ordering::Relaxed);
    (out, ALLOCATIONS.load(Ordering::Relaxed))
}

/// One test function, so no other test thread allocates while counting.
#[test]
fn test_hot_paths_do_not_allocate() {
    let proxy: Cidr = "10.0.0.1/32".parse().unwrap();
    let b = Bouncer::builder()
        .tickets(4096)
        .ban_capacity(4096)
        .trusted_proxies(&[proxy])
        .try_build()
        .unwrap();
    for i in 0..500u32 {
        b.ban(IpAddr::from((0xc633_6400 | i).to_be_bytes()))
            .unwrap();
    }
    b.ban("203.0.0.0/8".parse::<Cidr>().unwrap()).unwrap(); // the administrator set is in use
    let admitted: IpAddr = "192.0.2.9".parse().unwrap();
    let banned: IpAddr = "198.51.100.7".parse().unwrap();
    let admin_banned: IpAddr = "203.1.2.3".parse().unwrap();

    // Warm up the per-thread caches once.
    drop(b.door(admitted));
    drop(b.door(admin_banned));

    let ((), n) = counted(|| {
        for _ in 0..1000 {
            let conn = b.door(admitted).unwrap();
            let mut req = conn.request(RequestId(1)).unwrap();
            for _ in 0..10 {
                assert!(req.checkpoint().is_pass());
            }
            drop(req);
            drop(conn);
            assert!(b.door(banned).is_err());
            assert!(b.door(admin_banned).is_err());
        }
    });
    assert_eq!(n, 0, "door, request, checkpoint, and release allocated");

    let ((), n) = counted(|| {
        for _ in 0..100 {
            let hop = b.door("10.0.0.1".parse().unwrap()).unwrap();
            let mut req = hop.request(RequestId(2)).unwrap();
            assert!(
                req.bind_client(admitted, Provenance::ForwardedHeader)
                    .is_pass()
            );
            assert!(req.checkpoint().is_pass());
        }
    });
    assert_eq!(n, 0, "bind_client allocated");
}
