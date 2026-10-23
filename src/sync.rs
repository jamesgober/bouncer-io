//! Atomics, switched to loom's model-checked versions under `--cfg bouncer_loom`.
//!
//! Every lock-free primitive in the crate takes its atomics from here, so the
//! loom models exercise the same code that ships.

#[cfg(bouncer_loom)]
pub(crate) use loom::sync::atomic::{AtomicU32, AtomicU64, Ordering, fence};
#[cfg(not(bouncer_loom))]
pub(crate) use std::sync::atomic::{AtomicU32, AtomicU64, Ordering, fence};

/// Bounded spin used by readers that meet a writer mid-update. Writers hold a
/// slot for a handful of stores, so a few spins are enough; the bound keeps a
/// reader from waiting on a writer that was descheduled.
#[inline]
pub(crate) fn spin() {
    #[cfg(bouncer_loom)]
    loom::thread::yield_now();
    #[cfg(not(bouncer_loom))]
    std::hint::spin_loop();
}

/// Compare-and-swap loop: applies `f` to the current value until it stores or
/// `f` returns `None`. The standard `fetch_update` is being renamed upstream;
/// this keeps one spelling for every supported toolchain.
#[inline]
pub(crate) fn update(
    atomic: &AtomicU64,
    set: Ordering,
    fetch: Ordering,
    mut f: impl FnMut(u64) -> Option<u64>,
) -> Result<u64, u64> {
    let mut prev = atomic.load(fetch);
    while let Some(next) = f(prev) {
        match atomic.compare_exchange_weak(prev, next, set, fetch) {
            Ok(value) => return Ok(value),
            Err(actual) => prev = actual,
        }
    }
    Err(prev)
}
