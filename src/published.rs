//! A value read on hot paths and replaced whole: the allow list.
//!
//! Readers keep a per-thread copy of the `Arc` and check one version word, so
//! a read is one atomic load and a thread-local access; only the first read
//! after a replacement takes the lock. Writers swap the value under the lock
//! and then move the version, so a reader that sees the new version reads
//! the new value.

use core::{any::Any, cell::RefCell};
use std::sync::{
    Arc, RwLock,
    atomic::{AtomicU64, Ordering},
};

/// Cached values per thread: enough for every `Published` a thread reads in
/// one call chain of a few bouncers; others fall back to the lock.
const SLOTS: usize = 4;

type Slot = Option<(u64, u64, Arc<dyn Any + Send + Sync>)>;

thread_local! {
    static CACHE: RefCell<[Slot; SLOTS]> = const { RefCell::new([None, None, None, None]) };
}

static NEXT_UID: AtomicU64 = AtomicU64::new(1);

/// A value replaced whole, read without waiting.
pub(crate) struct Published<T> {
    uid: u64,
    version: AtomicU64,
    value: RwLock<Arc<T>>,
}

impl<T: Send + Sync + 'static> Published<T> {
    pub(crate) fn new(value: T) -> Published<T> {
        Published {
            uid: NEXT_UID.fetch_add(1, Ordering::Relaxed),
            version: AtomicU64::new(0),
            value: RwLock::new(Arc::new(value)),
        }
    }

    /// The current value (takes the read lock; for cold paths).
    pub(crate) fn load(&self) -> Arc<T> {
        Arc::clone(
            &self
                .value
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    /// Replaces the value. Readers on every thread see it at their next
    /// read.
    pub(crate) fn store(&self, value: T) {
        let mut slot = self
            .value
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *slot = Arc::new(value);
        self.version.fetch_add(1, Ordering::Release);
    }

    /// Runs `f` on the current value through the per-thread copy.
    #[inline]
    pub(crate) fn with<R>(&self, f: impl FnOnce(&T) -> R) -> R {
        let version = self.version.load(Ordering::Acquire);
        let mut f = Some(f);
        let cached = CACHE
            .try_with(|cell| {
                let mut slots = cell.try_borrow_mut().ok()?;
                let hit = slots.iter().position(
                    |s| matches!(s, Some((uid, v, _)) if *uid == self.uid && *v == version),
                );
                let i = match hit {
                    Some(i) => i,
                    None => {
                        let i = slots
                            .iter()
                            .position(|s| s.as_ref().is_none_or(|(uid, _, _)| *uid == self.uid))
                            .unwrap_or((self.uid as usize) % SLOTS);
                        let value: Arc<dyn Any + Send + Sync> = self.load();
                        slots[i] = Some((self.uid, version, value));
                        i
                    }
                };
                let value = slots[i].as_ref()?.2.downcast_ref::<T>()?;
                f.take().map(|f| f(value))
            })
            .ok()
            .flatten();
        match cached {
            Some(r) => r,
            None => {
                let value = self.load();
                match f.take() {
                    Some(f) => f(&value),
                    None => unreachable!("the closure runs at most once"),
                }
            }
        }
    }
}

#[cfg(all(test, not(bouncer_loom)))]
mod tests {
    use super::*;

    #[test]
    fn test_published_reads_follow_replacement() {
        let p = Published::new(1u32);
        assert_eq!(p.with(|v| *v), 1);
        p.store(2);
        assert_eq!(p.with(|v| *v), 2);
        let q = Published::new(String::from("a"));
        // Two cells on one thread do not disturb each other.
        assert_eq!(q.with(|s| s.clone()), "a");
        assert_eq!(p.with(|v| *v), 2);
        // Nested reads fall back to the lock.
        assert_eq!(p.with(|a| q.with(|s| format!("{a}{s}"))), "2a");
    }

    #[test]
    fn test_published_other_thread_sees_replacement() {
        let p = Arc::new(Published::new(5u64));
        assert_eq!(p.with(|v| *v), 5);
        let p2 = Arc::clone(&p);
        std::thread::spawn(move || p2.store(6)).join().unwrap();
        assert_eq!(p.with(|v| *v), 6);
    }
}
