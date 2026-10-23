//! The ticket registry: a fixed array of cells per shard, handed out from a
//! lock-free free list.
//!
//! The free list is a Treiber stack whose head packs `index (32) | tag (32)`.
//! The tag changes on every pop and push, so a stale head can never be
//! swapped back in (no ABA; loom model L-2).

use std::sync::Arc;

use crate::sync::{AtomicU32, AtomicU64, Ordering};

/// "No index": the end of a free-list chain, and "no parent".
pub(crate) const NIL: u32 = u32::MAX;

pub(crate) use crate::revoke::RevocationEpoch as Epoch;

/// Ticket kinds, in the low byte of the state word.
pub(crate) const KIND_CONNECTION: u64 = 1;
pub(crate) const KIND_REQUEST: u64 = 2;

/// Cell flags, bits 16..32 of the state word.
pub(crate) const F_LIVE: u64 = 1 << 16;
pub(crate) const F_REVOKED: u64 = 1 << 17;
pub(crate) const F_CANCELLED: u64 = 1 << 18;
pub(crate) const F_PENDING_CLIENT: u64 = 1 << 19;
pub(crate) const F_PROXY_HOP: u64 = 1 << 20;
pub(crate) const F_IMMUNE: u64 = 1 << 21;
pub(crate) const F_CLIENT_BOUND: u64 = 1 << 22;
/// The connection ticket is held by its tag, not by a handle.
pub(crate) const F_DETACHED: u64 = 1 << 23;
/// The connection holds door concurrency slots, returned on release.
pub(crate) const F_CHARGED: u64 = 1 << 27;
/// A request revoked by a revocation that keeps its connection open.
pub(crate) const F_KEEP_CONNECTION: u64 = 1 << 28;
/// Provenance, three bits at 24..27.
pub(crate) const PROVENANCE_SHIFT: u32 = 24;
pub(crate) const PROVENANCE_MASK: u64 = 0b111 << PROVENANCE_SHIFT;
/// Denial code of a revoked cell, bits 8..16.
pub(crate) const CODE_SHIFT: u32 = 8;

/// Present bits of the key words.
pub(crate) const P_SOURCE: u64 = 1;
pub(crate) const P_SOURCE_V6: u64 = 1 << 1;
pub(crate) const P_REQUEST: u64 = 1 << 2;
pub(crate) const P_SESSION: u64 = 1 << 3;
pub(crate) const P_ACCOUNT: u64 = 1 << 4;
pub(crate) const P_TENANT: u64 = 1 << 5;
pub(crate) const P_FINGERPRINT: u64 = 1 << 6;
pub(crate) const PRESENT_SHIFT: u32 = 56;
/// Low bits of `present_child`: a connection's latest live request, or [`NIL`].
pub(crate) const CHILD_MASK: u64 = 0xffff_ffff;

/// Key word positions.
pub(crate) const K_SOURCE: usize = 0;
pub(crate) const K_REQUEST: usize = 2;
pub(crate) const K_SESSION: usize = 4;
pub(crate) const K_ACCOUNT: usize = 6;
pub(crate) const K_TENANT: usize = 8;
pub(crate) const K_FINGERPRINT: usize = 9;

#[inline]
pub(crate) const fn generation(state: u64) -> u32 {
    (state >> 32) as u32
}

/// One ticket cell: two cache lines.
///
/// `link` is, for a request, the parent connection's index and generation;
/// for a connection, its own generation and the number of live requests.
/// `present_child` holds the present-key bitmap in the high 8 bits and, for a
/// connection, the index of its latest live request in the low 32.
#[repr(align(64))]
pub(crate) struct Cell {
    pub(crate) state: AtomicU64,
    pub(crate) link: AtomicU64,
    pub(crate) seen: AtomicU64,
    pub(crate) conn: AtomicU64,
    pub(crate) present_child: AtomicU64,
    pub(crate) keys: [AtomicU64; 11],
}

impl Cell {
    pub(crate) fn new() -> Self {
        Cell {
            // Generation 1: a tag or id with generation 0 is never valid.
            state: AtomicU64::new(1u64 << 32),
            link: AtomicU64::new(0),
            seen: AtomicU64::new(0),
            conn: AtomicU64::new(0),
            present_child: AtomicU64::new(CHILD_MASK),
            keys: core::array::from_fn(|_| AtomicU64::new(0)),
        }
    }

    pub(crate) fn present(&self) -> u64 {
        self.present_child.load(Ordering::Acquire) >> PRESENT_SHIFT
    }
}

/// The free list of one shard: a range of global cell indices.
pub(crate) struct FreeList {
    head: AtomicU64,
    start: u32,
    next: Box<[AtomicU32]>,
}

impl FreeList {
    /// A list holding every index `start..start + n`.
    pub(crate) fn range(start: u32, n: u32) -> Self {
        let next = (0..n)
            .map(|i| AtomicU32::new(if i + 1 < n { start + i + 1 } else { NIL }))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let first = if n > 0 { start } else { NIL };
        FreeList {
            head: AtomicU64::new(u64::from(first)),
            start,
            next,
        }
    }

    #[cfg(test)]
    pub(crate) fn full(n: u32) -> Self {
        Self::range(0, n)
    }

    #[inline]
    pub(crate) fn pop(&self) -> Option<u32> {
        let mut head = self.head.load(Ordering::Acquire);
        loop {
            let index = head as u32;
            if index == NIL {
                return None;
            }
            let next = self.next[(index - self.start) as usize].load(Ordering::Relaxed);
            let tag = (head >> 32).wrapping_add(1);
            match self.head.compare_exchange_weak(
                head,
                (tag << 32) | u64::from(next),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(index),
                Err(actual) => head = actual,
            }
        }
    }

    #[inline]
    pub(crate) fn push(&self, index: u32) {
        let mut head = self.head.load(Ordering::Relaxed);
        loop {
            self.next[(index - self.start) as usize].store(head as u32, Ordering::Relaxed);
            let tag = (head >> 32).wrapping_add(1);
            match self.head.compare_exchange_weak(
                head,
                (tag << 32) | u64::from(index),
                Ordering::Release,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(actual) => head = actual,
            }
        }
    }
}

/// Every cell of the bouncer, partitioned into shards by index range, each
/// range with its own free list. Any ticket can reach any cell, so a request
/// can take a cell from another shard when its connection's shard is full.
pub(crate) struct Registry {
    pub(crate) cells: Box<[Cell]>,
    pub(crate) free: Box<[FreeList]>,
    pub(crate) next_conn: Box<[AtomicU64]>,
    per_shard: u32,
}

impl Registry {
    pub(crate) fn new(shards: u32, per_shard: u32) -> Self {
        let total = shards * per_shard;
        Registry {
            cells: (0..total)
                .map(|_| Cell::new())
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            free: (0..shards)
                .map(|s| FreeList::range(s * per_shard, per_shard))
                .collect(),
            next_conn: (0..shards).map(|_| AtomicU64::new(0)).collect(),
            per_shard,
        }
    }

    #[inline]
    pub(crate) fn cell(&self, index: u32) -> &Cell {
        &self.cells[index as usize]
    }

    /// Takes a free cell, starting with shard `first`, then the others.
    pub(crate) fn pop_from(&self, first: usize) -> Option<u32> {
        let n = self.free.len();
        (0..n).find_map(|step| self.free[(first + step) % n].pop())
    }

    /// Returns a cell to the free list of the shard that owns it.
    pub(crate) fn push(&self, index: u32) {
        self.free[(index / self.per_shard) as usize].push(index);
    }

    /// The shard that owns a cell.
    pub(crate) fn shard_of(&self, index: u32) -> usize {
        (index / self.per_shard) as usize
    }

    /// Bytes reserved by the cells and the free lists.
    pub(crate) fn bytes(&self) -> u64 {
        (self.cells.len() * (core::mem::size_of::<Cell>() + 4)) as u64
    }
}

/// A shard handle. Tickets hold one through an `Arc`, so reference-count
/// traffic is spread over shards instead of one shared line.
pub(crate) struct Shard {
    pub(crate) id: u8,
    pub(crate) epoch: Arc<Epoch>,
    pub(crate) shared: Arc<crate::bouncer::Shared>,
}

impl Shard {
    #[inline]
    pub(crate) fn cell(&self, index: u32) -> &Cell {
        self.shared.registry.cell(index)
    }
}

#[cfg(all(test, not(bouncer_loom)))]
mod tests {
    use super::*;

    #[test]
    fn test_cell_is_two_cache_lines() {
        assert_eq!(core::mem::size_of::<Cell>(), 128);
        assert_eq!(core::mem::align_of::<Cell>(), 64);
    }

    #[test]
    fn test_free_list_pops_every_index_once() {
        let f = FreeList::full(5);
        let mut got: Vec<u32> = (0..5).filter_map(|_| f.pop()).collect();
        assert_eq!(f.pop(), None);
        got.sort_unstable();
        assert_eq!(got, [0, 1, 2, 3, 4]);
        f.push(3);
        assert_eq!(f.pop(), Some(3));
        assert_eq!(FreeList::full(0).pop(), None);
    }

    #[test]
    fn test_free_list_concurrent_no_double_handout() {
        let f = Arc::new(FreeList::full(64));
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let f = Arc::clone(&f);
                std::thread::spawn(move || {
                    let mut mine = Vec::new();
                    for _ in 0..10_000 {
                        if let Some(i) = f.pop() {
                            mine.push(i);
                        }
                        if mine.len() > 4 {
                            f.push(mine.remove(0));
                        }
                    }
                    mine
                })
            })
            .collect();
        let mut held: Vec<u32> = handles
            .into_iter()
            .flat_map(|h| h.join().unwrap())
            .collect();
        while let Some(i) = f.pop() {
            held.push(i);
        }
        held.sort_unstable();
        assert_eq!(held, (0..64).collect::<Vec<_>>());
    }
}

#[cfg(all(test, bouncer_loom))]
mod loom_tests {
    use super::*;

    /// L-2: two threads popping and pushing on one free list never hold the
    /// same index at once, and no index is lost.
    #[test]
    fn loom_free_list_no_double_handout_no_aba() {
        loom::model(|| {
            let f = Arc::new(FreeList::full(2));
            let t: Vec<_> = (0..2)
                .map(|_| {
                    let f = Arc::clone(&f);
                    loom::thread::spawn(move || {
                        let a = f.pop();
                        if let Some(a) = a {
                            f.push(a);
                        }
                        f.pop()
                    })
                })
                .collect();
            let got: Vec<u32> = t.into_iter().filter_map(|h| h.join().unwrap()).collect();
            if got.len() == 2 {
                assert_ne!(got[0], got[1]);
            }
            let mut all = got.clone();
            while let Some(i) = f.pop() {
                all.push(i);
            }
            all.sort_unstable();
            assert_eq!(all, [0, 1]);
        });
    }
}
