//! The dynamic ban table: open addressing with linear probing, one slot per
//! entry, read without locks.
//!
//! Each slot is a small sequence lock: a writer makes the version odd, writes
//! the words, and makes it even again; a reader reads the version, the words,
//! and the version again, and keeps the read only if both versions are the
//! same even number. Writers are serialized by the caller (the ban writer
//! lock), so a reader never waits on more than one slot write (loom model L-3).
//!
//! Every key kind and prefix length shares the one table; the kind and length
//! are part of the key. A lookup probes once per length in use.

use crate::{
    directive::{ActorKind, Reason},
    hash::HashKey,
    sync::{AtomicU64, Ordering, fence, spin},
};

/// The keyed hash of a table key.
#[inline]
pub(crate) fn hash_key(key: &HashKey, k: &TableKey) -> u64 {
    let meta = u64::from(k.kind) | (u64::from(k.len) << 8);
    // A prefix key has one word that is always zero (IPv4 bits live in
    // `k1`; an IPv6 prefix of /64 or shorter in `k0`): two words suffice.
    // The kind and length in `meta` keep the classes apart.
    match k.kind {
        KIND_V4 => key.mix2(meta, k.k1),
        KIND_V6 if k.len <= 64 => key.mix2(meta, k.k0),
        _ => key.mix3(meta, k.k0, k.k1),
    }
}

/// Slot kinds stored in the low byte of the meta word.
pub(crate) const KIND_TOMBSTONE: u8 = 1;
pub(crate) const KIND_V4: u8 = 2;
pub(crate) const KIND_V6: u8 = 3;
pub(crate) const KIND_SESSION: u8 = 4;
pub(crate) const KIND_ACCOUNT: u8 = 5;
pub(crate) const KIND_TENANT: u8 = 6;
pub(crate) const KIND_FINGERPRINT: u8 = 7;
pub(crate) const KIND_FINGERPRINT_IN: u8 = 8;
/// Revocation table kinds: a connection id, a request id.
pub(crate) const KIND_CONNECTION: u8 = 9;
pub(crate) const KIND_REQUEST: u8 = 10;

/// Entry flag: evictable (a local heuristic's timed ban).
pub(crate) const FLAG_EVICTABLE: u8 = 1;

/// How many groups of eight slots a probe sequence may visit.
pub(crate) const MAX_PROBE: usize = crate::MAX_PROBE as usize;

/// Spins a reader allows a writer that holds a slot before it gives up.
#[cfg(not(bouncer_loom))]
const READ_SPINS: u32 = 256;
#[cfg(bouncer_loom)]
const READ_SPINS: u32 = 2;

/// A table key: kind, prefix length (0 for identity kinds), and 128 bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct TableKey {
    pub(crate) kind: u8,
    pub(crate) len: u8,
    pub(crate) k0: u64,
    pub(crate) k1: u64,
}

/// One stored ban.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Entry {
    pub(crate) key: TableKey,
    pub(crate) flags: u8,
    pub(crate) actor: ActorKind,
    pub(crate) reason: Reason,
    pub(crate) offences: u16,
    /// Seconds since the bouncer started at which the ban ends; 0 = permanent.
    pub(crate) until: u32,
    /// Seconds since the bouncer started at which it was issued.
    pub(crate) issued: u32,
    pub(crate) id: u64,
}

impl Entry {
    #[inline]
    pub(crate) fn expired(&self, now_secs: u64) -> bool {
        self.until != 0 && u64::from(self.until) <= now_secs
    }

    pub(crate) fn evictable(&self) -> bool {
        self.flags & FLAG_EVICTABLE != 0
    }
}

struct Slot {
    version: AtomicU64,
    meta: AtomicU64,
    k0: AtomicU64,
    k1: AtomicU64,
    times: AtomicU64,
    id: AtomicU64,
}

#[derive(Clone, Copy)]
struct Raw {
    meta: u64,
    k0: u64,
    k1: u64,
    times: u64,
    id: u64,
}

impl Raw {
    const fn kind(&self) -> u8 {
        self.meta as u8
    }

    fn key(&self) -> TableKey {
        TableKey {
            kind: self.kind(),
            len: (self.meta >> 8) as u8,
            k0: self.k0,
            k1: self.k1,
        }
    }

    fn entry(&self) -> Entry {
        Entry {
            key: self.key(),
            flags: (self.meta >> 16) as u8,
            actor: ActorKind::from_code((self.meta >> 24) as u8),
            reason: Reason::from_code((self.meta >> 32) as u16),
            offences: (self.meta >> 48) as u16,
            until: (self.times >> 32) as u32,
            issued: self.times as u32,
            id: self.id,
        }
    }

    fn from_entry(e: &Entry) -> Raw {
        let meta = u64::from(e.key.kind)
            | (u64::from(e.key.len) << 8)
            | (u64::from(e.flags) << 16)
            | (u64::from(e.actor.code()) << 24)
            | (u64::from(e.reason.code()) << 32)
            | (u64::from(e.offences) << 48);
        Raw {
            meta,
            k0: e.key.k0,
            k1: e.key.k1,
            times: (u64::from(e.until) << 32) | u64::from(e.issued),
            id: e.id,
        }
    }

    const fn tombstone() -> Raw {
        Raw {
            meta: KIND_TOMBSTONE as u64,
            k0: 0,
            k1: 0,
            times: 0,
            id: 0,
        }
    }
}

impl Slot {
    fn new() -> Self {
        Slot {
            version: AtomicU64::new(0),
            meta: AtomicU64::new(0),
            k0: AtomicU64::new(0),
            k1: AtomicU64::new(0),
            times: AtomicU64::new(0),
            id: AtomicU64::new(0),
        }
    }

    /// A consistent snapshot, or `None` when a writer held the slot for longer
    /// than the spin bound.
    #[inline]
    fn read(&self) -> Option<Raw> {
        for _ in 0..READ_SPINS {
            let v1 = self.version.load(Ordering::Acquire);
            if v1 & 1 == 0 {
                let raw = Raw {
                    meta: self.meta.load(Ordering::Relaxed),
                    k0: self.k0.load(Ordering::Relaxed),
                    k1: self.k1.load(Ordering::Relaxed),
                    times: self.times.load(Ordering::Relaxed),
                    id: self.id.load(Ordering::Relaxed),
                };
                fence(Ordering::Acquire);
                if self.version.load(Ordering::Relaxed) == v1 {
                    return Some(raw);
                }
            }
            spin();
        }
        None
    }

    /// The writer's view: no other writer exists, so plain loads are exact.
    fn read_owned(&self) -> Raw {
        Raw {
            meta: self.meta.load(Ordering::Relaxed),
            k0: self.k0.load(Ordering::Relaxed),
            k1: self.k1.load(Ordering::Relaxed),
            times: self.times.load(Ordering::Relaxed),
            id: self.id.load(Ordering::Relaxed),
        }
    }

    /// Replaces the slot. Callers hold the table's writer lock.
    fn write(&self, raw: &Raw) {
        let v = self.version.load(Ordering::Relaxed);
        self.version.store(v.wrapping_add(1), Ordering::Relaxed);
        fence(Ordering::Release);
        self.meta.store(raw.meta, Ordering::Relaxed);
        self.k0.store(raw.k0, Ordering::Relaxed);
        self.k1.store(raw.k1, Ordering::Relaxed);
        self.times.store(raw.times, Ordering::Relaxed);
        self.id.store(raw.id, Ordering::Relaxed);
        self.version.store(v.wrapping_add(2), Ordering::Release);
    }
}

/// The result of a read-side lookup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Probe {
    Hit(Entry),
    Miss,
    /// A slot on the probe path was being rewritten for longer than the spin
    /// bound. The caller fails closed.
    Busy,
}

/// The result of an insert.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Inserted {
    /// A new entry. `removed` is an entry taken out to make room: an expired
    /// one (`evicted` false) or the earliest evictable one (`evicted` true).
    New {
        removed: Option<Entry>,
        evicted: bool,
    },
    /// The key was already present (possibly expired): merged in place.
    Merged { previous: Entry },
}

/// Tag byte of an empty slot. A probe stops at a group holding one.
const TAG_EMPTY: u8 = 0x80;
/// Tag byte of a removed slot. Probes continue past it.
const TAG_DELETED: u8 = 0xfe;
/// Eight empty tags.
const TAGS_EMPTY: u64 = 0x8080_8080_8080_8080;
/// Slots per group: one tag word.
const GROUP: usize = 8;

/// The table. Readers call [`Table::find`]; every other method needs the
/// writer lock, which the owner holds.
///
/// Slots are grouped by eight, and each group has one tag word: a byte per
/// slot holding seven bits of the key's hash, or empty, or deleted. A lookup
/// reads the group's tag word and only the slots whose tag matches, so a miss
/// costs a few tag-word loads from one contiguous array. Probing moves group
/// by group, at most [`MAX_PROBE`] groups.
pub(crate) struct Table {
    slots: Box<[Slot]>,
    tags: Box<[AtomicU64]>,
    key: HashKey,
    capacity: u32,
    /// The anchor lengths (IPv4, IPv6): an address key at this length or
    /// longer lives in the probe sequence of its prefix at this length, so
    /// one group holds every automatic length of an address (D-104).
    anchors: (Option<u8>, Option<u8>),
    /// One bit per group: some key anchored here did not fit its anchor's
    /// probe sequence and lives in its own (a crowded prefix).
    overflow: Box<[AtomicU64]>,
}

/// Where a key lives: its home group (its anchor's, or its own), its own
/// group, its tag, and whether it is anchored elsewhere.
#[derive(Clone, Copy, Debug)]
struct Spot {
    home: usize,
    own: usize,
    tag: u8,
    anchored: bool,
}

/// Writer-side bookkeeping, kept inside the owner's writer lock.
#[derive(Debug)]
pub(crate) struct TableWriter {
    live: u32,
    hand: usize,
    /// Keys for reseeds.
    rng: crate::hash::Rng,
}

impl Default for TableWriter {
    fn default() -> Self {
        TableWriter::new(0x5eed)
    }
}

impl TableWriter {
    pub(crate) fn new(seed: u64) -> TableWriter {
        TableWriter {
            live: 0,
            hand: 0,
            rng: crate::hash::Rng::from_seed(seed),
        }
    }

    /// Live entries, expired ones not yet reclaimed included.
    pub(crate) fn live(&self) -> u32 {
        self.live
    }
}

/// Why an insert found no room.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NoRoom {
    /// Every entry is one the table may not evict.
    Full,
    /// The key's probe sequence is full although the table is not: keys
    /// that collide under this hash key (T-9). A reseed makes room.
    ProbeBound,
}

#[inline]
fn tag_at(word: u64, i: usize) -> u8 {
    (word >> (8 * i)) as u8
}

const LOW_BITS: u64 = 0x0101_0101_0101_0101;
const HIGH_BITS: u64 = 0x8080_8080_8080_8080;

/// Bytes of `word` equal to `tag`, as a mask with the high bit of each
/// matching byte set. May also flag a byte right after a true match; callers
/// confirm every candidate by comparing the full key.
#[inline]
fn match_tag(word: u64, tag: u8) -> u64 {
    let x = word ^ (LOW_BITS * u64::from(tag));
    x.wrapping_sub(LOW_BITS) & !x & HIGH_BITS
}

/// `true` when some tag in `word` is empty. Empty (0x80) is the only tag
/// with bit 7 set and bit 6 clear (deleted is 0xfe, hash tags are below 0x80).
#[inline]
fn has_empty(word: u64) -> bool {
    word & !(word << 1) & HIGH_BITS != 0
}

impl Table {
    /// A table for `capacity` entries at a load of at most 7/8, address keys
    /// anchored at the given lengths.
    pub(crate) fn with_anchors(
        capacity: u32,
        key: HashKey,
        anchors: (Option<u8>, Option<u8>),
    ) -> Table {
        Table {
            anchors,
            ..Table::new(capacity, key)
        }
    }

    /// The anchor lengths.
    pub(crate) fn anchors(&self) -> (Option<u8>, Option<u8>) {
        self.anchors
    }

    /// A table for `capacity` entries at a load of at most 7/8.
    pub(crate) fn new(capacity: u32, key: HashKey) -> Table {
        let wanted = (u64::from(capacity) * 8)
            .div_ceil(7)
            .max(u64::from(capacity) + 1);
        let groups = usize::try_from(wanted.div_ceil(GROUP as u64))
            .unwrap_or(usize::MAX / GROUP)
            .max(2);
        let slots = (0..groups * GROUP)
            .map(|_| Slot::new())
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let tags = (0..groups)
            .map(|_| AtomicU64::new(TAGS_EMPTY))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let overflow = (0..groups.div_ceil(64))
            .map(|_| AtomicU64::new(0))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Table {
            slots,
            tags,
            key,
            capacity,
            anchors: (None, None),
            overflow,
        }
    }

    /// The prefix an address key is anchored at, when it is longer than its
    /// family's anchor length.
    fn anchor_of(&self, k: &TableKey) -> Option<TableKey> {
        let (a, width) = match k.kind {
            KIND_V4 => (self.anchors.0?, 32u32),
            KIND_V6 => (self.anchors.1?, 128u32),
            _ => return None,
        };
        if k.len <= a {
            return None;
        }
        let bits = (u128::from(k.k0) << 64) | u128::from(k.k1);
        let keep = if a == 0 {
            0
        } else {
            let all = if width == 32 {
                u128::from(u32::MAX)
            } else {
                u128::MAX
            };
            (u128::MAX << (width - u32::from(a))) & all
        };
        let m = bits & keep;
        Some(TableKey {
            kind: k.kind,
            len: a,
            k0: (m >> 64) as u64,
            k1: m as u64,
        })
    }

    #[inline]
    fn spot(&self, k: &TableKey) -> Spot {
        let (own, tag) = self.locate(k);
        match self.anchor_of(k) {
            Some(a) => Spot {
                home: self.locate(&a).0,
                own,
                tag,
                anchored: true,
            },
            None => Spot {
                home: own,
                own,
                tag,
                anchored: false,
            },
        }
    }

    /// Whether some key anchored at `group` lives in its own sequence.
    #[inline]
    pub(crate) fn overflowed(&self, group: usize) -> bool {
        self.overflow[group / 64].load(Ordering::Acquire) & (1u64 << (group % 64)) != 0
    }

    fn mark_overflow(&self, group: usize) {
        self.overflow[group / 64].fetch_or(1u64 << (group % 64), Ordering::Release);
    }

    pub(crate) fn capacity(&self) -> u32 {
        self.capacity
    }

    /// Bytes reserved by the slots and tags.
    pub(crate) fn bytes(&self) -> u64 {
        (self.slots.len() * core::mem::size_of::<Slot>() + self.tags.len() * 8) as u64
    }

    /// Starting group and tag byte for a key.
    #[inline]
    pub(crate) fn locate(&self, key: &TableKey) -> (usize, u8) {
        self.locate_hash(hash_key(&self.key, key))
    }

    /// The group and tag of a key whose hash is already known.
    #[inline]
    pub(crate) fn locate_hash(&self, h: u64) -> (usize, u8) {
        let group = ((u128::from(h) * self.tags.len() as u128) >> 64) as usize;
        (group, (h & 0x7f) as u8)
    }

    /// The table's hash key (shared with the door budgets, so one hash of a
    /// prefix serves both).
    pub(crate) fn hasher(&self) -> HashKey {
        self.key
    }

    /// The probe sequence: triangular steps over groups (g, g+1, g+3, g+6, ...),
    /// which avoids the clustering of linear probing at high load.
    #[inline]
    fn next_group(&self, g: usize, step: usize) -> usize {
        (g + step) % self.tags.len()
    }

    /// Sets one tag byte. Only the writer changes tags.
    fn set_tag(&self, slot: usize, tag: u8) {
        let word = &self.tags[slot / GROUP];
        let shift = 8 * (slot % GROUP);
        let old = word.load(Ordering::Relaxed);
        word.store(
            (old & !(0xff << shift)) | (u64::from(tag) << shift),
            Ordering::Release,
        );
    }

    /// Lock-free lookup of a live (not expired) entry.
    #[inline]
    pub(crate) fn find(&self, key: &TableKey, now_secs: u64) -> Probe {
        let s = self.spot(key);
        let tags = self.first_tags(s.home);
        match self.find_at(key, s.home, s.tag, tags, now_secs) {
            Probe::Miss if s.anchored && self.overflowed(s.home) => {
                self.find_at(key, s.own, s.tag, self.first_tags(s.own), now_secs)
            }
            found => found,
        }
    }

    /// The tag word of a key's first group: callers that probe several keys
    /// load every first tag word before comparing any, so the cache misses
    /// overlap.
    #[inline]
    pub(crate) fn first_tags(&self, group: usize) -> u64 {
        self.tags[group].load(Ordering::Acquire)
    }

    /// Continues a lookup whose first tag word is already loaded.
    #[inline]
    pub(crate) fn find_at(
        &self,
        key: &TableKey,
        mut g: usize,
        h2: u8,
        mut tags: u64,
        now_secs: u64,
    ) -> Probe {
        for step in 1..=MAX_PROBE {
            let mut candidates = match_tag(tags, h2);
            while candidates != 0 {
                let i = (candidates.trailing_zeros() / 8) as usize;
                candidates &= candidates - 1;
                if tag_at(tags, i) != h2 {
                    continue;
                }
                let Some(raw) = self.slots[g * GROUP + i].read() else {
                    return Probe::Busy;
                };
                if raw.kind() >= KIND_V4 && raw.key() == *key {
                    let e = raw.entry();
                    return if e.expired(now_secs) {
                        Probe::Miss
                    } else {
                        Probe::Hit(e)
                    };
                }
            }
            if has_empty(tags) {
                return Probe::Miss;
            }
            g = self.next_group(g, step);
            tags = self.tags[g].load(Ordering::Acquire);
        }
        Probe::Miss
    }

    /// The slot holding `key` (expired or not), for the writer.
    fn position(&self, key: &TableKey) -> Option<(usize, Raw)> {
        let s = self.spot(key);
        self.position_from(key, s.home, s.tag).or_else(|| {
            (s.anchored && self.overflowed(s.home))
                .then(|| self.position_from(key, s.own, s.tag))
                .flatten()
        })
    }

    fn position_from(&self, key: &TableKey, start: usize, h2: u8) -> Option<(usize, Raw)> {
        let mut g = start;
        for step in 1..=MAX_PROBE {
            let tags = self.tags[g].load(Ordering::Relaxed);
            for i in 0..GROUP {
                if tag_at(tags, i) == h2 {
                    let raw = self.slots[g * GROUP + i].read_owned();
                    if raw.kind() >= KIND_V4 && raw.key() == *key {
                        return Some((g * GROUP + i, raw));
                    }
                }
            }
            if has_empty(tags) {
                return None;
            }
            g = self.next_group(g, step);
        }
        None
    }

    fn store(&self, slot: usize, entry: &Entry, h2: u8) {
        self.slots[slot].write(&Raw::from_entry(entry));
        self.set_tag(slot, h2);
    }

    fn clear(&self, slot: usize) {
        self.set_tag(slot, TAG_DELETED);
        self.slots[slot].write(&Raw::tombstone());
    }

    /// Inserts or merges. `merge` builds the stored entry from the previous
    /// one when the key is already present.
    ///
    /// Eviction order when there is no room: expired entries, then the
    /// evictable entry with the earliest end within a bounded scan. Entries
    /// that are not evictable are never removed; then the insert fails.
    pub(crate) fn insert(
        &self,
        w: &mut TableWriter,
        entry: Entry,
        now_secs: u64,
        merge: impl FnOnce(&Entry) -> Entry,
    ) -> Result<Inserted, NoRoom> {
        let s = self.spot(&entry.key);
        let h2 = s.tag;
        if let Some((slot, raw)) = self.position(&entry.key) {
            let previous = raw.entry();
            self.store(slot, &merge(&previous), h2);
            return Ok(Inserted::Merged { previous });
        }
        // The first reusable slot on the home probe path: empty, deleted, or
        // expired; for an anchored key whose anchor's path is full, one on
        // its own path (and the anchor's group is marked).
        let (mut free, mut window_victim) = self.scan(s.home, now_secs);
        if free.is_none() && s.anchored {
            let (own_free, _) = self.scan(s.own, now_secs);
            if own_free.is_some() {
                self.mark_overflow(s.home);
                free = own_free;
                window_victim = None;
            }
        }

        let (slot, removed, evicted) = match free {
            // Replaces an expired entry; the live count is unchanged.
            Some((slot, Some(expired))) => (slot, Some(expired), false),
            Some((slot, None)) => {
                let mut removed = None;
                let mut evicted = false;
                if w.live >= self.capacity {
                    let (e, was_evicted) = self.make_room(w, now_secs).ok_or(NoRoom::Full)?;
                    removed = Some(e);
                    evicted = was_evicted;
                }
                w.live += 1;
                (slot, removed, evicted)
            }
            None => match window_victim {
                Some((slot, victim)) => (slot, Some(victim), true),
                None if w.live < self.capacity => return Err(NoRoom::ProbeBound),
                None => return Err(NoRoom::Full),
            },
        };
        self.store(slot, &entry, h2);
        Ok(Inserted::New { removed, evicted })
    }

    /// The first reusable slot on the probe path from `start`, and the
    /// evictable entry with the earliest end seen on the way.
    #[allow(clippy::type_complexity)]
    fn scan(
        &self,
        start: usize,
        now_secs: u64,
    ) -> (Option<(usize, Option<Entry>)>, Option<(usize, Entry)>) {
        let mut window_victim: Option<(usize, Entry)> = None;
        let mut g = start;
        for step in 1..=MAX_PROBE {
            let tags = self.tags[g].load(Ordering::Relaxed);
            for i in 0..GROUP {
                let slot = g * GROUP + i;
                let tag = tag_at(tags, i);
                if tag == TAG_EMPTY || tag == TAG_DELETED {
                    return (Some((slot, None)), window_victim);
                }
                let raw = self.slots[slot].read_owned();
                if raw.kind() < KIND_V4 {
                    return (Some((slot, None)), window_victim);
                }
                let e = raw.entry();
                if e.expired(now_secs) {
                    return (Some((slot, Some(e))), window_victim);
                }
                if e.evictable() && window_victim.is_none_or(|(_, v)| earlier(&e, &v)) {
                    window_victim = Some((slot, e));
                }
            }
            g = self.next_group(g, step);
        }
        (None, window_victim)
    }

    /// Frees one entry somewhere in the table (bounded scan from the clock
    /// hand): an expired entry, else the evictable entry with the earliest
    /// end. Returns the entry removed and whether it was evicted (not
    /// expired); `None` means no room can be made.
    fn make_room(&self, w: &mut TableWriter, now_secs: u64) -> Option<(Entry, bool)> {
        let n = self.slots.len();
        let mut victim: Option<(usize, Entry)> = None;
        for _ in 0..(MAX_PROBE * GROUP).min(n) {
            let i = w.hand;
            w.hand = if w.hand + 1 == n { 0 } else { w.hand + 1 };
            let raw = self.slots[i].read_owned();
            if raw.kind() < KIND_V4 {
                continue;
            }
            let e = raw.entry();
            if e.expired(now_secs) {
                self.clear(i);
                w.live -= 1;
                return Some((e, false));
            }
            if e.evictable() && victim.is_none_or(|(_, v)| earlier(&e, &v)) {
                victim = Some((i, e));
            }
        }
        let (i, e) = victim?;
        self.clear(i);
        w.live -= 1;
        Some((e, true))
    }

    /// Removes the entry under `key`, expired or not.
    pub(crate) fn remove(&self, w: &mut TableWriter, key: &TableKey) -> Option<Entry> {
        let (slot, raw) = self.position(key)?;
        self.clear(slot);
        w.live -= 1;
        Some(raw.entry())
    }

    /// Removes every entry for which `remove` returns `true`; returns them.
    /// A full scan, for maintenance only.
    pub(crate) fn remove_where(
        &self,
        w: &mut TableWriter,
        mut remove: impl FnMut(&Entry) -> bool,
    ) -> Vec<Entry> {
        let mut out = Vec::new();
        for slot in 0..self.slots.len() {
            let raw = self.slots[slot].read_owned();
            if raw.kind() < KIND_V4 {
                continue;
            }
            let e = raw.entry();
            if remove(&e) {
                self.clear(slot);
                w.live -= 1;
                out.push(e);
            }
        }
        out
    }

    /// Calls `f` on every stored entry, expired or not. A full scan, for
    /// administration and persistence; the caller holds the writer lock.
    pub(crate) fn for_each(&self, mut f: impl FnMut(&Entry)) {
        for slot in self.slots.iter() {
            let raw = slot.read_owned();
            if raw.kind() >= KIND_V4 {
                f(&raw.entry());
            }
        }
    }

    /// The entry under `key` for the writer, expired or not.
    pub(crate) fn get_owned(&self, key: &TableKey) -> Option<Entry> {
        self.position(key).map(|(_, raw)| raw.entry())
    }
}

/// The ban table behind a handle that can be replaced whole: readers keep a
/// per-thread copy of the current table and check one version word, so a
/// read never waits; the writer (under the owner's writer lock) replaces the
/// table when an insert reaches the probe bound, rebuilt under a fresh hash
/// key (T-9). A replaced table is freed once every thread has moved on.
pub(crate) struct Tables {
    uid: u64,
    version: AtomicU64Std,
    current: std::sync::RwLock<std::sync::Arc<Table>>,
    reseeds: AtomicU64Std,
}

type AtomicU64Std = std::sync::atomic::AtomicU64;

type CachedTable = Option<(u64, u64, std::sync::Arc<Table>)>;

std::thread_local! {
    static CURRENT: core::cell::RefCell<CachedTable> = const { core::cell::RefCell::new(None) };
}

static NEXT_TABLES: AtomicU64Std = AtomicU64Std::new(1);

impl Tables {
    pub(crate) fn new(table: Table) -> Tables {
        Tables {
            uid: NEXT_TABLES.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            version: AtomicU64Std::new(0),
            current: std::sync::RwLock::new(std::sync::Arc::new(table)),
            reseeds: AtomicU64Std::new(0),
        }
    }

    fn load(&self) -> std::sync::Arc<Table> {
        std::sync::Arc::clone(
            &self
                .current
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    /// Runs `f` on the current table.
    #[inline]
    pub(crate) fn with<R>(&self, f: impl FnOnce(&Table) -> R) -> R {
        let version = self.version.load(std::sync::atomic::Ordering::Acquire);
        let mut f = Some(f);
        let done = CURRENT
            .try_with(|cell| {
                let mut slot = cell.try_borrow_mut().ok()?;
                if !matches!(&*slot, Some((uid, v, _)) if *uid == self.uid && *v == version) {
                    *slot = Some((self.uid, version, self.load()));
                }
                let table = &slot.as_ref()?.2;
                f.take().map(|f| f(table))
            })
            .ok()
            .flatten();
        match done {
            Some(r) => r,
            None => {
                let table = self.load();
                match f.take() {
                    Some(f) => f(&table),
                    None => unreachable!("the closure runs at most once"),
                }
            }
        }
    }

    /// Reseeds so far.
    pub(crate) fn reseeds(&self) -> u64 {
        self.reseeds.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub(crate) fn capacity(&self) -> u32 {
        self.with(Table::capacity)
    }

    pub(crate) fn bytes(&self) -> u64 {
        self.with(Table::bytes)
    }

    pub(crate) fn hasher(&self) -> HashKey {
        self.with(Table::hasher)
    }

    pub(crate) fn find(&self, key: &TableKey, now_secs: u64) -> Probe {
        self.with(|t| t.find(key, now_secs))
    }

    pub(crate) fn get_owned(&self, key: &TableKey) -> Option<Entry> {
        self.with(|t| t.get_owned(key))
    }

    pub(crate) fn remove(&self, w: &mut TableWriter, key: &TableKey) -> Option<Entry> {
        self.with(|t| t.remove(w, key))
    }

    pub(crate) fn remove_where(
        &self,
        w: &mut TableWriter,
        remove: impl FnMut(&Entry) -> bool,
    ) -> Vec<Entry> {
        self.with(|t| t.remove_where(w, remove))
    }

    pub(crate) fn for_each(&self, f: impl FnMut(&Entry)) {
        self.with(|t| t.for_each(f));
    }

    /// Inserts or merges, as [`Table::insert`]. When the key's probe
    /// sequence is full although the table is not, the table is rebuilt
    /// under a fresh hash key and the insert retried (once). The caller
    /// holds the owner's writer lock.
    pub(crate) fn insert(
        &self,
        w: &mut TableWriter,
        entry: Entry,
        now_secs: u64,
        merge: impl Fn(&Entry) -> Entry,
    ) -> Result<Inserted, NoRoom> {
        match self.with(|t| t.insert(w, entry, now_secs, &merge)) {
            Err(NoRoom::ProbeBound) => {
                let old = self.load();
                let key = HashKey::new(w.rng.next_u64(), w.rng.next_u64());
                let fresh = Table::with_anchors(old.capacity, key, old.anchors);
                let mut moved = TableWriter {
                    live: 0,
                    hand: 0,
                    rng: w.rng.clone(),
                };
                let mut ok = true;
                old.for_each(|e| {
                    ok &= fresh.insert(&mut moved, *e, 0, |_| *e).is_ok();
                });
                if !ok {
                    return Err(NoRoom::ProbeBound);
                }
                let result = fresh.insert(&mut moved, entry, now_secs, &merge);
                w.live = moved.live;
                w.hand = 0;
                *self
                    .current
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) =
                    std::sync::Arc::new(fresh);
                self.version
                    .fetch_add(1, std::sync::atomic::Ordering::Release);
                self.reseeds
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                result
            }
            other => other,
        }
    }
}

/// `a` ends before `b` (permanent entries never count as earlier).
fn earlier(a: &Entry, b: &Entry) -> bool {
    match (a.until, b.until) {
        (0, _) => false,
        (_, 0) => true,
        (x, y) => x < y,
    }
}

#[cfg(all(test, not(bouncer_loom)))]
mod tests {
    use super::*;

    fn key(n: u64) -> TableKey {
        TableKey {
            kind: KIND_V4,
            len: 32,
            k0: 0,
            k1: n,
        }
    }

    fn entry(n: u64, until: u32, evictable: bool) -> Entry {
        Entry {
            key: key(n),
            flags: if evictable { FLAG_EVICTABLE } else { 0 },
            actor: ActorKind::Local,
            reason: Reason::STRIKE_THRESHOLD,
            offences: 0,
            until,
            issued: 0,
            id: n,
        }
    }

    fn table(cap: u32) -> (Table, TableWriter) {
        (
            Table::new(cap, HashKey::new(11, 22)),
            TableWriter::default(),
        )
    }

    #[test]
    fn test_table_insert_find_remove() {
        let (t, mut w) = table(16);
        assert_eq!(
            t.insert(&mut w, entry(1, 100, true), 0, |e| *e),
            Ok(Inserted::New {
                removed: None,
                evicted: false
            })
        );
        assert!(matches!(t.find(&key(1), 0), Probe::Hit(e) if e.id == 1));
        assert_eq!(t.find(&key(2), 0), Probe::Miss);
        assert!(t.remove(&mut w, &key(1)).is_some());
        assert_eq!(t.find(&key(1), 0), Probe::Miss);
        assert_eq!(w.live(), 0);
        assert!(t.remove(&mut w, &key(1)).is_none());
    }

    #[test]
    fn test_table_entry_expires_at_until() {
        let (t, mut w) = table(4);
        t.insert(&mut w, entry(1, 10, true), 0, |e| *e).unwrap();
        assert!(matches!(t.find(&key(1), 9), Probe::Hit(_)));
        assert_eq!(t.find(&key(1), 10), Probe::Miss);
        let mut perm = entry(2, 0, false);
        perm.until = 0;
        t.insert(&mut w, perm, 0, |e| *e).unwrap();
        assert!(matches!(t.find(&key(2), u64::MAX), Probe::Hit(_)));
    }

    #[test]
    fn test_table_merge_existing_key() {
        let (t, mut w) = table(4);
        t.insert(&mut w, entry(1, 10, true), 0, |e| *e).unwrap();
        let r = t.insert(&mut w, entry(1, 50, true), 0, |prev| Entry {
            offences: prev.offences + 1,
            ..entry(1, 50, true)
        });
        assert!(matches!(r, Ok(Inserted::Merged { .. })));
        assert!(matches!(t.find(&key(1), 20), Probe::Hit(e) if e.offences == 1 && e.until == 50));
        assert_eq!(w.live(), 1);
    }

    #[test]
    fn test_table_never_exceeds_capacity_and_keeps_unevictable() {
        let (t, mut w) = table(8);
        for n in 0..8 {
            t.insert(&mut w, entry(n, 0, false), 0, |e| *e).unwrap();
        }
        assert_eq!(
            t.insert(&mut w, entry(100, 50, true), 0, |e| *e),
            Err(NoRoom::Full)
        );
        for n in 0..8 {
            assert!(matches!(t.find(&key(n), 0), Probe::Hit(_)));
        }
        assert_eq!(w.live(), 8);
    }

    #[test]
    fn test_table_evicts_earliest_evictable_when_full() {
        let (t, mut w) = table(4);
        t.insert(&mut w, entry(1, 0, false), 0, |e| *e).unwrap();
        t.insert(&mut w, entry(2, 30, true), 0, |e| *e).unwrap();
        t.insert(&mut w, entry(3, 10, true), 0, |e| *e).unwrap();
        t.insert(&mut w, entry(4, 20, true), 0, |e| *e).unwrap();
        let r = t.insert(&mut w, entry(5, 40, true), 0, |e| *e).unwrap();
        assert!(matches!(r, Inserted::New { removed: Some(e), evicted: true } if e.id == 3));
        assert_eq!(w.live(), 4);
        assert!(matches!(t.find(&key(1), 0), Probe::Hit(_)));
    }

    #[test]
    fn test_table_reclaims_expired_first() {
        let (t, mut w) = table(2);
        t.insert(&mut w, entry(1, 5, true), 0, |e| *e).unwrap();
        t.insert(&mut w, entry(2, 0, false), 0, |e| *e).unwrap();
        let r = t.insert(&mut w, entry(3, 0, false), 10, |e| *e).unwrap();
        assert!(matches!(r, Inserted::New { removed: Some(e), evicted: false } if e.id == 1));
        assert_eq!(w.live(), 2);
        assert!(matches!(t.find(&key(2), 10), Probe::Hit(_)));
        assert!(matches!(t.find(&key(3), 10), Probe::Hit(_)));
    }

    #[test]
    fn test_table_many_keys_round_trip() {
        let (t, mut w) = table(10_000);
        for n in 0..10_000 {
            t.insert(&mut w, entry(n, 0, false), 0, |e| *e).unwrap();
        }
        for n in 0..10_000 {
            assert!(
                matches!(t.find(&key(n), 0), Probe::Hit(e) if e.id == n),
                "{n}"
            );
        }
        assert_eq!(t.find(&key(10_001), 0), Probe::Miss);
    }
}

#[cfg(all(test, bouncer_loom))]
mod loom_tests {
    use super::*;

    /// L-3: a reader racing a writer on one slot sees the old entry, the new
    /// entry, or gives up; never a torn mix.
    #[test]
    fn loom_slot_reader_never_sees_torn_entry() {
        loom::model(|| {
            let slot = loom::sync::Arc::new(Slot::new());
            let old = Raw {
                meta: 2,
                k0: 1,
                k1: 1,
                times: 1,
                id: 1,
            };
            let new = Raw {
                meta: 2,
                k0: 2,
                k1: 2,
                times: 2,
                id: 2,
            };
            slot.write(&old);
            let s = slot.clone();
            let writer = loom::thread::spawn(move || s.write(&new));
            if let Some(r) = slot.read() {
                let words = [r.k0, r.k1, r.times, r.id];
                assert!(
                    words == [1, 1, 1, 1] || words == [2, 2, 2, 2],
                    "torn read {words:?}"
                );
            }
            writer.join().unwrap();
        });
    }
}

#[cfg(all(test, not(bouncer_loom)))]
mod flood_tests {
    use super::*;

    fn entry(n: u64) -> Entry {
        Entry {
            key: TableKey {
                kind: KIND_V4,
                len: 32,
                k0: 0,
                k1: n,
            },
            flags: 0,
            actor: ActorKind::Admin,
            reason: Reason::ADMIN,
            offences: 0,
            until: 0,
            issued: 0,
            id: n,
        }
    }

    /// Threat T-9: keys chosen to collide under a known hash key exhaust the
    /// probe bound; the same keys under a different (secret, random) key all
    /// fit. The attacker never learns the key, so it cannot choose collisions;
    /// if keys pile up anyway, the table rebuilds under a fresh key.
    #[test]
    fn test_table_hash_flooding_needs_the_key() {
        let known = HashKey::new(0x1111, 0x2222);
        let victim = Table::new(4096, known);
        let target = victim.locate(&entry(0).key).0;
        let colliding: Vec<u64> = (1..)
            .filter(|&n| victim.locate(&entry(n).key).0 == target)
            .take(400)
            .collect();
        let mut w = TableWriter::default();
        let refused = colliding
            .iter()
            .filter(|&&n| victim.insert(&mut w, entry(n), 0, |e| *e).is_err())
            .count();
        assert!(
            refused > 0,
            "colliding keys under a known key reach the probe bound"
        );

        let secret = Table::new(4096, HashKey::new(0x9e37_79b9, 0x7f4a_7c15));
        let mut w = TableWriter::default();
        for &n in &colliding {
            secret.insert(&mut w, entry(n), 0, |e| *e).unwrap();
        }
        for &n in &colliding {
            assert!(matches!(secret.find(&entry(n).key, 0), Probe::Hit(_)));
        }

        // The known key behind the handle: it reseeds and every key fits.
        let tables = Tables::new(Table::new(4096, known));
        let mut w = TableWriter::new(9);
        for &n in &colliding {
            tables.insert(&mut w, entry(n), 0, |e| *e).unwrap();
        }
        assert!(tables.reseeds() >= 1, "the probe bound forced a reseed");
        assert_ne!(tables.hasher(), known);
        for &n in &colliding {
            assert!(matches!(tables.find(&entry(n).key, 0), Probe::Hit(_)));
        }
        assert_eq!(w.live(), colliding.len() as u32);
    }
}
