//! Sharing across nodes: node ids, deltas, and the merge rules.
//!
//! ```text
//! delta := "BNCD" | format:u16 | flags:u16 | origin:u16 | last:u64
//!          | count:u32 | record* | crc32c:u32
//! ```
//!
//! Records carry their origin node and sequence, and a hybrid logical clock
//! stamp: Unix milliseconds in the top 48 bits and a counter in the low 16,
//! so stamps from different nodes compare by wall time and never repeat.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use crate::{
    codec::{self, Envelope, Reader, Writer},
    error::{BouncerError, ImportError},
    keys::BanKey,
};

/// A node of a cluster, stamped on every record it exports. 0 is not a
/// valid node id.
///
/// # Examples
///
/// ```
/// use bouncer_io::{Bouncer, NodeId};
/// let bouncer = Bouncer::builder().node(NodeId(3)).try_build()?;
/// # let _ = bouncer;
/// assert!(Bouncer::builder().node(NodeId(0)).try_build().is_err());
/// # Ok::<(), bouncer_io::BouncerError>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId(pub u16);

/// A position in a node's outbound log. Pass [`Delta::last`] as `since` to
/// the next [`export_delta`](crate::Bouncer::export_delta).
///
/// # Examples
///
/// ```
/// assert!(bouncer_io::Sequence::START < bouncer_io::Sequence::START.next());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Sequence(pub(crate) u64);

impl Sequence {
    /// Before the first record.
    pub const START: Sequence = Sequence(0);

    /// The position after this one.
    #[must_use]
    pub const fn next(self) -> Sequence {
        Sequence(self.0.saturating_add(1))
    }

    /// The raw position, for storing between runs.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// A position from a stored raw value.
    #[must_use]
    pub const fn from_raw(raw: u64) -> Sequence {
        Sequence(raw)
    }
}

const MAGIC: [u8; 4] = *b"BNCD";
const FORMAT: u16 = 1;
const HEADER: usize = 4 + 2 + 2 + 2 + 8 + 4;
/// Largest delta accepted or produced.
pub(crate) const MAX_DELTA: usize = 16 << 20;
/// Records kept in the outbound log.
const LOG: usize = 65_536;
/// Record ids remembered to count and skip duplicates.
const SEEN: usize = 1 << 20;
/// Lift tombstones remembered.
const TOMBSTONES: usize = 65_536;

/// Encoded records for another node, at most 16 MiB. The transport is the
/// caller's (a node link, the back-channel, a replicated log), authenticated
/// by that transport.
///
/// # Examples
///
/// ```
/// use bouncer_io::{Bouncer, Delta, NodeId, Sequence};
/// let a = Bouncer::builder().node(NodeId(1)).try_build()?;
/// a.ban("198.51.100.9".parse::<std::net::IpAddr>()?)?;
/// let delta = a.export_delta(Sequence::START)?;
/// let copy = Delta::from_bytes(delta.as_bytes())?;
/// assert_eq!(copy.last(), delta.last());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delta {
    bytes: Vec<u8>,
    last: Sequence,
    origin: u16,
    full: bool,
    count: u32,
}

impl Delta {
    /// The encoded bytes, to send.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The last log position this delta carries.
    #[must_use]
    pub fn last(&self) -> Sequence {
        self.last
    }

    /// Checks received bytes and wraps them.
    ///
    /// # Errors
    ///
    /// `Import(Corrupt | TooLarge | UnsupportedFormat)`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Delta, BouncerError> {
        let d = Delta::check(bytes)?;
        Ok(d)
    }

    fn check(bytes: &[u8]) -> Result<Delta, ImportError> {
        if bytes.len() > MAX_DELTA {
            return Err(ImportError::TooLarge);
        }
        if bytes.len() < HEADER + 4 || bytes[..4] != MAGIC {
            return Err(ImportError::Corrupt { offset: 0 });
        }
        let body_end = bytes.len() - 4;
        let crc = u32::from_le_bytes([
            bytes[body_end],
            bytes[body_end + 1],
            bytes[body_end + 2],
            bytes[body_end + 3],
        ]);
        let mut r = Reader::new(&bytes[4..HEADER], 4);
        let bad = |b: codec::Bad| ImportError::Corrupt { offset: b.0 };
        let format = r.u16().map_err(bad)?;
        if format == 0 || format > FORMAT {
            return Err(ImportError::UnsupportedFormat(format));
        }
        if codec::crc32c(&bytes[..body_end]) != crc {
            return Err(ImportError::Corrupt {
                offset: body_end as u64,
            });
        }
        let flags = r.u16().map_err(bad)?;
        let origin = r.u16().map_err(bad)?;
        let last = r.u64().map_err(bad)?;
        let count = r.u32().map_err(bad)?;
        // Every record must decode, exactly `count` of them.
        let mut body = Reader::new(&bytes[HEADER..body_end], HEADER as u64);
        for _ in 0..count {
            codec::decode(&mut body).map_err(bad)?;
        }
        if body.remaining() != 0 {
            return Err(ImportError::Corrupt {
                offset: body.offset(),
            });
        }
        Ok(Delta {
            bytes: bytes.to_vec(),
            last: Sequence(last),
            origin,
            full: flags & 1 != 0,
            count,
        })
    }

    /// Builds a delta. Records that cannot travel are left out; the delta
    /// stops before 16 MiB (`last` then says where it stopped).
    pub(crate) fn build(origin: u16, full: bool, records: &[(u64, Envelope)], last: u64) -> Delta {
        let mut bytes = Vec::with_capacity(HEADER + records.len() * 64 + 4);
        bytes.extend_from_slice(&[0; HEADER]);
        let mut count = 0u32;
        let mut reached = last;
        for (pos, env) in records {
            let before = bytes.len();
            if !codec::encode(&mut bytes, env) {
                continue;
            }
            if bytes.len() + 4 > MAX_DELTA {
                bytes.truncate(before);
                reached = pos.saturating_sub(1);
                break;
            }
            count += 1;
        }
        let mut header = Vec::with_capacity(HEADER);
        let mut w = Writer(&mut header);
        w.bytes(&MAGIC);
        w.u16(FORMAT);
        w.u16(u16::from(full));
        w.u16(origin);
        w.u64(reached);
        w.u32(count);
        bytes[..HEADER].copy_from_slice(&header);
        let crc = codec::crc32c(&bytes);
        bytes.extend_from_slice(&crc.to_le_bytes());
        Delta {
            bytes,
            last: Sequence(reached),
            origin,
            full,
            count,
        }
    }

    /// The records (already checked when the delta was built or received).
    pub(crate) fn records(&self) -> Vec<Envelope> {
        let end = self.bytes.len() - 4;
        let mut r = Reader::new(&self.bytes[HEADER..end], HEADER as u64);
        (0..self.count)
            .filter_map(|_| codec::decode(&mut r).ok())
            .collect()
    }

    pub(crate) fn is_full(&self) -> bool {
        self.full
    }
}

/// What an import did.
///
/// # Examples
///
/// ```
/// let report = bouncer_io::ImportReport::default();
/// assert_eq!(report.applied, 0);
/// ```
#[must_use]
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ImportReport {
    /// Records that changed something here.
    pub applied: u32,
    /// Records older than what is here (a later lift, a longer ban).
    pub superseded: u32,
    /// Records already imported.
    pub duplicates: u32,
    /// Revocations applied to running requests here.
    pub revocations: u32,
    /// Records refused (allow-listed keys, clock skew, foreign lifts); each
    /// is also an `import.rejected` event.
    pub rejected: u32,
}

/// Lift tombstones by key, and keys in the order first noted (for
/// forgetting the oldest in constant time).
#[derive(Default)]
struct Tombstones {
    map: HashMap<BanKey, (u64, u16)>,
    order: VecDeque<BanKey>,
}

/// Record ids seen, and their order for forgetting the oldest.
type Seen = (HashSet<(u16, u64)>, VecDeque<(u16, u64)>);

/// The sharing state of one bouncer.
pub(crate) struct Share {
    hlc: AtomicU64,
    log: Mutex<VecDeque<(u64, Envelope)>>,
    next: AtomicU64,
    seen: Mutex<Seen>,
    tombstones: Mutex<Tombstones>,
    /// Records accepted per second from channels (a storm defence).
    pub(crate) channel_rate: Option<rate_net::Gcra>,
}

impl Share {
    pub(crate) fn new(channel_per_second: u32) -> Share {
        Share {
            hlc: AtomicU64::new(0),
            log: Mutex::new(VecDeque::new()),
            next: AtomicU64::new(1),
            seen: Mutex::new((HashSet::new(), VecDeque::new())),
            tombstones: Mutex::new(Tombstones::default()),
            channel_rate: rate_net::Quota::rate(
                channel_per_second.max(1),
                core::time::Duration::from_secs(1),
            )
            .ok()
            .map(|q| rate_net::Gcra::new(q.with_burst(channel_per_second.max(1))))
            .filter(|_| channel_per_second > 0),
        }
    }

    /// A new stamp at wall time `wall_ms`.
    pub(crate) fn stamp(&self, wall_ms: u64) -> u64 {
        let base = wall_ms << 16;
        let mut cur = self.hlc.load(Ordering::Acquire);
        loop {
            let next = if base > cur { base } else { cur + 1 };
            match self
                .hlc
                .compare_exchange_weak(cur, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return next,
                Err(actual) => cur = actual,
            }
        }
    }

    /// Moves the clock past a stamp seen from another node.
    pub(crate) fn observe(&self, stamp: u64) {
        self.hlc.fetch_max(stamp, Ordering::AcqRel);
    }

    pub(crate) fn clock(&self) -> u64 {
        self.hlc.load(Ordering::Acquire)
    }

    /// The next local sequence number.
    pub(crate) fn next_seq(&self) -> u64 {
        self.next.fetch_add(1, Ordering::AcqRel)
    }

    /// Adds a record to the outbound log.
    pub(crate) fn push(&self, env: Envelope) {
        let mut log = self
            .log
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let pos = log.back().map_or(1, |(p, _)| p + 1);
        if log.len() >= LOG {
            log.pop_front();
        }
        log.push_back((pos, env));
    }

    /// Records after `since`, or `None` when `since` is older than the log
    /// keeps (the caller then exports everything).
    pub(crate) fn since(&self, since: u64) -> Option<(Vec<(u64, Envelope)>, u64)> {
        let log = self
            .log
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let last = log.back().map_or(since, |(p, _)| *p);
        if let Some((first, _)) = log.front() {
            if since + 1 < *first {
                return None;
            }
        }
        Some((
            log.iter().filter(|(p, _)| *p > since).copied().collect(),
            last.max(since),
        ))
    }

    /// The last log position.
    pub(crate) fn last(&self) -> u64 {
        self.log
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .back()
            .map_or(0, |(p, _)| *p)
    }

    /// Remembers a record id; `false` when it was already seen.
    pub(crate) fn first_time(&self, origin: u16, seq: u64) -> bool {
        let mut g = self
            .seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (set, order) = &mut *g;
        if !set.insert((origin, seq)) {
            return false;
        }
        order.push_back((origin, seq));
        if order.len() > SEEN {
            if let Some(old) = order.pop_front() {
                set.remove(&old);
            }
        }
        true
    }

    /// Records a lift tombstone; keeps the later stamp.
    pub(crate) fn tombstone(&self, key: BanKey, stamp: u64, origin: u16) {
        let mut t = self
            .tombstones
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let t = &mut *t;
        if !t.map.contains_key(&key) {
            // Full: forget the tombstone noted longest ago.
            while t.map.len() >= TOMBSTONES {
                match t.order.pop_front() {
                    Some(old) => {
                        t.map.remove(&old);
                    }
                    None => break,
                }
            }
            t.order.push_back(key);
        }
        let e = t.map.entry(key).or_insert((stamp, origin));
        if stamp > e.0 {
            *e = (stamp, origin);
        }
    }

    /// The latest lift stamp of a key.
    pub(crate) fn lifted_at(&self, key: &BanKey) -> Option<u64> {
        self.tombstones
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .map
            .get(key)
            .map(|(s, _)| *s)
    }

    /// Every tombstone (snapshots and full exports).
    pub(crate) fn tombstones(&self) -> Vec<(BanKey, u64, u16)> {
        self.tombstones
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .map
            .iter()
            .map(|(k, (s, o))| (*k, *s, *o))
            .collect()
    }
}
