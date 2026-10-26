//! Persistence: bans, lift tombstones, and offender memory survive a
//! restart.
//!
//! ```text
//! snapshot := "BNCR" | format:u16 | flags:u16 | created:u64 | epoch:u64
//!             | node:u16 | hlc:u64 | count:u64 | record* | length:u64
//!             | crc32c:u32 | [mac:32]
//! batch    := "BNCJ" | epoch:u64 | wall:u64 | length:u32 | record*
//!             | crc32c:u32 | [mac:32]
//! ```
//!
//! The snapshot's MAC is a keyed BLAKE3 over everything before it. Each
//! journal batch's MAC covers the previous MAC and the batch, so batches
//! cannot be altered, reordered, dropped from the middle, or spliced in from
//! another file without the key. Cutting the journal after a whole batch,
//! or putting back an older snapshot and journal together, is not detected:
//! that needs a counter kept outside the files (see `docs/SECURITY.md`). A
//! batch from another epoch (left by a crash during compaction)
//! is ignored. Writing happens off the hot path: changes queue in memory
//! and the maintainer writes and syncs them about every second.

use core::time::Duration;
use std::{
    collections::VecDeque,
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Mutex,
};

use crate::{
    codec::{self, Envelope, Reader, Writer},
    error::PersistError,
    time::Now,
};

/// The snapshot file's magic bytes.
pub const SNAPSHOT_MAGIC: [u8; 4] = *b"BNCR";
/// The snapshot and journal format this version writes: 2 since lifts carry
/// their scope (lifts of one origin's bans or of every origin's). Format 1
/// is still read, and rewritten as format 2 as soon as it is loaded.
pub const SNAPSHOT_FORMAT: u16 = 2;

const BATCH_MAGIC: [u8; 4] = *b"BNCJ";
const HEADER: usize = 4 + 2 + 2 + 8 + 8 + 2 + 8 + 8;
const MAC_LEN: usize = 32;
/// Records waiting to be written, at most.
pub(crate) const QUEUE: usize = 65_536;
/// The journal is folded into a new snapshot past this size.
const COMPACT_AT: u64 = 16 << 20;
/// How often queued records are written and synced.
const FLUSH_EVERY: Duration = Duration::from_secs(1);

/// Where bouncer keeps its bytes: a file, a database row, a replicated
/// store. bouncer owns the format; the store only keeps bytes.
///
/// # Examples
///
/// ```
/// use bouncer_io::{PersistError, Persistence};
///
/// /// Keeps everything in memory (tests).
/// #[derive(Default)]
/// struct InMemory { snapshot: Option<Vec<u8>>, journal: Vec<u8> }
///
/// impl Persistence for InMemory {
///     fn load(&mut self) -> Result<Option<Vec<u8>>, PersistError> { Ok(self.snapshot.clone()) }
///     fn journal(&mut self) -> Result<Vec<u8>, PersistError> { Ok(self.journal.clone()) }
///     fn append(&mut self, records: &[u8]) -> Result<(), PersistError> {
///         self.journal.extend_from_slice(records);
///         Ok(())
///     }
///     fn sync(&mut self) -> Result<(), PersistError> { Ok(()) }
///     fn replace_snapshot(&mut self, snapshot: &[u8]) -> Result<(), PersistError> {
///         self.snapshot = Some(snapshot.to_vec());
///         self.journal.clear();
///         Ok(())
///     }
/// }
/// let bouncer = bouncer_io::Bouncer::builder().persistence(Box::new(InMemory::default())).try_build()?;
/// # let _ = bouncer;
/// # Ok::<(), bouncer_io::BouncerError>(())
/// ```
pub trait Persistence: Send {
    /// The snapshot bytes, or `None` when there is none yet.
    ///
    /// # Errors
    ///
    /// `Io` when the store fails.
    fn load(&mut self) -> Result<Option<Vec<u8>>, PersistError>;

    /// The journal bytes (empty when there are none).
    ///
    /// # Errors
    ///
    /// `Io` when the store fails.
    fn journal(&mut self) -> Result<Vec<u8>, PersistError>;

    /// Appends to the journal.
    ///
    /// # Errors
    ///
    /// `Io` when the store fails.
    fn append(&mut self, records: &[u8]) -> Result<(), PersistError>;

    /// Makes appended bytes durable.
    ///
    /// # Errors
    ///
    /// `Io` when the store fails.
    fn sync(&mut self) -> Result<(), PersistError>;

    /// Replaces the snapshot crash-safely (the old one or the new one
    /// survives a crash, never a mix), then empties the journal.
    ///
    /// # Errors
    ///
    /// `Io` when the store fails.
    fn replace_snapshot(&mut self, snapshot: &[u8]) -> Result<(), PersistError>;
}

/// What to do when persisted state is corrupt or tampered with.
///
/// # Examples
///
/// ```
/// assert_eq!(bouncer_io::LoadFailure::default(), bouncer_io::LoadFailure::Refuse);
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LoadFailure {
    /// Fail closed: `try_build` returns `Persist(..)` and the service does
    /// not start without its bans.
    #[default]
    Refuse,
    /// Start with empty memory and report the failure.
    LoadEmpty,
}

/// Crash-safe files: `name` (the snapshot) and `name.journal` in a
/// directory.
///
/// The snapshot is written to `name.tmp`, synced, and renamed over `name`;
/// on Unix the directory is synced too. Windows rename replaces the target.
///
/// # Examples
///
/// ```no_run
/// use bouncer_io::{Bouncer, FilePersistence};
/// let bouncer = Bouncer::builder()
///     .persistence(Box::new(FilePersistence::open("/var/lib/gate".as_ref(), "bans")?))
///     .try_build()?;
/// # let _ = bouncer;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug)]
pub struct FilePersistence {
    dir: PathBuf,
    snapshot: PathBuf,
    journal_path: PathBuf,
    tmp: PathBuf,
    journal: Option<File>,
}

fn io(e: &std::io::Error) -> PersistError {
    PersistError::Io(e.kind())
}

impl FilePersistence {
    /// Uses `dir` (which must exist) for the files named after `name`.
    ///
    /// # Errors
    ///
    /// `Io(NotFound)` when the directory does not exist; `Io(InvalidInput)`
    /// for an empty name or one with a path separator.
    pub fn open(dir: &Path, name: &str) -> Result<FilePersistence, PersistError> {
        if name.is_empty() || name.contains(['/', '\\']) || name == "." || name == ".." {
            return Err(PersistError::Io(std::io::ErrorKind::InvalidInput));
        }
        if !dir.is_dir() {
            return Err(PersistError::Io(std::io::ErrorKind::NotFound));
        }
        Ok(FilePersistence {
            dir: dir.to_path_buf(),
            snapshot: dir.join(name),
            journal_path: dir.join(format!("{name}.journal")),
            tmp: dir.join(format!("{name}.tmp")),
            journal: None,
        })
    }

    fn read(path: &Path) -> Result<Option<Vec<u8>>, PersistError> {
        match File::open(path) {
            Ok(mut f) => {
                let mut v = Vec::new();
                f.read_to_end(&mut v).map_err(|e| io(&e))?;
                Ok(Some(v))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io(&e)),
        }
    }

    fn journal_file(&mut self) -> Result<&mut File, PersistError> {
        if self.journal.is_none() {
            let f = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.journal_path)
                .map_err(|e| io(&e))?;
            self.journal = Some(f);
        }
        self.journal
            .as_mut()
            .ok_or(PersistError::Io(std::io::ErrorKind::Other))
    }
}

impl Persistence for FilePersistence {
    fn load(&mut self) -> Result<Option<Vec<u8>>, PersistError> {
        Self::read(&self.snapshot)
    }

    fn journal(&mut self) -> Result<Vec<u8>, PersistError> {
        Ok(Self::read(&self.journal_path)?.unwrap_or_default())
    }

    fn append(&mut self, records: &[u8]) -> Result<(), PersistError> {
        self.journal_file()?.write_all(records).map_err(|e| io(&e))
    }

    fn sync(&mut self) -> Result<(), PersistError> {
        self.journal_file()?.sync_data().map_err(|e| io(&e))
    }

    fn replace_snapshot(&mut self, snapshot: &[u8]) -> Result<(), PersistError> {
        {
            let mut f = File::create(&self.tmp).map_err(|e| io(&e))?;
            f.write_all(snapshot).map_err(|e| io(&e))?;
            f.sync_all().map_err(|e| io(&e))?;
        }
        std::fs::rename(&self.tmp, &self.snapshot).map_err(|e| io(&e))?;
        #[cfg(unix)]
        {
            File::open(&self.dir)
                .and_then(|d| d.sync_all())
                .map_err(|e| io(&e))?;
        }
        #[cfg(not(unix))]
        let _ = &self.dir;
        // A crash before this truncation leaves batches of the old epoch,
        // which the next load ignores.
        self.journal = None;
        let f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&self.journal_path)
            .map_err(|e| io(&e))?;
        f.sync_all().map_err(|e| io(&e))?;
        Ok(())
    }
}

/// The MAC key, wiped when dropped.
pub(crate) struct Key([u8; 32]);

impl Drop for Key {
    fn drop(&mut self) {
        crypt_io::wipe(&mut self.0);
    }
}

fn mac(key: &Key, parts: &[&[u8]]) -> [u8; MAC_LEN] {
    let total: usize = parts.iter().map(|p| p.len()).sum();
    let mut data = Vec::with_capacity(total);
    for p in parts {
        data.extend_from_slice(p);
    }
    crypt_io::mac::blake3_keyed(&key.0, &data)
}

/// The fields of a snapshot header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Header {
    /// The format read (encoding always writes [`SNAPSHOT_FORMAT`]).
    pub(crate) format: u16,
    pub(crate) created: u64,
    pub(crate) epoch: u64,
    pub(crate) node: u16,
    pub(crate) hlc: u64,
}

/// Encodes a snapshot; returns it and its MAC (zero without a key).
pub(crate) fn encode_snapshot(
    h: &Header,
    records: &[Envelope],
    key: Option<&Key>,
) -> (Vec<u8>, [u8; MAC_LEN]) {
    let mut out = Vec::with_capacity(HEADER + records.len() * 64 + 44);
    let mut body = Vec::with_capacity(records.len() * 64);
    let mut count = 0u64;
    for r in records {
        if codec::encode(&mut body, r) {
            count += 1;
        }
    }
    let mut w = Writer(&mut out);
    w.bytes(&SNAPSHOT_MAGIC);
    w.u16(SNAPSHOT_FORMAT);
    w.u16(u16::from(key.is_some()));
    w.u64(h.created);
    w.u64(h.epoch);
    w.u16(h.node);
    w.u64(h.hlc);
    w.u64(count);
    w.bytes(&body);
    let len = out.len() as u64;
    Writer(&mut out).u64(len);
    let crc = codec::crc32c(&out);
    Writer(&mut out).u32(crc);
    let tag = match key {
        Some(k) => {
            let t = mac(k, &[&out]);
            out.extend_from_slice(&t);
            t
        }
        None => [0; MAC_LEN],
    };
    (out, tag)
}

/// Decodes a snapshot: its header, records, and MAC (zero without a key).
pub(crate) fn decode_snapshot(
    bytes: &[u8],
    key: Option<&Key>,
) -> Result<(Header, Vec<Envelope>, [u8; MAC_LEN]), PersistError> {
    if bytes.len() < HEADER + 12 {
        return Err(if bytes.starts_with(&SNAPSHOT_MAGIC) || bytes.is_empty() {
            PersistError::Truncated
        } else {
            PersistError::Corrupt { offset: 0 }
        });
    }
    if bytes[..4] != SNAPSHOT_MAGIC {
        return Err(PersistError::Corrupt { offset: 0 });
    }
    let mut r = Reader::new(&bytes[4..], 4);
    let bad = |b: codec::Bad| PersistError::Corrupt { offset: b.0 };
    let format = r.u16().map_err(bad)?;
    if format > SNAPSHOT_FORMAT || format == 0 {
        return Err(PersistError::UnsupportedFormat(format));
    }
    let flags = r.u16().map_err(bad)?;
    let has_mac = flags & 1 != 0;
    if has_mac != key.is_some() {
        return Err(PersistError::Mac);
    }
    let trailer = 12 + if has_mac { MAC_LEN } else { 0 };
    if bytes.len() < HEADER + trailer {
        return Err(PersistError::Truncated);
    }
    let body_end = bytes.len() - trailer;
    let mut t = Reader::new(&bytes[body_end..], body_end as u64);
    let len = t.u64().map_err(bad)?;
    if len != body_end as u64 {
        return Err(if len > body_end as u64 {
            PersistError::Truncated
        } else {
            PersistError::Corrupt {
                offset: body_end as u64,
            }
        });
    }
    let crc = t.u32().map_err(bad)?;
    if codec::crc32c(&bytes[..body_end + 8]) != crc {
        return Err(PersistError::Corrupt {
            offset: body_end as u64,
        });
    }
    let mut tag = [0u8; MAC_LEN];
    if let Some(k) = key {
        let given = &bytes[body_end + 12..];
        if crypt_io::mac::blake3_keyed_check(&k.0, &bytes[..body_end + 12], given).is_err() {
            return Err(PersistError::Mac);
        }
        tag.copy_from_slice(given);
    }
    let header = Header {
        format,
        created: r.u64().map_err(bad)?,
        epoch: r.u64().map_err(bad)?,
        node: r.u16().map_err(bad)?,
        hlc: r.u64().map_err(bad)?,
    };
    let count = r.u64().map_err(bad)?;
    let mut body = Reader::new(&bytes[HEADER..body_end], HEADER as u64);
    let mut records = Vec::with_capacity((count as usize).min(body.remaining() / 16));
    for _ in 0..count {
        records.push(codec::decode(&mut body).map_err(bad)?);
    }
    if body.remaining() != 0 {
        return Err(PersistError::Corrupt {
            offset: body.offset(),
        });
    }
    Ok((header, records, tag))
}

/// Encodes one journal batch, chaining its MAC from `chain`; returns the
/// bytes and the new chain value.
pub(crate) fn encode_batch(
    epoch: u64,
    wall: u64,
    records: &[Envelope],
    key: Option<&Key>,
    chain: &[u8; MAC_LEN],
) -> (Vec<u8>, [u8; MAC_LEN]) {
    let mut body = Vec::with_capacity(records.len() * 64);
    for r in records {
        codec::encode(&mut body, r);
    }
    let mut out = Vec::with_capacity(body.len() + 60);
    let mut w = Writer(&mut out);
    w.bytes(&BATCH_MAGIC);
    w.u64(epoch);
    w.u64(wall);
    w.u32(body.len() as u32);
    w.bytes(&body);
    let crc = codec::crc32c(&out);
    Writer(&mut out).u32(crc);
    let next = match key {
        Some(k) => {
            let t = mac(k, &[chain, &out]);
            out.extend_from_slice(&t);
            t
        }
        None => *chain,
    };
    (out, next)
}

/// The outcome of replaying a journal.
#[derive(Debug, Default)]
pub(crate) struct Replay {
    pub(crate) records: Vec<Envelope>,
    /// Bytes after the first bad or torn batch: lost.
    pub(crate) lost: u64,
    pub(crate) chain: [u8; MAC_LEN],
    /// The wall time of the last batch applied.
    pub(crate) last_wall: Option<u64>,
    /// Bytes of valid batches of this epoch.
    pub(crate) bytes: u64,
}

/// Replays the batches of `epoch` in order, from the snapshot's chain.
/// Stops at the first torn or bad batch (a crash cut the tail, or the
/// middle is damaged); what follows is reported as lost.
pub(crate) fn replay(
    journal: &[u8],
    epoch: u64,
    key: Option<&Key>,
    chain: [u8; MAC_LEN],
) -> Replay {
    let mut out = Replay {
        chain,
        ..Replay::default()
    };
    let mut pos = 0usize;
    let mac_len = if key.is_some() { MAC_LEN } else { 0 };
    while pos < journal.len() {
        let rest = &journal[pos..];
        let fixed = 4 + 8 + 8 + 4;
        let ok = (|| -> Option<(usize, u64, u64, &[u8])> {
            if rest.len() < fixed || rest[..4] != BATCH_MAGIC {
                return None;
            }
            let mut r = Reader::new(&rest[4..], 0);
            let e = r.u64().ok()?;
            let wall = r.u64().ok()?;
            let len = r.u32().ok()? as usize;
            let total = fixed + len + 4 + mac_len;
            if rest.len() < total {
                return None;
            }
            let crc = u32::from_le_bytes(rest[fixed + len..fixed + len + 4].try_into().ok()?);
            if codec::crc32c(&rest[..fixed + len]) != crc {
                return None;
            }
            Some((total, e, wall, &rest[fixed..fixed + len]))
        })();
        let Some((total, e, wall, body)) = ok else {
            break;
        };
        if e != epoch {
            // Left by a crash during compaction: not part of this snapshot.
            pos += total;
            continue;
        }
        if let Some(k) = key {
            let given = &rest[total - MAC_LEN..total];
            let expect = mac(k, &[&out.chain, &rest[..total - MAC_LEN]]);
            if given != expect.as_slice() {
                break;
            }
            out.chain = expect;
        }
        let mut r = Reader::new(body, (pos + fixed) as u64);
        let mut batch = Vec::new();
        let mut good = true;
        while r.remaining() > 0 {
            match codec::decode(&mut r) {
                Ok(env) => batch.push(env),
                Err(_) => {
                    good = false;
                    break;
                }
            }
        }
        if !good {
            break;
        }
        out.records.extend(batch);
        out.last_wall = Some(wall);
        out.bytes += total as u64;
        pos += total;
    }
    out.lost = (journal.len() - pos) as u64;
    out
}

/// Writing state, kept under one lock.
pub(crate) struct State {
    pub(crate) epoch: u64,
    pub(crate) chain: [u8; MAC_LEN],
    pub(crate) journal_bytes: u64,
    pub(crate) last_flush: Now,
    pub(crate) failed: Option<std::io::ErrorKind>,
}

/// A bouncer's persistence: the store, the queue, and the writing state.
pub(crate) struct Persist {
    pub(crate) store: Mutex<Box<dyn Persistence>>,
    queue: Mutex<VecDeque<Envelope>>,
    pub(crate) key: Option<Key>,
    pub(crate) state: Mutex<State>,
    backlog: std::sync::atomic::AtomicU32,
    dropped: std::sync::atomic::AtomicU64,
}

impl Persist {
    pub(crate) fn new(store: Box<dyn Persistence>, key: Option<[u8; 32]>) -> Persist {
        Persist {
            store: Mutex::new(store),
            queue: Mutex::new(VecDeque::with_capacity(QUEUE)),
            key: key.map(Key),
            state: Mutex::new(State {
                epoch: 0,
                chain: [0; MAC_LEN],
                journal_bytes: 0,
                last_flush: Now::default(),
                failed: None,
            }),
            backlog: std::sync::atomic::AtomicU32::new(0),
            dropped: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Queues a record. `false` when the queue is full: the record is kept
    /// in memory but not persisted.
    pub(crate) fn enqueue(&self, env: Envelope) -> bool {
        let mut q = self
            .queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if q.len() >= QUEUE {
            self.dropped
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return false;
        }
        q.push_back(env);
        self.backlog
            .store(q.len() as u32, std::sync::atomic::Ordering::Relaxed);
        true
    }

    pub(crate) fn backlog(&self) -> u32 {
        self.backlog.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub(crate) fn last_error(&self) -> Option<std::io::ErrorKind> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .failed
    }

    /// When the next flush is due: one interval after the last, while
    /// records are queued.
    pub(crate) fn due(&self) -> Option<Now> {
        if self.backlog() == 0 {
            return None;
        }
        let last = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .last_flush;
        Some(Now::from_nanos(
            last.as_nanos()
                .saturating_add(FLUSH_EVERY.as_nanos() as u64),
        ))
    }

    /// Takes every queued record.
    pub(crate) fn drain(&self) -> Vec<Envelope> {
        let mut q = self
            .queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let v: Vec<Envelope> = q.drain(..).collect();
        self.backlog.store(0, std::sync::atomic::Ordering::Relaxed);
        v
    }

    /// Puts records back at the front after a failed write.
    pub(crate) fn requeue(&self, records: Vec<Envelope>) {
        let mut q = self
            .queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for r in records.into_iter().rev() {
            if q.len() >= QUEUE {
                break;
            }
            q.push_front(r);
        }
        self.backlog
            .store(q.len() as u32, std::sync::atomic::Ordering::Relaxed);
    }

    /// Whether the journal should be folded into a new snapshot.
    pub(crate) fn wants_compaction(state: &State) -> bool {
        state.journal_bytes > COMPACT_AT
    }

    /// Records dropped because the queue was full.
    #[allow(dead_code)]
    pub(crate) fn dropped(&self) -> u64 {
        self.dropped.load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[cfg(all(test, not(bouncer_loom)))]
mod tests {
    use super::*;
    use crate::{codec::Rec, keys::BanKey};

    fn rec(n: u64) -> Envelope {
        Envelope {
            origin: 0,
            seq: n,
            rec: Rec::Remove {
                key: BanKey::Address(std::net::IpAddr::from([192, 0, 2, n as u8])),
            },
        }
    }

    fn header() -> Header {
        Header {
            format: SNAPSHOT_FORMAT,
            created: 1_800_000_000,
            epoch: 3,
            node: 1,
            hlc: 9,
        }
    }

    #[test]
    fn test_snapshot_round_trip_with_and_without_mac() {
        let key = Key([7; 32]);
        for k in [None, Some(&key)] {
            let recs: Vec<Envelope> = (0..5).map(rec).collect();
            let (bytes, tag) = encode_snapshot(&header(), &recs, k);
            let (h, back, tag2) = decode_snapshot(&bytes, k).unwrap();
            assert_eq!(h, header());
            assert_eq!(back, recs);
            assert_eq!(tag, tag2);
        }
    }

    #[test]
    fn test_snapshot_truncated_anywhere_is_refused() {
        // Edge case 61.
        let key = Key([7; 32]);
        let recs: Vec<Envelope> = (0..3).map(rec).collect();
        for k in [None, Some(&key)] {
            let (bytes, _) = encode_snapshot(&header(), &recs, k);
            for cut in 0..bytes.len() {
                assert!(
                    decode_snapshot(&bytes[..cut], k).is_err(),
                    "cut at {cut} accepted"
                );
            }
            let mut flipped = bytes.clone();
            flipped[HEADER + 3] ^= 0x10;
            assert!(decode_snapshot(&flipped, k).is_err());
        }
    }

    #[test]
    fn test_snapshot_mac_rules() {
        // Edge case 63, and the downgrade the other way.
        let key = Key([7; 32]);
        let other = Key([8; 32]);
        let (mac_d, _) = encode_snapshot(&header(), &[rec(1)], Some(&key));
        let (plain, _) = encode_snapshot(&header(), &[rec(1)], None);
        assert_eq!(decode_snapshot(&mac_d, None).err(), Some(PersistError::Mac));
        assert_eq!(
            decode_snapshot(&plain, Some(&key)).err(),
            Some(PersistError::Mac)
        );
        assert_eq!(
            decode_snapshot(&mac_d, Some(&other)).err(),
            Some(PersistError::Mac)
        );
        let mut newer = plain.clone();
        newer[4] = 9;
        assert_eq!(
            decode_snapshot(&newer, None).err(),
            Some(PersistError::UnsupportedFormat(9))
        );
    }

    #[test]
    fn test_journal_replay_stops_at_damage_and_skips_old_epochs() {
        // Edge case 62, and the torn tail.
        let key = Key([7; 32]);
        for k in [None, Some(&key)] {
            let chain0 = [1u8; 32];
            let (old, _) = encode_batch(2, 10, &[rec(9)], k, &chain0);
            let (b1, c1) = encode_batch(3, 11, &[rec(1), rec(2)], k, &chain0);
            let (b2, c2) = encode_batch(3, 12, &[rec(3)], k, &c1);
            let (b3, _) = encode_batch(3, 13, &[rec(4)], k, &c2);
            let mut journal = [old.clone(), b1.clone(), b2.clone(), b3.clone()].concat();
            let r = replay(&journal, 3, k, chain0);
            assert_eq!(r.records.len(), 4);
            assert_eq!(r.lost, 0);
            assert_eq!(r.last_wall, Some(13));
            // A torn tail.
            journal.truncate(journal.len() - 3);
            let r = replay(&journal, 3, k, chain0);
            assert_eq!(r.records.len(), 3);
            assert_eq!(r.lost, b3.len() as u64 - 3);
            // A damaged middle batch: everything after it is lost.
            let mut damaged = [old.clone(), b1.clone(), b2.clone(), b3.clone()].concat();
            let at = old.len() + b1.len() + 30;
            damaged[at] ^= 1;
            let r = replay(&damaged, 3, k, chain0);
            assert_eq!(r.records.len(), 2);
            assert_eq!(r.lost, (b2.len() + b3.len()) as u64);
        }
        // With a key, batches out of order break the chain.
        let chain0 = [1u8; 32];
        let (b1, c1) = encode_batch(3, 11, &[rec(1)], Some(&key), &chain0);
        let (b2, _) = encode_batch(3, 12, &[rec(2)], Some(&key), &c1);
        let swapped = [b2, b1].concat();
        assert!(replay(&swapped, 3, Some(&key), chain0).records.is_empty());
    }
}
