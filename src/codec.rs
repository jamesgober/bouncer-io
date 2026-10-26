//! The record format shared by snapshots, the journal, and deltas.
//!
//! ```text
//! record  := len:u32 | body | crc32c(body):u32
//! body    := type:u8 | origin:u16 | seq:u64 | payload
//! ```
//!
//! All integers are little-endian. The decoder never panics and never
//! allocates more than the input it was given (it is fuzzed).

use crate::{
    keys::{AccountKey, BanKey, Cidr, Family, FingerprintKey, SessionKey, TenantKey},
    revoke::Target,
};

/// Largest encoded record accepted.
pub(crate) const MAX_RECORD: usize = 256;

const T_BAN: u8 = 1;
const T_LIFT: u8 = 2;
const T_REMOVE: u8 = 3;
const T_OFFENCE: u8 = 4;
const T_REVOKE: u8 = 5;
/// A lift with its scope (format 2). Type 2 is the format-1 lift, read as a
/// lift of every origin (what it meant then).
const T_LIFT_SCOPED: u8 = 6;

/// One state change.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum Rec {
    /// A ban as stored: wall times in Unix seconds (0 = permanent for
    /// `until`), its original length (0 = permanent), and its HLC stamp.
    Ban {
        key: BanKey,
        until: u64,
        issued: u64,
        length: u64,
        actor: u8,
        reason: u16,
        offences: u16,
        id: u64,
        stamp: u64,
    },
    /// A lift: a tombstone stamped with its clock. `all`: it covers every
    /// origin's bans (an administrator's lift), not only its own origin's.
    Lift {
        key: BanKey,
        stamp: u64,
        actor: u8,
        all: bool,
    },
    /// A ban removed without a lift (folded, evicted, or allow-listed).
    Remove { key: BanKey },
    /// An offender record: the decayed score as of `last` (Unix seconds).
    Offence { key: BanKey, score: f32, last: u64 },
    /// A revocation (sharing only).
    Revoke {
        target: Target,
        code: u8,
        keep_connection: bool,
        eject_now: bool,
        actor: u8,
        reason: u16,
        stamp: u64,
    },
}

/// A record with its origin.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Envelope {
    pub(crate) origin: u16,
    pub(crate) seq: u64,
    pub(crate) rec: Rec,
}

/// A decoding failure at a byte offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Bad(pub(crate) u64);

/// CRC32C (Castagnoli), table-driven.
pub(crate) fn crc32c(data: &[u8]) -> u32 {
    const fn table() -> [u32; 256] {
        let mut t = [0u32; 256];
        let mut i = 0;
        while i < 256 {
            let mut c = i as u32;
            let mut k = 0;
            while k < 8 {
                c = if c & 1 != 0 {
                    (c >> 1) ^ 0x82f6_3b78
                } else {
                    c >> 1
                };
                k += 1;
            }
            t[i] = c;
            i += 1;
        }
        t
    }
    static TABLE: [u32; 256] = table();
    let mut crc = !0u32;
    for &b in data {
        crc = TABLE[((crc ^ u32::from(b)) & 0xff) as usize] ^ (crc >> 8);
    }
    !crc
}

/// Appends little-endian values.
pub(crate) struct Writer<'a>(pub(crate) &'a mut Vec<u8>);

impl Writer<'_> {
    pub(crate) fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    pub(crate) fn u16(&mut self, v: u16) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    pub(crate) fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    pub(crate) fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    pub(crate) fn u128(&mut self, v: u128) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    pub(crate) fn bytes(&mut self, b: &[u8]) {
        self.0.extend_from_slice(b);
    }
}

/// Reads little-endian values; every read is bounds-checked.
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    /// Offset of `buf` in the whole input, for error offsets.
    base: u64,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8], base: u64) -> Reader<'a> {
        Reader { buf, pos: 0, base }
    }

    pub(crate) fn offset(&self) -> u64 {
        self.base + self.pos as u64
    }

    pub(crate) fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], Bad> {
        if self.remaining() < n {
            return Err(Bad(self.offset()));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], Bad> {
        let s = self.take(N)?;
        let mut a = [0u8; N];
        a.copy_from_slice(s);
        Ok(a)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, Bad> {
        Ok(self.array::<1>()?[0])
    }
    pub(crate) fn u16(&mut self) -> Result<u16, Bad> {
        Ok(u16::from_le_bytes(self.array()?))
    }
    pub(crate) fn u32(&mut self) -> Result<u32, Bad> {
        Ok(u32::from_le_bytes(self.array()?))
    }
    pub(crate) fn u64(&mut self) -> Result<u64, Bad> {
        Ok(u64::from_le_bytes(self.array()?))
    }
    pub(crate) fn u128(&mut self) -> Result<u128, Bad> {
        Ok(u128::from_le_bytes(self.array()?))
    }
}

fn family_code(f: Family) -> u8 {
    match f {
        Family::V4 => 4,
        Family::V6 => 6,
    }
}

fn put_cidr(w: &mut Writer<'_>, c: &Cidr) {
    w.u8(family_code(c.family()));
    w.u8(c.len());
    w.u128(c.bits());
}

fn get_cidr(r: &mut Reader<'_>) -> Result<Cidr, Bad> {
    let at = r.offset();
    let fam = match r.u8()? {
        4 => Family::V4,
        6 => Family::V6,
        _ => return Err(Bad(at)),
    };
    let len = r.u8()?;
    let bits = r.u128()?;
    let c = Cidr::from_parts(fam, len, bits).ok_or(Bad(at))?;
    // Host bits set or IPv4 bits above 32: not something we wrote.
    if c.bits() != bits {
        return Err(Bad(at));
    }
    Ok(c)
}

fn put_digest(w: &mut Writer<'_>, (hi, lo): (u64, u64)) {
    w.u64(hi);
    w.u64(lo);
}

fn put_key(w: &mut Writer<'_>, key: &BanKey) {
    match *key {
        BanKey::Address(a) => {
            w.u8(1);
            put_cidr(w, &Cidr::host(a));
        }
        BanKey::Prefix(c) => {
            w.u8(2);
            put_cidr(w, &c);
        }
        BanKey::Session(s) => {
            w.u8(3);
            put_digest(w, s.words());
        }
        BanKey::Account(a) => {
            w.u8(4);
            w.u128(a.0);
        }
        BanKey::Tenant(t) => {
            w.u8(5);
            w.u64(t.0);
        }
        BanKey::Fingerprint(f) => {
            w.u8(6);
            put_digest(w, f.words());
        }
        BanKey::FingerprintIn(f, c) => {
            w.u8(7);
            put_digest(w, f.words());
            put_cidr(w, &c);
        }
    }
}

fn get_key(r: &mut Reader<'_>) -> Result<BanKey, Bad> {
    let at = r.offset();
    Ok(match r.u8()? {
        1 => {
            let c = get_cidr(r)?;
            if c.len() != c.family().max_len() {
                return Err(Bad(at));
            }
            BanKey::Address(c.network())
        }
        2 => BanKey::Prefix(get_cidr(r)?),
        3 => BanKey::Session(SessionKey::from_words(r.u64()?, r.u64()?)),
        4 => BanKey::Account(AccountKey(r.u128()?)),
        5 => BanKey::Tenant(TenantKey(r.u64()?)),
        6 => BanKey::Fingerprint(FingerprintKey::from_words(r.u64()?, r.u64()?)),
        7 => {
            let f = FingerprintKey::from_words(r.u64()?, r.u64()?);
            BanKey::FingerprintIn(f, get_cidr(r)?)
        }
        _ => return Err(Bad(at)),
    })
}

fn put_target(w: &mut Writer<'_>, t: &Target) -> bool {
    match *t {
        Target::Source(c) => {
            w.u8(1);
            put_cidr(w, &c);
        }
        Target::Session(s) => {
            w.u8(2);
            put_digest(w, s.words());
        }
        Target::Account(a) => {
            w.u8(3);
            w.u128(a.0);
        }
        Target::Tenant(t) => {
            w.u8(4);
            w.u64(t.0);
        }
        Target::Fingerprint(f) => {
            w.u8(5);
            put_digest(w, f.words());
        }
        // Connection and request ids mean nothing on another node.
        Target::Connection(_) | Target::Request(_) => return false,
    }
    true
}

fn get_target(r: &mut Reader<'_>) -> Result<Target, Bad> {
    let at = r.offset();
    Ok(match r.u8()? {
        1 => Target::Source(get_cidr(r)?),
        2 => Target::Session(SessionKey::from_words(r.u64()?, r.u64()?)),
        3 => Target::Account(AccountKey(r.u128()?)),
        4 => Target::Tenant(TenantKey(r.u64()?)),
        5 => Target::Fingerprint(FingerprintKey::from_words(r.u64()?, r.u64()?)),
        _ => return Err(Bad(at)),
    })
}

/// Appends one record. Returns `false` (nothing written) for a record that
/// cannot travel (a revocation of a connection or request id).
pub(crate) fn encode(out: &mut Vec<u8>, env: &Envelope) -> bool {
    let start = out.len();
    out.extend_from_slice(&[0; 4]);
    let body = out.len();
    let mut w = Writer(out);
    let ty = match env.rec {
        Rec::Ban { .. } => T_BAN,
        Rec::Lift { .. } => T_LIFT_SCOPED,
        Rec::Remove { .. } => T_REMOVE,
        Rec::Offence { .. } => T_OFFENCE,
        Rec::Revoke { .. } => T_REVOKE,
    };
    w.u8(ty);
    w.u16(env.origin);
    w.u64(env.seq);
    match env.rec {
        Rec::Ban {
            key,
            until,
            issued,
            length,
            actor,
            reason,
            offences,
            id,
            stamp,
        } => {
            put_key(&mut w, &key);
            w.u64(until);
            w.u64(issued);
            w.u64(length);
            w.u8(actor);
            w.u16(reason);
            w.u16(offences);
            w.u64(id);
            w.u64(stamp);
        }
        Rec::Lift {
            key,
            stamp,
            actor,
            all,
        } => {
            put_key(&mut w, &key);
            w.u64(stamp);
            w.u8(actor);
            w.u8(u8::from(all));
        }
        Rec::Remove { key } => put_key(&mut w, &key),
        Rec::Offence { key, score, last } => {
            put_key(&mut w, &key);
            w.u32(score.to_bits());
            w.u64(last);
        }
        Rec::Revoke {
            target,
            code,
            keep_connection,
            eject_now,
            actor,
            reason,
            stamp,
        } => {
            if !put_target(&mut w, &target) {
                out.truncate(start);
                return false;
            }
            let mut w = Writer(out);
            w.u8(code);
            w.u8(u8::from(keep_connection) | (u8::from(eject_now) << 1));
            w.u8(actor);
            w.u16(reason);
            w.u64(stamp);
        }
    }
    let len = (out.len() - body) as u32;
    out[start..start + 4].copy_from_slice(&len.to_le_bytes());
    let crc = crc32c(&out[body..]);
    out.extend_from_slice(&crc.to_le_bytes());
    true
}

/// Reads one record.
pub(crate) fn decode(r: &mut Reader<'_>) -> Result<Envelope, Bad> {
    let at = r.offset();
    let len = r.u32()? as usize;
    if len == 0 || len > MAX_RECORD {
        return Err(Bad(at));
    }
    let body = r.take(len)?;
    let crc = r.u32()?;
    if crc32c(body) != crc {
        return Err(Bad(at));
    }
    let mut b = Reader::new(body, at + 4);
    let ty = b.u8()?;
    let origin = b.u16()?;
    let seq = b.u64()?;
    let rec = match ty {
        T_BAN => Rec::Ban {
            key: get_key(&mut b)?,
            until: b.u64()?,
            issued: b.u64()?,
            length: b.u64()?,
            actor: b.u8()?,
            reason: b.u16()?,
            offences: b.u16()?,
            id: b.u64()?,
            stamp: b.u64()?,
        },
        T_LIFT => Rec::Lift {
            key: get_key(&mut b)?,
            stamp: b.u64()?,
            actor: b.u8()?,
            all: true,
        },
        T_LIFT_SCOPED => {
            let key = get_key(&mut b)?;
            let stamp = b.u64()?;
            let actor = b.u8()?;
            let all = match b.u8()? {
                0 => false,
                1 => true,
                _ => return Err(Bad(at)),
            };
            Rec::Lift {
                key,
                stamp,
                actor,
                all,
            }
        }
        T_REMOVE => Rec::Remove {
            key: get_key(&mut b)?,
        },
        T_OFFENCE => {
            let key = get_key(&mut b)?;
            let score = f32::from_bits(b.u32()?);
            if !score.is_finite() || score < 0.0 {
                return Err(Bad(at));
            }
            Rec::Offence {
                key,
                score,
                last: b.u64()?,
            }
        }
        T_REVOKE => {
            let target = get_target(&mut b)?;
            let code = b.u8()?;
            let flags = b.u8()?;
            Rec::Revoke {
                target,
                code,
                keep_connection: flags & 1 != 0,
                eject_now: flags & 2 != 0,
                actor: b.u8()?,
                reason: b.u16()?,
                stamp: b.u64()?,
            }
        }
        _ => return Err(Bad(at)),
    };
    if b.remaining() != 0 {
        return Err(Bad(at));
    }
    Ok(Envelope { origin, seq, rec })
}

#[cfg(all(test, not(bouncer_loom)))]
mod tests {
    use super::*;

    fn c(s: &str) -> Cidr {
        s.parse().unwrap()
    }

    fn all() -> Vec<Envelope> {
        let fp = FingerprintKey::from_digest([7; 16]);
        let keys = [
            BanKey::Address("192.0.2.1".parse().unwrap()),
            BanKey::Address("2001:db8::1".parse().unwrap()),
            BanKey::Prefix(c("2001:db8::/48")),
            BanKey::Session(SessionKey::from_digest([1; 16])),
            BanKey::Account(AccountKey(u128::MAX - 3)),
            BanKey::Tenant(TenantKey(9)),
            BanKey::Fingerprint(fp),
            BanKey::FingerprintIn(fp, c("198.51.100.0/24")),
        ];
        let mut v: Vec<Envelope> = keys
            .iter()
            .enumerate()
            .map(|(i, &key)| Envelope {
                origin: 3,
                seq: i as u64,
                rec: Rec::Ban {
                    key,
                    until: 1_800_000_000,
                    issued: 1_799_999_000,
                    length: 1000,
                    actor: 1,
                    reason: 6,
                    offences: 2,
                    id: 77,
                    stamp: 123 << 16,
                },
            })
            .collect();
        v.push(Envelope {
            origin: 0,
            seq: 99,
            rec: Rec::Lift {
                key: keys[0],
                stamp: 5,
                actor: 1,
                all: false,
            },
        });
        v.push(Envelope {
            origin: 3,
            seq: 98,
            rec: Rec::Lift {
                key: keys[1],
                stamp: 6,
                actor: 2,
                all: true,
            },
        });
        v.push(Envelope {
            origin: 0,
            seq: 100,
            rec: Rec::Remove { key: keys[2] },
        });
        v.push(Envelope {
            origin: 0,
            seq: 101,
            rec: Rec::Offence {
                key: keys[3],
                score: 1.5,
                last: 42,
            },
        });
        v.push(Envelope {
            origin: 2,
            seq: 102,
            rec: Rec::Revoke {
                target: Target::Account(AccountKey(5)),
                code: 5,
                keep_connection: true,
                eject_now: false,
                actor: 4,
                reason: 4,
                stamp: 9,
            },
        });
        v
    }

    #[test]
    fn test_codec_round_trips_every_record() {
        let mut buf = Vec::new();
        for e in all() {
            assert!(encode(&mut buf, &e));
        }
        let mut r = Reader::new(&buf, 0);
        for e in all() {
            assert_eq!(decode(&mut r).unwrap(), e);
        }
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn test_codec_reads_format_1_lifts_as_lifts_of_every_origin() {
        // A format-1 lift (type 2: key, stamp, actor) as 0.6 wrote it.
        let key = BanKey::Address("192.0.2.1".parse().unwrap());
        let mut body = Vec::new();
        let mut w = Writer(&mut body);
        w.u8(T_LIFT);
        w.u16(4);
        w.u64(17);
        put_key(&mut w, &key);
        w.u64(5 << 16);
        w.u8(1);
        let mut buf = (body.len() as u32).to_le_bytes().to_vec();
        buf.extend_from_slice(&body);
        buf.extend_from_slice(&crc32c(&body).to_le_bytes());
        let mut r = Reader::new(&buf, 0);
        let e = decode(&mut r).unwrap();
        assert_eq!(
            e,
            Envelope {
                origin: 4,
                seq: 17,
                rec: Rec::Lift {
                    key,
                    stamp: 5 << 16,
                    actor: 1,
                    all: true,
                },
            }
        );
    }

    #[test]
    fn test_codec_refuses_every_corruption() {
        let mut buf = Vec::new();
        encode(&mut buf, &all()[7]);
        for i in 0..buf.len() {
            for bit in 0..8 {
                let mut bad = buf.clone();
                bad[i] ^= 1 << bit;
                let mut r = Reader::new(&bad, 0);
                assert!(decode(&mut r).is_err(), "flip at {i}.{bit} accepted");
            }
        }
        for cut in 0..buf.len() {
            let mut r = Reader::new(&buf[..cut], 0);
            assert!(decode(&mut r).is_err());
        }
    }

    #[test]
    fn test_connection_revocations_do_not_travel() {
        let mut buf = Vec::new();
        let e = Envelope {
            origin: 1,
            seq: 1,
            rec: Rec::Revoke {
                target: Target::Connection(crate::keys::ConnId(3)),
                code: 5,
                keep_connection: false,
                eject_now: false,
                actor: 0,
                reason: 1,
                stamp: 1,
            },
        };
        assert!(!encode(&mut buf, &e));
        assert!(buf.is_empty());
    }

    #[test]
    fn test_crc32c_known_value() {
        assert_eq!(crc32c(b"123456789"), 0xe306_9283);
    }
}
