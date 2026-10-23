//! Keys: addresses and prefixes, connection and request ids, and identity
//! digests. Addresses are normalized once, at every public entry point.

use core::{fmt, str::FromStr};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::error::BouncerError;

/// Longest prefix text accepted by [`Cidr::parse`], in bytes.
pub(crate) const MAX_CIDR_TEXT: usize = 64;

/// An address family.
///
/// # Examples
///
/// ```
/// use bouncer_io::{Cidr, Family};
/// assert_eq!("2001:db8::/32".parse::<Cidr>()?.family(), Family::V6);
/// # Ok::<(), bouncer_io::BouncerError>(())
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Family {
    /// IPv4.
    V4,
    /// IPv6.
    V6,
}

impl Family {
    /// The longest prefix length of the family: 32 or 128.
    #[must_use]
    pub const fn max_len(self) -> u8 {
        match self {
            Self::V4 => 32,
            Self::V6 => 128,
        }
    }
}

impl fmt::Display for Family {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::V4 => "IPv4",
            Self::V6 => "IPv6",
        })
    }
}

/// Maps IPv4-mapped IPv6 (`::ffff:a.b.c.d`) to IPv4 and leaves every other
/// address alone.
///
/// The deprecated IPv4-compatible form (`::a.b.c.d`), NAT64 (`64:ff9b::/96`),
/// Teredo, and 6to4 stay IPv6: the IPv4 address embedded in them is chosen by
/// the client, so it is never used as a key.
///
/// # Examples
///
/// ```
/// use bouncer_io::normalize;
/// use std::net::IpAddr;
///
/// let mapped: IpAddr = "::ffff:203.0.113.7".parse()?;
/// assert_eq!(normalize(mapped), "203.0.113.7".parse::<IpAddr>()?);
/// let nat64: IpAddr = "64:ff9b::cb00:7107".parse()?;
/// assert_eq!(normalize(nat64), nat64);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[inline]
#[must_use]
pub fn normalize(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

/// The prefix of length `len` that contains `addr` (normalized first).
///
/// # Errors
///
/// [`BouncerError::InvalidPrefix`] when `len` is longer than the family allows.
///
/// # Examples
///
/// ```
/// let p = bouncer_io::prefix_of("2001:db8::1234".parse()?, 64)?;
/// assert_eq!(p.to_string(), "2001:db8::/64");
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn prefix_of(addr: IpAddr, len: u8) -> Result<Cidr, BouncerError> {
    Cidr::new(normalize(addr), len)
}

/// A network prefix: a normalized network address and a length, with every
/// bit below the length cleared.
///
/// # Examples
///
/// ```
/// use bouncer_io::Cidr;
///
/// let net: Cidr = "2001:db8:aa::/48".parse()?;
/// assert!(net.contains("2001:db8:aa:1::5".parse()?));
/// assert_eq!(net.parent(32).unwrap().to_string(), "2001:db8::/32");
/// assert_eq!("10.0.0.5/24".parse::<Cidr>()?.to_string(), "10.0.0.0/24");
/// assert!(Cidr::parse_strict("10.0.0.5/24").is_err());
/// assert!(Cidr::parse("010.0.0.1").is_err());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Cidr {
    family: Family,
    len: u8,
    bits: u128,
}

impl Cidr {
    /// A prefix of `len` bits containing `addr`. Host bits are cleared.
    /// IPv4-mapped IPv6 with a length of 96 or more becomes the IPv4 prefix.
    ///
    /// # Errors
    ///
    /// [`BouncerError::InvalidPrefix`] for a length above 32 (IPv4) or 128 (IPv6).
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::Cidr;
    /// let c = Cidr::new("192.0.2.77".parse()?, 24)?;
    /// assert_eq!(c.to_string(), "192.0.2.0/24");
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn new(addr: IpAddr, len: u8) -> Result<Cidr, BouncerError> {
        let (cidr, _) = Self::build(addr, len)?;
        Ok(cidr)
    }

    /// The host prefix of `addr`: /32 for IPv4, /128 for IPv6.
    ///
    /// # Examples
    ///
    /// ```
    /// let c = bouncer_io::Cidr::host("2001:db8::1".parse()?);
    /// assert_eq!(c.len(), 128);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub fn host(addr: IpAddr) -> Cidr {
        match normalize(addr) {
            IpAddr::V4(v4) => Cidr {
                family: Family::V4,
                len: 32,
                bits: u128::from(u32::from(v4)),
            },
            IpAddr::V6(v6) => Cidr {
                family: Family::V6,
                len: 128,
                bits: u128::from(v6),
            },
        }
    }

    /// Parses `"203.0.113.0/24"`, `"2001:db8::/48"`, or a bare address (a
    /// host prefix). Host bits are cleared.
    ///
    /// Refused: more than 64 bytes, whitespace, zone ids (`fe80::1%eth0`),
    /// leading zeros in IPv4 octets (`010.0.0.1`, ambiguous between decimal and
    /// octal) and in the length.
    ///
    /// # Errors
    ///
    /// [`BouncerError::ParseCidr`] with the byte offset of the first bad
    /// character; [`BouncerError::InvalidPrefix`] for a length out of range.
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::{BouncerError, Cidr};
    /// assert_eq!(Cidr::parse("198.51.100.0/24")?.len(), 24);
    /// assert_eq!(Cidr::parse("fe80::1%eth0"), Err(BouncerError::ParseCidr { position: 7 }));
    /// # Ok::<(), BouncerError>(())
    /// ```
    pub fn parse(text: &str) -> Result<Cidr, BouncerError> {
        let (addr, len) = parse_text(text)?;
        Self::new(addr, len)
    }

    /// As [`parse`](Self::parse), and also refuses host bits set below the
    /// length.
    ///
    /// # Errors
    ///
    /// As `parse`, plus [`BouncerError::InvalidPrefix`] with
    /// `host_bits_set: true`.
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::Cidr;
    /// assert!(Cidr::parse_strict("10.0.0.0/24").is_ok());
    /// assert!(Cidr::parse_strict("10.0.0.5/24").is_err());
    /// ```
    pub fn parse_strict(text: &str) -> Result<Cidr, BouncerError> {
        let (addr, len) = parse_text(text)?;
        let (cidr, host_bits) = Self::build(addr, len)?;
        if host_bits {
            return Err(BouncerError::InvalidPrefix {
                len: cidr.len,
                family: cidr.family,
                host_bits_set: true,
            });
        }
        Ok(cidr)
    }

    /// `true` when `addr` (normalized) falls inside this prefix.
    ///
    /// # Examples
    ///
    /// ```
    /// let c: bouncer_io::Cidr = "203.0.113.0/24".parse()?;
    /// assert!(c.contains("::ffff:203.0.113.9".parse()?));
    /// assert!(!c.contains("203.0.114.9".parse()?));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub fn contains(&self, addr: IpAddr) -> bool {
        let host = Cidr::host(addr);
        host.family == self.family && mask(host.bits, self.len, self.family) == self.bits
    }

    /// `true` when `other` lies entirely inside this prefix.
    pub(crate) fn covers(&self, other: &Cidr) -> bool {
        other.family == self.family
            && other.len >= self.len
            && mask(other.bits, self.len, self.family) == self.bits
    }

    /// The address family.
    #[must_use]
    pub fn family(&self) -> Family {
        self.family
    }

    /// The prefix length.
    #[must_use]
    #[allow(clippy::len_without_is_empty)] // a prefix length, not a collection
    pub fn len(&self) -> u8 {
        self.len
    }

    /// The network address (host bits cleared).
    #[must_use]
    pub fn network(&self) -> IpAddr {
        match self.family {
            Family::V4 => IpAddr::V4(Ipv4Addr::from(self.bits as u32)),
            Family::V6 => IpAddr::V6(Ipv6Addr::from(self.bits)),
        }
    }

    /// The shorter prefix of length `len` containing this one; `None` when
    /// `len` is longer than this prefix.
    ///
    /// # Examples
    ///
    /// ```
    /// let c: bouncer_io::Cidr = "2001:db8:aa:bb::/64".parse()?;
    /// assert_eq!(c.parent(48).unwrap().to_string(), "2001:db8:aa::/48");
    /// assert!(c.parent(65).is_none());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub fn parent(&self, len: u8) -> Option<Cidr> {
        (len <= self.len).then(|| Cidr {
            family: self.family,
            len,
            bits: mask(self.bits, len, self.family),
        })
    }

    /// The prefix bits, right-aligned in a `u128` (IPv4 in the low 32 bits).
    pub(crate) fn bits(&self) -> u128 {
        self.bits
    }

    /// A prefix from stored parts; host bits are cleared. `None` for a
    /// length beyond the family's.
    pub(crate) fn from_parts(family: Family, len: u8, bits: u128) -> Option<Cidr> {
        if len > family.max_len() {
            return None;
        }
        let bits = match family {
            Family::V4 => bits & 0xffff_ffff,
            Family::V6 => bits,
        };
        Some(Cidr {
            family,
            len,
            bits: mask(bits, len, family),
        })
    }

    /// Builds the prefix and reports whether host bits had to be cleared.
    fn build(addr: IpAddr, len: u8) -> Result<(Cidr, bool), BouncerError> {
        let (family, raw, len) = match addr {
            IpAddr::V4(v4) => (Family::V4, u128::from(u32::from(v4)), len),
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) if (96..=128).contains(&len) => {
                    (Family::V4, u128::from(u32::from(v4)), len - 96)
                }
                _ => (Family::V6, u128::from(v6), len),
            },
        };
        if len > family.max_len() {
            return Err(BouncerError::InvalidPrefix {
                len,
                family,
                host_bits_set: false,
            });
        }
        let bits = mask(raw, len, family);
        Ok((Cidr { family, len, bits }, bits != raw))
    }
}

/// Clears every bit below `len` for the family.
#[inline]
pub(crate) fn mask(bits: u128, len: u8, family: Family) -> u128 {
    let width = u32::from(family.max_len());
    let len = u32::from(len).min(width);
    if len == 0 {
        return 0;
    }
    let keep = (u128::MAX << (width - len)) & width_mask(family);
    bits & keep
}

#[inline]
const fn width_mask(family: Family) -> u128 {
    match family {
        Family::V4 => u32::MAX as u128,
        Family::V6 => u128::MAX,
    }
}

impl From<IpAddr> for Cidr {
    fn from(addr: IpAddr) -> Self {
        Cidr::host(addr)
    }
}

impl FromStr for Cidr {
    type Err = BouncerError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Cidr::parse(s)
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network(), self.len)
    }
}

impl fmt::Debug for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Cidr({self})")
    }
}

/// Parses address text plus optional `/len` into an address and a length.
fn parse_text(text: &str) -> Result<(IpAddr, u8), BouncerError> {
    let b = text.as_bytes();
    if b.len() > MAX_CIDR_TEXT {
        return Err(BouncerError::ParseCidr {
            position: MAX_CIDR_TEXT as u8,
        });
    }
    let slash = b.iter().position(|&c| c == b'/');
    let addr_end = slash.unwrap_or(b.len());
    let addr_bytes = &b[..addr_end];
    let is_v6 = addr_bytes.contains(&b':');
    let addr = if is_v6 {
        IpAddr::V6(Ipv6Addr::from(parse_v6(addr_bytes, 0).map_err(position)?))
    } else {
        IpAddr::V4(Ipv4Addr::from(parse_v4(addr_bytes, 0).map_err(position)?))
    };
    let len = match slash {
        None => {
            if is_v6 {
                128
            } else {
                32
            }
        }
        Some(at) => parse_len(&b[at + 1..], at + 1).map_err(position)?,
    };
    Ok((addr, len))
}

fn position(at: usize) -> BouncerError {
    // Input is bounded at 64 bytes, so every offset fits.
    BouncerError::ParseCidr {
        position: at.min(MAX_CIDR_TEXT) as u8,
    }
}

/// A decimal prefix length: 1 to 3 digits, no sign, no leading zeros.
fn parse_len(b: &[u8], base: usize) -> Result<u8, usize> {
    if b.is_empty() {
        return Err(base);
    }
    if b.len() > 3 {
        return Err(base + 3);
    }
    if b[0] == b'0' && b.len() > 1 {
        return Err(base + 1);
    }
    let mut v: u16 = 0;
    for (i, &c) in b.iter().enumerate() {
        if !c.is_ascii_digit() {
            return Err(base + i);
        }
        v = v * 10 + u16::from(c - b'0');
    }
    u8::try_from(v).map_err(|_| base)
}

/// Dotted-quad IPv4: exactly four decimal octets, no leading zeros.
fn parse_v4(b: &[u8], base: usize) -> Result<u32, usize> {
    let mut out: u32 = 0;
    let mut i = 0;
    for octet in 0..4 {
        if octet > 0 {
            if i >= b.len() || b[i] != b'.' {
                return Err(base + i);
            }
            i += 1;
        }
        let start = i;
        let mut v: u16 = 0;
        while i < b.len() && b[i].is_ascii_digit() {
            if i - start == 3 {
                return Err(base + i);
            }
            v = v * 10 + u16::from(b[i] - b'0');
            i += 1;
        }
        if i == start {
            return Err(base + i);
        }
        if b[start] == b'0' && i - start > 1 {
            return Err(base + start + 1);
        }
        if v > 255 {
            return Err(base + start);
        }
        out = (out << 8) | u32::from(v);
    }
    if i != b.len() {
        return Err(base + i);
    }
    Ok(out)
}

/// RFC 4291 IPv6 text: up to eight groups of 1-4 hex digits, one `::`, an
/// optional trailing dotted quad. No zone ids.
fn parse_v6(b: &[u8], base: usize) -> Result<u128, usize> {
    let mut groups = [0u16; 8];
    let mut n = 0usize;
    let mut gap: Option<usize> = None;
    let mut i = 0usize;
    if b.len() >= 2 && b[0] == b':' && b[1] == b':' {
        gap = Some(0);
        i = 2;
    } else if b.first() == Some(&b':') {
        return Err(base + 1);
    }
    while i < b.len() {
        // An embedded IPv4 address ends the text.
        let token_end = b[i..]
            .iter()
            .position(|&c| c == b':')
            .map_or(b.len(), |p| i + p);
        if b[i..token_end].contains(&b'.') {
            if n > 6 || token_end != b.len() {
                return Err(base + i);
            }
            let v4 = parse_v4(&b[i..token_end], base + i)?;
            groups[n] = (v4 >> 16) as u16;
            groups[n + 1] = v4 as u16;
            n += 2;
            break;
        }
        let start = i;
        let mut v: u32 = 0;
        while i < b.len() && b[i].is_ascii_hexdigit() {
            if i - start == 4 {
                return Err(base + i);
            }
            v = (v << 4) | hex(b[i]);
            i += 1;
        }
        if i == start {
            return Err(base + i);
        }
        if n == 8 {
            return Err(base + start);
        }
        groups[n] = v as u16;
        n += 1;
        if i == b.len() {
            break;
        }
        if b[i] != b':' {
            return Err(base + i);
        }
        i += 1;
        if i < b.len() && b[i] == b':' {
            if gap.is_some() {
                return Err(base + i);
            }
            gap = Some(n);
            i += 1;
            if i == b.len() {
                break;
            }
        } else if i == b.len() {
            return Err(base + i);
        }
    }
    let mut out = [0u16; 8];
    match gap {
        Some(at) => {
            if n >= 8 {
                return Err(base + b.len());
            }
            out[..at].copy_from_slice(&groups[..at]);
            let tail = n - at;
            out[8 - tail..].copy_from_slice(&groups[at..n]);
        }
        None => {
            if n != 8 {
                return Err(base + b.len());
            }
            out = groups;
        }
    }
    Ok(out
        .iter()
        .fold(0u128, |acc, &g| (acc << 16) | u128::from(g)))
}

#[inline]
fn hex(c: u8) -> u32 {
    match c {
        b'0'..=b'9' => u32::from(c - b'0'),
        b'a'..=b'f' => u32::from(c - b'a' + 10),
        _ => u32::from(c - b'A' + 10),
    }
}

/// A connection id from the transport. net-io never reuses one in a process.
///
/// # Examples
///
/// ```
/// let id = bouncer_io::ConnId(41);
/// assert_eq!(id.0, 41);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConnId(pub u64);

/// A request id, opaque to bouncer (a ULID from the request layer fits).
///
/// # Examples
///
/// ```
/// let id = bouncer_io::RequestId(0x0192_5f3e_1111_7abc_8000_0000_0000_0001);
/// # let _ = id;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RequestId(pub u128);

/// An account: the user id (a UUIDv7 as `u128`).
///
/// # Examples
///
/// ```
/// let account = bouncer_io::AccountKey(42);
/// # let _ = account;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AccountKey(pub u128);

/// A tenant number from the identity stamp.
///
/// # Examples
///
/// ```
/// let tenant = bouncer_io::TenantKey(7);
/// # let _ = tenant;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TenantKey(pub u64);

/// Constant-time equality of two 16-byte digests: no early exit.
#[inline]
fn digest_eq(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= a[i] ^ b[i];
    }
    core::hint::black_box(diff) == 0
}

macro_rules! digest_key {
    ($(#[$doc:meta])* $name:ident, $label:literal) => {
        $(#[$doc])*
        #[derive(Clone, Copy)]
        pub struct $name([u8; 16]);

        impl $name {
            /// Wraps a 16-byte digest. Pass a keyed digest, never the secret itself.
            #[must_use]
            pub const fn from_digest(bytes: [u8; 16]) -> $name {
                $name(bytes)
            }

            /// The digest from the two words of [`words`](Self::words).
            pub(crate) fn from_words(hi: u64, lo: u64) -> $name {
                let (h, l) = (hi.to_be_bytes(), lo.to_be_bytes());
                $name([
                    h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7],
                    l[0], l[1], l[2], l[3], l[4], l[5], l[6], l[7],
                ])
            }

            /// The digest as two words, for the tables.
            pub(crate) fn words(&self) -> (u64, u64) {
                let hi = u64::from_be_bytes([
                    self.0[0], self.0[1], self.0[2], self.0[3],
                    self.0[4], self.0[5], self.0[6], self.0[7],
                ]);
                let lo = u64::from_be_bytes([
                    self.0[8], self.0[9], self.0[10], self.0[11],
                    self.0[12], self.0[13], self.0[14], self.0[15],
                ]);
                (hi, lo)
            }
        }

        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                digest_eq(&self.0, &other.0)
            }
        }

        impl Eq for $name {}

        impl core::hash::Hash for $name {
            fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
                self.0.hash(state);
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!($label, "(..)"))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!($label, "(..)"))
            }
        }
    };
}

digest_key!(
    /// A session: a keyed digest of the session token, never the token.
    ///
    /// Equality is constant time; `Debug` and `Display` never print the bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::SessionKey;
    /// let a = SessionKey::from_digest([9; 16]);
    /// assert_eq!(a, SessionKey::from_digest([9; 16]));
    /// assert_eq!(format!("{a:?}"), "SessionKey(..)");
    /// ```
    SessionKey,
    "SessionKey"
);

digest_key!(
    /// A client fingerprint: a digest of the TLS ClientHello fingerprint.
    ///
    /// A weak identifier: every client of one browser build shares it, so
    /// automation bans it only within a prefix ([`BanKey::FingerprintIn`]).
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::FingerprintKey;
    /// let fp = FingerprintKey::from_digest([1; 16]);
    /// assert_eq!(fp.to_string(), "FingerprintKey(..)");
    /// ```
    FingerprintKey,
    "FingerprintKey"
);

/// What a ban, lift, or explanation targets.
///
/// Every key type converts into it.
///
/// # Examples
///
/// ```
/// use bouncer_io::{AccountKey, BanKey, Cidr};
/// let a: BanKey = "203.0.113.7".parse::<std::net::IpAddr>()?.into();
/// let p: BanKey = "203.0.113.0/24".parse::<Cidr>()?.into();
/// let u: BanKey = AccountKey(42).into();
/// assert_ne!(a, p);
/// # let _ = u;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BanKey {
    /// One client: the IPv4 address, or the IPv6 address's /64.
    Address(IpAddr),
    /// A prefix.
    Prefix(Cidr),
    /// A session.
    Session(SessionKey),
    /// An account.
    Account(AccountKey),
    /// A tenant.
    Tenant(TenantKey),
    /// A fingerprint everywhere (administrators only).
    Fingerprint(FingerprintKey),
    /// A fingerprint within a prefix: the compound key automation uses.
    FingerprintIn(FingerprintKey, Cidr),
}

impl BanKey {
    /// Normalizes an address key.
    pub(crate) fn normalized(self) -> BanKey {
        match self {
            BanKey::Address(a) => BanKey::Address(normalize(a)),
            other => other,
        }
    }
}

impl From<IpAddr> for BanKey {
    fn from(a: IpAddr) -> Self {
        BanKey::Address(normalize(a))
    }
}
impl From<Cidr> for BanKey {
    fn from(c: Cidr) -> Self {
        BanKey::Prefix(c)
    }
}
impl From<SessionKey> for BanKey {
    fn from(k: SessionKey) -> Self {
        BanKey::Session(k)
    }
}
impl From<AccountKey> for BanKey {
    fn from(k: AccountKey) -> Self {
        BanKey::Account(k)
    }
}
impl From<TenantKey> for BanKey {
    fn from(k: TenantKey) -> Self {
        BanKey::Tenant(k)
    }
}
impl From<FingerprintKey> for BanKey {
    fn from(k: FingerprintKey) -> Self {
        BanKey::Fingerprint(k)
    }
}

impl fmt::Display for BanKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BanKey::Address(a) => write!(f, "{a}"),
            BanKey::Prefix(c) => write!(f, "{c}"),
            BanKey::Session(_) => f.write_str("session (redacted)"),
            BanKey::Account(a) => write!(f, "account {:#x}", a.0),
            BanKey::Tenant(t) => write!(f, "tenant {}", t.0),
            BanKey::Fingerprint(_) => f.write_str("fingerprint (redacted)"),
            BanKey::FingerprintIn(_, c) => write!(f, "fingerprint (redacted) in {c}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn test_normalize_mapped_becomes_v4() {
        assert_eq!(normalize(ip("::ffff:203.0.113.7")), ip("203.0.113.7"));
        assert_eq!(normalize(ip("203.0.113.7")), ip("203.0.113.7"));
    }

    #[test]
    fn test_normalize_compatible_nat64_teredo_6to4_stay_v6() {
        for s in [
            "::203.0.113.7",
            "64:ff9b::cb00:7107",
            "2001::1",
            "2002:cb00:7107::1",
        ] {
            assert_eq!(normalize(ip(s)), ip(s), "{s}");
        }
    }

    #[test]
    fn test_cidr_parse_v4_lengths_boundaries() {
        for len in [0u8, 1, 31, 32] {
            let c = Cidr::parse(&format!("203.0.113.7/{len}")).unwrap();
            assert_eq!(c.len(), len);
        }
        assert!(matches!(
            Cidr::parse("203.0.113.7/33"),
            Err(BouncerError::InvalidPrefix {
                len: 33,
                family: Family::V4,
                ..
            })
        ));
    }

    #[test]
    fn test_cidr_parse_v6_lengths_boundaries() {
        for len in [0u8, 1, 63, 64, 65, 127, 128] {
            let c = Cidr::parse(&format!("2001:db8::1/{len}")).unwrap();
            assert_eq!(c.len(), len);
        }
        assert!(matches!(
            Cidr::parse("2001:db8::1/129"),
            Err(BouncerError::InvalidPrefix {
                len: 129,
                family: Family::V6,
                ..
            })
        ));
    }

    #[test]
    fn test_cidr_parse_host_bits_cleared_and_strict_refuses() {
        assert_eq!(
            Cidr::parse("10.0.0.5/24").unwrap().to_string(),
            "10.0.0.0/24"
        );
        assert_eq!(
            Cidr::parse_strict("10.0.0.5/24"),
            Err(BouncerError::InvalidPrefix {
                len: 24,
                family: Family::V4,
                host_bits_set: true
            })
        );
        assert!(Cidr::parse_strict("10.0.0.0/24").is_ok());
    }

    #[test]
    fn test_cidr_parse_bare_address_is_host() {
        assert_eq!(Cidr::parse("192.0.2.1").unwrap().len(), 32);
        assert_eq!(Cidr::parse("2001:db8::1").unwrap().len(), 128);
    }

    #[test]
    fn test_cidr_parse_mapped_v6_text_becomes_v4() {
        let c = Cidr::parse("::ffff:203.0.113.0/120").unwrap();
        assert_eq!(c.family(), Family::V4);
        assert_eq!(c.to_string(), "203.0.113.0/24");
        let wide = Cidr::parse("::ffff:0:0/95").unwrap();
        assert_eq!(wide.family(), Family::V6);
    }

    #[test]
    fn test_cidr_parse_rejects_zone_id_with_position() {
        assert_eq!(
            Cidr::parse("fe80::1%eth0"),
            Err(BouncerError::ParseCidr { position: 7 })
        );
    }

    #[test]
    fn test_cidr_parse_rejects_whitespace_and_leading_zeros() {
        assert_eq!(
            Cidr::parse(" 10.0.0.1"),
            Err(BouncerError::ParseCidr { position: 0 })
        );
        assert_eq!(
            Cidr::parse("10.0.0.1 "),
            Err(BouncerError::ParseCidr { position: 8 })
        );
        assert_eq!(
            Cidr::parse("010.0.0.1"),
            Err(BouncerError::ParseCidr { position: 1 })
        );
        assert_eq!(
            Cidr::parse("10.0.0.0/024"),
            Err(BouncerError::ParseCidr { position: 10 })
        );
        assert!(Cidr::parse("0.0.0.0/0").is_ok());
    }

    #[test]
    fn test_cidr_parse_length_limit_64_and_65() {
        // 64 bytes: a valid full IPv6 text padded with an IPv4 tail is at most 45
        // characters, so build an invalid 64-byte text and a 65-byte one and
        // check that only the length check differs.
        let s64 = "1".repeat(64);
        let s65 = "1".repeat(65);
        assert_ne!(
            Cidr::parse(&s64),
            Err(BouncerError::ParseCidr { position: 64 })
        );
        assert_eq!(
            Cidr::parse(&s65),
            Err(BouncerError::ParseCidr { position: 64 })
        );
        let longest = "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255/128";
        assert!(Cidr::parse(longest).is_ok());
    }

    #[test]
    fn test_cidr_parse_v6_forms() {
        for (text, expect) in [
            ("::", "::/128"),
            ("::1", "::1/128"),
            ("1::", "1::/128"),
            ("2001:db8:0:0:0:0:0:1", "2001:db8::1/128"),
            ("2001:DB8::A", "2001:db8::a/128"),
            ("::ffff:1.2.3.4", "1.2.3.4/32"),
            ("64:ff9b::203.0.113.7", "64:ff9b::cb00:7107/128"),
        ] {
            assert_eq!(Cidr::parse(text).unwrap().to_string(), expect, "{text}");
        }
        for bad in [
            ":",
            ":::",
            "1:::2",
            "1::2::3",
            "1:2:3:4:5:6:7:8:9",
            "1:2:3:4:5:6:7",
            "12345::",
            "1:",
            "::g",
            "1::2:3:4:5:6:7:8",
        ] {
            assert!(Cidr::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn test_cidr_parse_matches_std_for_valid_v4() {
        for s in ["0.0.0.0", "255.255.255.255", "192.0.2.1", "10.20.30.40"] {
            assert_eq!(Cidr::parse(s).unwrap().network(), ip(s));
        }
        for bad in [
            "1.2.3",
            "1.2.3.4.5",
            "256.1.1.1",
            "1..2.3",
            "1.2.3.",
            ".1.2.3",
            "1.2.3.4/",
            "/24",
            "",
        ] {
            assert!(Cidr::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn test_cidr_contains_and_parent() {
        let c = Cidr::parse("203.0.113.0/24").unwrap();
        assert!(c.contains(ip("203.0.113.255")));
        assert!(c.contains(ip("::ffff:203.0.113.1")));
        assert!(!c.contains(ip("2001:db8::1")));
        assert_eq!(c.parent(16).unwrap().to_string(), "203.0.0.0/16");
        assert_eq!(c.parent(24), Some(c));
        assert!(c.parent(25).is_none());
        let all = Cidr::parse("0.0.0.0/0").unwrap();
        assert!(all.contains(ip("8.8.8.8")));
        assert!(all.covers(&c));
        assert!(!c.covers(&all));
    }

    #[test]
    fn test_prefix_of_v6_64() {
        assert_eq!(
            prefix_of(ip("2001:db8::1234"), 64).unwrap().to_string(),
            "2001:db8::/64"
        );
        assert!(prefix_of(ip("10.0.0.1"), 33).is_err());
    }

    #[test]
    fn test_digest_keys_constant_time_eq_and_redacted() {
        let a = SessionKey::from_digest([0xab; 16]);
        let b = SessionKey::from_digest([0xab; 16]);
        let mut other = [0xab; 16];
        other[15] = 0;
        assert_eq!(a, b);
        assert_ne!(a, SessionKey::from_digest(other));
        let dbg = format!("{a:?} {a} {}", BanKey::Session(a));
        assert!(!dbg.to_lowercase().contains("ab"), "{dbg}");
        let fp = FingerprintKey::from_digest([0xcd; 16]);
        let shown = format!(
            "{fp:?} {}",
            BanKey::FingerprintIn(fp, Cidr::host(ip("10.0.0.1")))
        );
        assert!(!shown.to_lowercase().contains("cd"), "{shown}");
    }

    #[test]
    fn test_bankey_from_normalizes() {
        assert_eq!(
            BanKey::from(ip("::ffff:10.0.0.1")),
            BanKey::Address(ip("10.0.0.1"))
        );
    }
}
