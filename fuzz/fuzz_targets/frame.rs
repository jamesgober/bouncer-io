#![allow(dead_code)]

//! Framing for the decoder targets: valid magic, lengths, and CRC32C around
//! fuzzed contents, so mutations reach the record decoder behind the
//! integrity checks instead of stopping at a checksum.

/// CRC32C (Castagnoli), bit by bit: slow and obviously correct.
pub fn crc32c(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0x82f6_3b78
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// Takes `n` bytes, padding with zeros when the input is short.
fn take<'a>(data: &mut &'a [u8], n: usize) -> Vec<u8> {
    let k = n.min(data.len());
    let mut v = data[..k].to_vec();
    v.resize(n, 0);
    *data = &data[k..];
    v
}

/// A delta: `BNCD`, `format` (1 or 2), then flags, origin, last, and count
/// from the input (16 bytes), the rest of the input as records, and the CRC.
pub fn delta(format: u16, mut data: &[u8]) -> Vec<u8> {
    let mut out = b"BNCD".to_vec();
    out.extend_from_slice(&format.to_le_bytes());
    out.extend(take(&mut data, 16));
    out.extend_from_slice(data);
    let crc = crc32c(&out);
    out.extend_from_slice(&crc.to_le_bytes());
    out
}

/// A snapshot without a MAC: `BNCR`, `format` (1 or 2), flags 0, then
/// created, epoch, node, hlc, and count from the input (34 bytes), the rest
/// as records, the length, and the CRC.
pub fn snapshot(format: u16, mut data: &[u8]) -> Vec<u8> {
    let mut out = b"BNCR".to_vec();
    out.extend_from_slice(&format.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend(take(&mut data, 34));
    out.extend_from_slice(data);
    let len = out.len() as u64;
    out.extend_from_slice(&len.to_le_bytes());
    let crc = crc32c(&out);
    out.extend_from_slice(&crc.to_le_bytes());
    out
}

/// The epoch in a snapshot's header.
pub fn snapshot_epoch(snapshot: &[u8]) -> u64 {
    u64::from_le_bytes(snapshot[16..24].try_into().unwrap())
}

/// Journal batches without a MAC, for `epoch`: the input is split into
/// bodies, each preceded by a length byte.
pub fn batches(epoch: u64, mut data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut wall = 1_000u64;
    while let Some((&n, rest)) = data.split_first() {
        data = rest;
        let body = take(&mut data, usize::from(n));
        let start = out.len();
        out.extend_from_slice(b"BNCJ");
        out.extend_from_slice(&epoch.to_le_bytes());
        out.extend_from_slice(&wall.to_le_bytes());
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend_from_slice(&body);
        let crc = crc32c(&out[start..]);
        out.extend_from_slice(&crc.to_le_bytes());
        wall += 1_000;
    }
    out
}
