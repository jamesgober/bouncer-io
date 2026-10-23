//! `Collected`: the buffer a response is built in, so that "wipe" means
//! overwritten, not dropped.

use core::fmt;

use crate::error::{BouncerError, ConfigError, ConfigProblem};

/// Default capacity of [`Collected::new`]: 16 KiB.
const DEFAULT_CAPACITY: usize = 16 * 1024;
/// Default limit of [`Collected::new`]: 1 MiB.
const DEFAULT_LIMIT: usize = 1024 * 1024;

/// The buffer a response is collected in.
///
/// It never reallocates in place: growth (doubling, up to `limit`) allocates a
/// new block, copies, and wipes the old block before freeing it, which closes
/// the gap a plain `Vec` leaves (`Vec` growth copies and frees the old block
/// without clearing it). Every wipe goes through crypt-io's volatile writes,
/// which the optimizer cannot remove. `Debug` prints the length and capacity
/// only, never the contents.
///
/// | Call | Wipes |
/// |---|---|
/// | `clear` | the used part; keeps the capacity, for reuse between requests |
/// | `truncate(len)` | the cut part |
/// | `wipe`, drop | the whole capacity, whatever was used, so the time does not depend on the content |
///
/// # Examples
///
/// ```
/// use bouncer_io::Collected;
/// use std::io::Write;
///
/// let mut reply = Collected::with_capacity(4096, 64 * 1024)?;
/// write!(reply, "{{\"balance\":{}}}", 1204)?;
/// assert_eq!(reply.as_slice(), b"{\"balance\":1204}");
/// reply.wipe();
/// assert!(reply.is_empty());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct Collected {
    buf: Box<[u8]>,
    len: usize,
    limit: usize,
    spare: usize,
}

impl Default for Collected {
    fn default() -> Self {
        Collected::new()
    }
}

impl Collected {
    /// 16 KiB preallocated, growing up to 1 MiB.
    #[must_use]
    pub fn new() -> Collected {
        Collected {
            buf: vec![0; DEFAULT_CAPACITY].into_boxed_slice(),
            len: 0,
            limit: DEFAULT_LIMIT,
            spare: 0,
        }
    }

    /// `capacity` bytes preallocated, growing up to `limit`.
    ///
    /// # Errors
    ///
    /// [`BouncerError::Config`] when `capacity` exceeds `limit`.
    pub fn with_capacity(capacity: usize, limit: usize) -> Result<Collected, BouncerError> {
        if capacity > limit {
            return Err(ConfigError::new(
                "Collected::with_capacity",
                ConfigProblem::TooLarge { max: limit as u64 },
            )
            .into());
        }
        Ok(Collected {
            buf: vec![0; capacity].into_boxed_slice(),
            len: 0,
            limit,
            spare: 0,
        })
    }

    /// Bytes collected.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// `true` when nothing is collected.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Bytes reserved now.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.buf.len()
    }

    /// The most this buffer may grow to.
    #[must_use]
    pub fn limit(&self) -> usize {
        self.limit
    }

    /// The collected bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// Makes room for `more` bytes after the collected ones, growing by
    /// allocate, copy, and wipe.
    fn reserve(&mut self, more: usize) -> Result<(), BouncerError> {
        let needed = self
            .len
            .checked_add(more)
            .ok_or(BouncerError::CollectedFull {
                capacity: self.limit,
                needed: usize::MAX,
            })?;
        if needed > self.limit {
            return Err(BouncerError::CollectedFull {
                capacity: self.limit,
                needed,
            });
        }
        if needed <= self.buf.len() {
            return Ok(());
        }
        let grown = needed.max(self.buf.len().saturating_mul(2)).min(self.limit);
        let mut next = vec![0u8; grown].into_boxed_slice();
        next[..self.len].copy_from_slice(&self.buf[..self.len]);
        let mut old = core::mem::replace(&mut self.buf, next);
        crypt_io::wipe(&mut old);
        Ok(())
    }

    /// Appends `bytes`.
    ///
    /// # Errors
    ///
    /// [`BouncerError::CollectedFull`] past the limit; nothing is appended.
    pub fn extend_from_slice(&mut self, bytes: &[u8]) -> Result<(), BouncerError> {
        self.reserve(bytes.len())?;
        self.buf[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
        self.spare = 0;
        Ok(())
    }

    /// Room for `want` bytes to be written in place; follow with
    /// [`commit`](Self::commit).
    ///
    /// # Errors
    ///
    /// [`BouncerError::CollectedFull`] past the limit.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut reply = bouncer_io::Collected::new();
    /// let room = reply.spare(5)?;
    /// room.copy_from_slice(b"hello");
    /// reply.commit(5)?;
    /// assert_eq!(reply.len(), 5);
    /// # Ok::<(), bouncer_io::BouncerError>(())
    /// ```
    pub fn spare(&mut self, want: usize) -> Result<&mut [u8], BouncerError> {
        self.reserve(want)?;
        self.spare = want;
        Ok(&mut self.buf[self.len..self.len + want])
    }

    /// Counts `written` bytes of the last [`spare`](Self::spare) as collected.
    ///
    /// # Errors
    ///
    /// [`BouncerError::InvalidCommit`] when `written` is more than `spare` gave.
    pub fn commit(&mut self, written: usize) -> Result<(), BouncerError> {
        if written > self.spare {
            return Err(BouncerError::InvalidCommit);
        }
        self.len += written;
        self.spare = 0;
        Ok(())
    }

    /// Keeps the first `len` bytes and wipes the rest of what was collected.
    pub fn truncate(&mut self, len: usize) {
        if len < self.len {
            crypt_io::wipe(&mut self.buf[len..self.len]);
            self.len = len;
        }
        self.spare = 0;
    }

    /// Wipes what was collected and keeps the capacity, for reuse.
    pub fn clear(&mut self) {
        crypt_io::wipe(&mut self.buf[..self.len]);
        self.len = 0;
        self.spare = 0;
    }

    /// Wipes the whole capacity.
    pub fn wipe(&mut self) {
        crypt_io::wipe(&mut self.buf);
        self.len = 0;
        self.spare = 0;
    }
}

impl Drop for Collected {
    fn drop(&mut self) {
        crypt_io::wipe(&mut self.buf);
    }
}

impl std::io::Write for Collected {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.extend_from_slice(bytes)
            .map(|()| bytes.len())
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::WriteZero))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl fmt::Debug for Collected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Collected")
            .field("len", &self.len)
            .field("capacity", &self.buf.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    #[test]
    fn test_collected_boundaries() {
        // Edge case 42: empty, one byte, exactly capacity, capacity plus one,
        // limit, limit plus one.
        let mut c = Collected::with_capacity(4, 8).unwrap();
        assert!(c.is_empty());
        c.extend_from_slice(b"a").unwrap();
        c.extend_from_slice(b"bcd").unwrap();
        assert_eq!(c.capacity(), 4);
        c.extend_from_slice(b"e").unwrap();
        assert_eq!(c.capacity(), 8, "grew by doubling");
        c.extend_from_slice(b"fgh").unwrap();
        assert_eq!(c.len(), 8);
        assert_eq!(
            c.extend_from_slice(b"i"),
            Err(BouncerError::CollectedFull {
                capacity: 8,
                needed: 9
            })
        );
        assert_eq!(
            c.as_slice(),
            b"abcdefgh",
            "a refused append leaves the buffer as it was"
        );
        assert!(Collected::with_capacity(9, 8).is_err());
    }

    #[test]
    fn test_collected_wipe_clear_truncate_zero_bytes() {
        let mut c = Collected::with_capacity(16, 16).unwrap();
        c.extend_from_slice(b"secret-secret").unwrap();
        c.truncate(6);
        assert_eq!(c.as_slice(), b"secret");
        assert!(c.buf[6..].iter().all(|&b| b == 0));
        c.clear();
        assert!(c.buf.iter().all(|&b| b == 0));
        c.extend_from_slice(b"again").unwrap();
        c.wipe();
        assert!(c.is_empty() && c.buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_collected_spare_commit_and_write() {
        let mut c = Collected::with_capacity(2, 64).unwrap();
        c.spare(4).unwrap().copy_from_slice(b"1234");
        assert_eq!(c.commit(5), Err(BouncerError::InvalidCommit));
        c.commit(4).unwrap();
        write!(c, "-{}", 5).unwrap();
        assert_eq!(c.as_slice(), b"1234-5");
        let mut small = Collected::with_capacity(0, 2).unwrap();
        assert_eq!(
            small.write(b"abc").unwrap_err().kind(),
            std::io::ErrorKind::WriteZero
        );
        assert!(small.flush().is_ok());
        assert!(format!("{c:?}").contains("len: 6"));
        assert!(!format!("{c:?}").contains("1234"));
    }
}
