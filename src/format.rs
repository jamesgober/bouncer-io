//! Denial formatting: the protocol adapter's side of wipe, replace, eject.

use crate::{
    collected::Collected,
    verdict::{Denial, Reference},
};

/// Writes a protocol's denial for a [`Denial`] into the (already wiped)
/// buffer. Implemented by protocol adapters: the HTTP adapter, ws-net, a
/// database wire.
///
/// It must not allocate and must not write anything but the code, the
/// application code, the message, and the reference. To keep denials
/// identical to ordinary refusals, use the same body and headers the adapter
/// uses for its own refusals of that code. Output past
/// [`MAX_DENIAL_BYTES`](crate::MAX_DENIAL_BYTES) is discarded.
///
/// # Examples
///
/// ```
/// use bouncer_io::{Collected, Denial, DenialCode, DenialFormat, FormatError};
/// use std::io::Write;
///
/// struct Http;
/// impl DenialFormat for Http {
///     fn format(&self, d: &Denial, out: &mut Collected) -> Result<(), FormatError> {
///         let status = match d.code {
///             DenialCode::Forbidden => "403 Forbidden",
///             DenialCode::NotFound => "404 Not Found",
///             DenialCode::TooManyRequests => "429 Too Many Requests",
///             DenialCode::Unauthorized => "401 Unauthorized",
///             _ => "503 Service Unavailable",
///         };
///         write!(out, "HTTP/1.1 {status}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}", d.message.len(), d.message)
///             .map_err(|_| FormatError::TooLarge)
///     }
/// }
/// ```
pub trait DenialFormat: Send + Sync {
    /// Writes the denial.
    ///
    /// # Errors
    ///
    /// [`FormatError`]; the denial bytes are then skipped and the eject still
    /// happens.
    fn format(&self, denial: &Denial, out: &mut Collected) -> Result<(), FormatError>;
}

/// Writes nothing: the connection is closed without a reply.
///
/// # Examples
///
/// ```
/// use bouncer_io::{Collected, DenialFormat, NoFormat};
/// # let d = {
/// #     let b = bouncer_io::Bouncer::new();
/// #     let c = b.door("192.0.2.1".parse().unwrap()).unwrap();
/// #     let mut r = c.request(bouncer_io::RequestId(1)).unwrap();
/// #     drop(c);
/// #     *r.checkpoint().denial().unwrap()
/// # };
/// let mut out = Collected::new();
/// NoFormat.format(&d, &mut out).unwrap();
/// assert!(out.is_empty());
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct NoFormat;

impl DenialFormat for NoFormat {
    fn format(&self, _denial: &Denial, _out: &mut Collected) -> Result<(), FormatError> {
        Ok(())
    }
}

/// Why a formatter wrote no denial.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatError {
    /// The denial would not fit the budget.
    TooLarge,
    /// The protocol has no denial frame in its current state.
    Unsupported,
}

impl core::fmt::Display for FormatError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            FormatError::TooLarge => "the denial does not fit the formatting budget",
            FormatError::Unsupported => "the protocol cannot send a denial now",
        })
    }
}

impl std::error::Error for FormatError {}

/// What [`Ticket::deny_and_eject`](crate::Ticket::deny_and_eject) did.
///
/// `ejected` is `false` when no `Ejector` is configured (the caller must close
/// the connection itself) or when the revocation kept the connection open.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ejected {
    /// The buffer's whole capacity was overwritten with zeroes.
    pub wiped: bool,
    /// The formatter wrote denial bytes into the buffer.
    pub formatted: bool,
    /// The connection was handed to the `Ejector`.
    pub ejected: bool,
    /// The source is in ban memory, so the next attempt dies at the door.
    pub remembered: bool,
    /// The denial's reference.
    pub reference: Reference,
}
