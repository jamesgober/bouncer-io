//! Verdicts and denials: the answer of every checkpoint.

use core::fmt;

/// The answer of every checkpoint and bind.
///
/// Ignoring it is the bug this crate exists to prevent, so it is
/// `#[must_use]`.
///
/// # Examples
///
/// ```
/// use bouncer_io::{Bouncer, RequestId, Verdict};
/// let bouncer = Bouncer::new();
/// let conn = bouncer.door("192.0.2.31".parse()?)?;
/// let mut request = conn.request(RequestId(1))?;
/// assert_eq!(request.checkpoint(), Verdict::Pass);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[must_use]
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Carry on.
    Pass,
    /// Stop: wipe, replace with this denial, eject.
    Deny(Denial),
}

impl Verdict {
    /// `true` for `Pass`.
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::{Bouncer, Reason, RequestId};
    /// let bouncer = Bouncer::new();
    /// let conn = bouncer.door("192.0.2.5".parse()?)?;
    /// let mut request = conn.request(RequestId(1))?;
    /// assert!(request.checkpoint().is_pass());
    /// bouncer.revoke(conn.conn(), Reason::ADMIN)?;
    /// assert!(!request.checkpoint().is_pass());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub fn is_pass(&self) -> bool {
        matches!(self, Verdict::Pass)
    }

    /// `true` for `Deny`.
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::{Bouncer, Reason, RequestId};
    /// let bouncer = Bouncer::new();
    /// let conn = bouncer.door("192.0.2.5".parse()?)?;
    /// let mut request = conn.request(RequestId(1))?;
    /// assert!(!request.checkpoint().is_deny());
    /// bouncer.revoke(conn.conn(), Reason::ADMIN)?;
    /// assert!(request.checkpoint().is_deny());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub fn is_deny(&self) -> bool {
        matches!(self, Verdict::Deny(_))
    }

    /// The denial, for `Deny`.
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::{Bouncer, DenialCode, Reason, RequestId};
    /// let bouncer = Bouncer::new();
    /// let conn = bouncer.door("192.0.2.5".parse()?)?;
    /// let mut request = conn.request(RequestId(1))?;
    /// assert!(request.checkpoint().denial().is_none());
    /// bouncer.revoke(conn.conn(), Reason::ADMIN)?;
    /// let verdict = request.checkpoint();
    /// assert_eq!(verdict.denial().map(|d| d.code), Some(DenialCode::Forbidden));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub fn denial(&self) -> Option<&Denial> {
        match self {
            Verdict::Deny(d) => Some(d),
            Verdict::Pass => None,
        }
    }
}

/// What a protocol adapter formats: a code from a fixed set, an application
/// code and message fixed at build, and an opaque reference. Nothing in it
/// carries the reason.
///
/// # Examples
///
/// ```
/// use bouncer_io::{DenialCode, Verdict};
/// # let bouncer = bouncer_io::Bouncer::new();
/// # let conn = bouncer.door("10.9.9.9".parse()?)?;
/// # let mut req = conn.request(bouncer_io::RequestId(1))?;
/// # drop(conn);
/// if let Verdict::Deny(d) = req.checkpoint() {
///     assert_eq!(d.code, DenialCode::Unavailable);
///     println!("{} (ref {})", d.message, d.reference);
/// }
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Denial {
    /// The protocol-neutral code.
    pub code: DenialCode,
    /// The application code from the denial table.
    pub app_code: u16,
    /// The fixed message from the denial table.
    pub message: &'static str,
    /// The opaque reference an administrator can look up.
    pub reference: Reference,
}

impl Denial {
    #[cfg(test)]
    pub(crate) const fn new(code: DenialCode, reference: Reference) -> Denial {
        Denial {
            code,
            app_code: 0,
            message: code.default_message(),
            reference,
        }
    }
}

/// A protocol-neutral denial code. The adapter maps it (HTTP 503, 404, 429,
/// 401, 403; WebSocket 1013 or 1008; a database error frame).
///
/// Ordered by precedence: when a ticket is denied twice, the stronger code is
/// kept.
///
/// # Examples
///
/// ```
/// use bouncer_io::DenialCode;
/// assert!(DenialCode::Forbidden > DenialCode::NotFound);
/// assert_eq!(DenialCode::Forbidden.number(), 5);
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DenialCode {
    /// The service cannot take the request (HTTP 503).
    Unavailable,
    /// Hide that the resource exists (HTTP 404).
    NotFound,
    /// Throttled (HTTP 429).
    TooManyRequests,
    /// Authentication required (HTTP 401).
    Unauthorized,
    /// Refused (HTTP 403). The default for revocations.
    Forbidden,
}

impl DenialCode {
    /// The number a transport carries: 1 `Unavailable` to 5 `Forbidden`.
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::DenialCode;
    /// assert_eq!(DenialCode::Unavailable.number(), 1);
    /// assert_eq!(DenialCode::TooManyRequests.number(), 3);
    /// assert_eq!(DenialCode::Forbidden.number(), 5);
    /// ```
    #[must_use]
    pub const fn number(self) -> u16 {
        match self {
            DenialCode::Unavailable => 1,
            DenialCode::NotFound => 2,
            DenialCode::TooManyRequests => 3,
            DenialCode::Unauthorized => 4,
            DenialCode::Forbidden => 5,
        }
    }

    /// The HTTP status this code stands for: 503, 404, 429, 401, or 403.
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::DenialCode;
    /// assert_eq!(DenialCode::TooManyRequests.http_status(), 429);
    /// assert_eq!(DenialCode::from_http_status(429), Some(DenialCode::TooManyRequests));
    /// assert_eq!(DenialCode::from_http_status(200), None);
    /// ```
    #[must_use]
    pub const fn http_status(self) -> u16 {
        match self {
            DenialCode::Unavailable => 503,
            DenialCode::NotFound => 404,
            DenialCode::TooManyRequests => 429,
            DenialCode::Unauthorized => 401,
            DenialCode::Forbidden => 403,
        }
    }

    /// The code an HTTP status stands for, if it is one of the five.
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::DenialCode;
    /// assert_eq!(DenialCode::from_http_status(403), Some(DenialCode::Forbidden));
    /// assert_eq!(DenialCode::from_http_status(500), None);
    /// let code = DenialCode::NotFound;
    /// assert_eq!(DenialCode::from_http_status(code.http_status()), Some(code));
    /// ```
    #[must_use]
    pub const fn from_http_status(status: u16) -> Option<DenialCode> {
        match status {
            503 => Some(DenialCode::Unavailable),
            404 => Some(DenialCode::NotFound),
            429 => Some(DenialCode::TooManyRequests),
            401 => Some(DenialCode::Unauthorized),
            403 => Some(DenialCode::Forbidden),
            _ => None,
        }
    }

    pub(crate) const fn from_number(n: u8) -> DenialCode {
        match n {
            2 => DenialCode::NotFound,
            3 => DenialCode::TooManyRequests,
            4 => DenialCode::Unauthorized,
            5 => DenialCode::Forbidden,
            _ => DenialCode::Unavailable,
        }
    }

    /// The plain default message.
    pub(crate) const fn default_message(self) -> &'static str {
        match self {
            DenialCode::Unavailable => "Service unavailable.",
            DenialCode::NotFound => "Not found.",
            DenialCode::TooManyRequests => "Too many requests.",
            DenialCode::Unauthorized => "Unauthorized.",
            DenialCode::Forbidden => "Forbidden.",
        }
    }
}

/// 64 random bits that index an event so an administrator can look a denial
/// or refusal up. It carries no information.
///
/// # Examples
///
/// ```
/// # use bouncer_io::{Bouncer, Refusal};
/// let bouncer = Bouncer::new();
/// bouncer.ban("198.51.100.9".parse::<std::net::IpAddr>()?)?;
/// if let Err(Refusal::Banned { reference }) = bouncer.door("198.51.100.9".parse()?) {
///     assert_eq!(reference.to_string().len(), 16);
/// }
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Reference(u64);

impl Reference {
    pub(crate) const fn new(raw: u64) -> Reference {
        Reference(raw)
    }

    /// The raw value.
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::{Bouncer, Reason, RequestId};
    /// let bouncer = Bouncer::new();
    /// let conn = bouncer.door("192.0.2.5".parse()?)?;
    /// let mut request = conn.request(RequestId(1))?;
    /// bouncer.revoke(conn.conn(), Reason::ADMIN)?;
    /// let verdict = request.checkpoint();
    /// let reference = verdict.denial().ok_or("not denied")?.reference;
    /// assert_eq!(format!("{:016x}", reference.get()), reference.to_string());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for Reference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}

/// The fixed message and application code per denial code, set at build so a
/// denial can never carry text made from the request.
///
/// # Examples
///
/// ```
/// use bouncer_io::{Bouncer, DenialCode, DenialTable};
/// let bouncer = Bouncer::builder()
///     .denials(DenialTable::new().message(DenialCode::Forbidden, "Request refused.").app_code(DenialCode::Forbidden, 4031))
///     .try_build()?;
/// # let _ = bouncer;
/// # Ok::<(), bouncer_io::BouncerError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DenialTable {
    entries: [(&'static str, u16); 5],
}

impl Default for DenialTable {
    /// Plain messages: "Service unavailable.", "Not found.", "Too many
    /// requests.", "Unauthorized.", "Forbidden."; application code 0.
    fn default() -> Self {
        DenialTable {
            entries: [
                (DenialCode::Unavailable.default_message(), 0),
                (DenialCode::NotFound.default_message(), 0),
                (DenialCode::TooManyRequests.default_message(), 0),
                (DenialCode::Unauthorized.default_message(), 0),
                (DenialCode::Forbidden.default_message(), 0),
            ],
        }
    }
}

impl DenialTable {
    /// The default table.
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::{Bouncer, DenialTable, Reason, RequestId};
    /// let bouncer = Bouncer::builder().denials(DenialTable::new()).try_build()?;
    /// let conn = bouncer.door("192.0.2.5".parse()?)?;
    /// let mut request = conn.request(RequestId(1))?;
    /// bouncer.revoke(conn.conn(), Reason::ADMIN)?;
    /// let verdict = request.checkpoint();
    /// let d = verdict.denial().ok_or("not denied")?;
    /// assert_eq!((d.message, d.app_code), ("Forbidden.", 0));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub fn new() -> DenialTable {
        DenialTable::default()
    }

    /// The message for one code (at most 256 bytes, checked at build).
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::{Bouncer, DenialCode, DenialTable, Reason, RequestId};
    /// let table = DenialTable::new().message(DenialCode::Forbidden, "Request refused.");
    /// let bouncer = Bouncer::builder().denials(table).try_build()?;
    /// let conn = bouncer.door("192.0.2.5".parse()?)?;
    /// let mut request = conn.request(RequestId(1))?;
    /// bouncer.revoke(conn.conn(), Reason::ADMIN)?;
    /// let verdict = request.checkpoint();
    /// assert_eq!(verdict.denial().map(|d| d.message), Some("Request refused."));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub fn message(mut self, code: DenialCode, message: &'static str) -> DenialTable {
        self.entries[Self::slot(code)].0 = message;
        self
    }

    /// The application code for one code.
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::{Bouncer, DenialCode, DenialTable, Reason, RequestId};
    /// let table = DenialTable::new().app_code(DenialCode::Forbidden, 4031);
    /// let bouncer = Bouncer::builder().denials(table).try_build()?;
    /// let conn = bouncer.door("192.0.2.5".parse()?)?;
    /// let mut request = conn.request(RequestId(1))?;
    /// bouncer.revoke(conn.conn(), Reason::ADMIN)?;
    /// let verdict = request.checkpoint();
    /// assert_eq!(verdict.denial().map(|d| d.app_code), Some(4031));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub fn app_code(mut self, code: DenialCode, app_code: u16) -> DenialTable {
        self.entries[Self::slot(code)].1 = app_code;
        self
    }

    fn slot(code: DenialCode) -> usize {
        usize::from(code.number() - 1)
    }

    pub(crate) fn validate(&self) -> Result<(), crate::error::ConfigError> {
        if self.entries.iter().any(|(m, _)| m.len() > 256) {
            return Err(crate::error::ConfigError::new(
                "denials",
                crate::error::ConfigProblem::MessageTooLong,
            ));
        }
        Ok(())
    }

    /// The denial for a code and reference.
    pub(crate) fn denial(&self, code: DenialCode, reference: Reference) -> Denial {
        let (message, app_code) = self.entries[Self::slot(code)];
        Denial {
            code,
            app_code,
            message,
            reference,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_every_denial_code_round_trips_its_http_status() {
        for code in [
            DenialCode::Unavailable,
            DenialCode::NotFound,
            DenialCode::TooManyRequests,
            DenialCode::Unauthorized,
            DenialCode::Forbidden,
        ] {
            assert_eq!(DenialCode::from_http_status(code.http_status()), Some(code));
        }
        assert_eq!(DenialCode::from_http_status(500), None);
    }

    #[test]
    fn test_verdict_helpers() {
        let d = Denial::new(DenialCode::Forbidden, Reference::new(1));
        assert!(Verdict::Pass.is_pass());
        assert!(Verdict::Deny(d).is_deny());
        assert_eq!(Verdict::Deny(d).denial(), Some(&d));
        assert_eq!(Verdict::Pass.denial(), None);
        assert_eq!(d.message, "Forbidden.");
    }

    #[test]
    fn test_denial_code_numbers_round_trip_and_order() {
        let all = [
            DenialCode::Unavailable,
            DenialCode::NotFound,
            DenialCode::TooManyRequests,
            DenialCode::Unauthorized,
            DenialCode::Forbidden,
        ];
        for w in all.windows(2) {
            assert!(w[0] < w[1]);
        }
        for c in all {
            assert_eq!(DenialCode::from_number(c.number() as u8), c);
        }
        assert_eq!(DenialCode::from_number(0), DenialCode::Unavailable);
    }

    #[test]
    fn test_reference_display_16_hex() {
        assert_eq!(Reference::new(0xab).to_string(), "00000000000000ab");
        assert_eq!(Reference::new(9).get(), 9);
    }
}
