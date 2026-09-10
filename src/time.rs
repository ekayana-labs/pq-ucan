//! Timestamps with the 53-bit bound every UCAN implementation must honour.

use core::fmt;

use thiserror::Error;

/// Seconds since the Unix epoch, within `±(2^53 - 1)`.
///
/// The bound comes from the specification: JavaScript cannot represent
/// integers beyond it, so a timestamp outside it is invalid everywhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(i64);

impl Timestamp {
    /// The largest representable timestamp.
    pub const MAX: Timestamp = Timestamp((1 << 53) - 1);
    /// The smallest representable timestamp.
    pub const MIN: Timestamp = Timestamp(-((1 << 53) - 1));

    /// From Unix seconds.
    pub fn from_unix(seconds: i64) -> Result<Self, TimeError> {
        if (Self::MIN.0..=Self::MAX.0).contains(&seconds) {
            Ok(Timestamp(seconds))
        } else {
            Err(TimeError::OutOfRange)
        }
    }

    /// Unix seconds.
    #[must_use]
    pub const fn as_unix(self) -> i64 {
        self.0
    }

    /// This timestamp moved later, saturating at [`Timestamp::MAX`].
    #[must_use]
    pub fn plus_seconds(self, seconds: u32) -> Self {
        Timestamp(self.0.saturating_add(i64::from(seconds)).min(Self::MAX.0))
    }

    /// This timestamp moved earlier, saturating at [`Timestamp::MIN`].
    #[must_use]
    pub fn minus_seconds(self, seconds: u32) -> Self {
        Timestamp(self.0.saturating_sub(i64::from(seconds)).max(Self::MIN.0))
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl TryFrom<i64> for Timestamp {
    type Error = TimeError;

    fn try_from(seconds: i64) -> Result<Self, TimeError> {
        Self::from_unix(seconds)
    }
}

/// When a token stops being valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Expiry {
    /// At the given time, inclusive.
    At(Timestamp),
    /// Never. Wire form `null`.
    Never,
}

impl Expiry {
    /// Whether `now` is past this expiry, allowing `skew` seconds.
    #[must_use]
    pub fn is_past(self, now: Timestamp, skew: u32) -> bool {
        match self {
            Expiry::At(at) => now > at.plus_seconds(skew),
            Expiry::Never => false,
        }
    }
}

/// Check that `now` lies inside `[not_before - skew, expiry + skew]`, both
/// ends inclusive.
pub fn check_window(
    not_before: Option<Timestamp>,
    expiry: Expiry,
    now: Timestamp,
    skew: u32,
) -> Result<(), crate::Error> {
    if let Some(nbf) = not_before {
        if now < nbf.minus_seconds(skew) {
            return Err(crate::Error::NotYetValid(nbf));
        }
    }
    match expiry {
        Expiry::At(at) if expiry.is_past(now, skew) => Err(crate::Error::Expired(at)),
        _ => Ok(()),
    }
}

/// A source of the current time.
pub trait Clock {
    /// The current time.
    fn now(&self) -> Timestamp;
}

/// A clock that always reports one time. For tests and for validators fed
/// a time by their caller.
#[derive(Debug, Clone, Copy)]
pub struct FixedClock(pub Timestamp);

impl Clock for FixedClock {
    fn now(&self) -> Timestamp {
        self.0
    }
}

/// The operating system clock.
#[cfg(feature = "std")]
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

#[cfg(feature = "std")]
impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        let seconds = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
        Timestamp(seconds.clamp(Timestamp::MIN.0, Timestamp::MAX.0))
    }
}

/// A timestamp problem.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TimeError {
    /// Outside `±(2^53 - 1)`.
    #[error("timestamp outside the 53-bit range")]
    OutOfRange,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn bounds_are_enforced() {
        assert!(Timestamp::from_unix((1 << 53) - 1).is_ok());
        assert_eq!(Timestamp::from_unix(1 << 53), Err(TimeError::OutOfRange));
        assert_eq!(Timestamp::from_unix(-(1 << 53)), Err(TimeError::OutOfRange));
        assert_eq!(Timestamp::MAX.plus_seconds(5), Timestamp::MAX);
    }

    #[test]
    fn expiry_is_inclusive_and_skew_extends_it() {
        let at = Timestamp::from_unix(100).unwrap();
        let exp = Expiry::At(at);
        assert!(!exp.is_past(at, 0));
        assert!(exp.is_past(Timestamp::from_unix(101).unwrap(), 0));
        assert!(!exp.is_past(Timestamp::from_unix(160).unwrap(), 60));
        assert!(!Expiry::Never.is_past(Timestamp::MAX, 0));
    }
}
