//! The token nonce.

use alloc::{boxed::Box, vec::Vec};
use core::fmt;

use rand_core::CryptoRng;

/// Bytes that make a token unique.
///
/// Twelve random bytes are the recommended default. An empty nonce is
/// legitimate for idempotent invocations, where equal tasks should share
/// a task ID; the builders make that an explicit choice rather than a
/// default.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Nonce(Box<[u8]>);

impl Nonce {
    /// The recommended random length.
    pub const RANDOM_LEN: usize = 12;

    /// Twelve random bytes.
    pub fn random<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        let mut bytes = [0u8; Self::RANDOM_LEN];
        rng.fill_bytes(&mut bytes);
        Nonce(Box::new(bytes))
    }

    /// The empty nonce, for idempotent commands.
    #[must_use]
    pub fn empty() -> Self {
        Nonce(Box::new([]))
    }

    /// A nonce with exactly these bytes.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Nonce(bytes.into())
    }

    /// The bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Whether this is the empty nonce.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<Vec<u8>> for Nonce {
    fn from(bytes: Vec<u8>) -> Self {
        Nonce(bytes.into_boxed_slice())
    }
}

impl fmt::Debug for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Nonce(")?;
        for byte in &*self.0 {
            write!(f, "{byte:02x}")?;
        }
        write!(f, ")")
    }
}
