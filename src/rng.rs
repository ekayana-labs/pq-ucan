//! Randomness: the trait key generation and nonces take, and the system
//! source under `std`.
//!
//! Nothing in the crate draws randomness on its own. A caller passes an
//! RNG where one is needed, which keeps `no_std` builds free of any
//! platform assumption and makes tests deterministic.

pub use rand_core::{CryptoRng, UnwrapErr};

/// The operating system's random source, wrapped so that it implements
/// [`CryptoRng`]. A failure to read from it aborts rather than returning
/// weak bytes.
#[cfg(feature = "std")]
#[must_use]
pub fn system() -> UnwrapErr<getrandom::SysRng> {
    UnwrapErr(getrandom::SysRng)
}
