use thiserror::Error;

use crate::time::Timestamp;

/// Anything that stops a token from being built, decoded or verified.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// The token is not valid yet.
    #[error("not valid before {0}")]
    NotYetValid(Timestamp),

    /// The token has expired.
    #[error("expired at {0}")]
    Expired(Timestamp),
}
