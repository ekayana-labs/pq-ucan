use thiserror::Error;

use crate::{command::CommandError, time::Timestamp};

/// Anything that stops a token from being built, decoded or verified.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// A command string does not parse.
    #[error("command: {0}")]
    Command(#[from] CommandError),

    /// The token is not valid yet.
    #[error("not valid before {0}")]
    NotYetValid(Timestamp),

    /// The token has expired.
    #[error("expired at {0}")]
    Expired(Timestamp),
}
