use thiserror::Error;

use crate::{
    command::CommandError, crypto::CryptoError, did::DidError, did::ResolveError, time::Timestamp,
};

/// Anything that stops a token from being built, decoded or verified.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// A DID string does not parse.
    #[error("did: {0}")]
    Did(#[from] DidError),

    /// A command string does not parse.
    #[error("command: {0}")]
    Command(#[from] CommandError),

    /// A key, signature, or algorithm problem.
    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),

    /// The issuer could not be turned into a key.
    #[error("resolve: {0}")]
    Resolve(#[from] ResolveError),

    /// The token is not valid yet.
    #[error("not valid before {0}")]
    NotYetValid(Timestamp),

    /// The token has expired.
    #[error("expired at {0}")]
    Expired(Timestamp),
}
