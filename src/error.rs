use thiserror::Error;

use crate::{
    codec::CodecError,
    command::CommandError,
    crypto::CryptoError,
    did::{DidError, ResolveError},
    envelope::EnvelopeError,
    policy::PolicyError,
    time::Timestamp,
    varsig::VarsigError,
};

/// Anything that stops a token from being built, decoded or verified.
///
/// Chain validation has its own error, [`crate::validate::ValidationError`],
/// because it needs to say which hop failed.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// The bytes are not strict DAG-CBOR.
    #[error("codec: {0}")]
    Codec(#[from] CodecError),

    /// The envelope has the wrong shape or an unknown tag.
    #[error("envelope: {0}")]
    Envelope(#[from] EnvelopeError),

    /// The varsig header is malformed or names an unknown algorithm.
    #[error("varsig: {0}")]
    Varsig(#[from] VarsigError),

    /// A payload field is missing, unknown, or of the wrong type.
    #[error("payload: {0}")]
    Payload(#[from] PayloadError),

    /// A DID string does not parse.
    #[error("did: {0}")]
    Did(#[from] DidError),

    /// A command string does not parse.
    #[error("command: {0}")]
    Command(#[from] CommandError),

    /// A policy does not parse.
    #[error("policy: {0}")]
    Policy(#[from] PolicyError),

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

/// A payload field problem, named by field.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum PayloadError {
    /// A required field is absent.
    #[error("missing field `{0}`")]
    Missing(&'static str),

    /// A field this implementation does not know. Unknown fields are refused
    /// rather than ignored; see `docs/wire-format.md`.
    #[error("unknown field `{0}`")]
    Unknown(alloc::string::String),

    /// A field holds the wrong kind of value.
    #[error("field `{0}` has the wrong type")]
    Type(&'static str),

    /// A field holds a value outside its allowed range.
    #[error("field `{0}` is out of range")]
    Range(&'static str),

    /// A field is present when the specification requires it to be absent.
    #[error("field `{0}` must be omitted here")]
    Forbidden(&'static str),
}
