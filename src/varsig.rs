//! Varsig v1 headers.
//!
//! A header names the signature algorithm and the payload encoding, so a
//! token says how it was signed. Every token here is DAG-CBOR; the
//! algorithm segments are tabulated in `docs/wire-format.md`.

use alloc::vec::Vec;
use core::fmt;

use thiserror::Error;

use crate::{
    codec::{put_uvarint, read_uvarint},
    crypto::Algorithm,
};

const PREFIX: u8 = 0x34;
const VERSION: u8 = 0x01;
const DAG_CBOR: u64 = 0x71;

const EDDSA: u64 = 0xed;
const ECDSA: u64 = 0xec;
const SHA2_256: u64 = 0x12;
const SHA2_512: u64 = 0x13;

/// A varsig header for one algorithm over DAG-CBOR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Header {
    algorithm: Algorithm,
}

impl Header {
    /// The header for `algorithm`.
    #[must_use]
    pub const fn new(algorithm: Algorithm) -> Self {
        Header { algorithm }
    }

    /// The algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// The header bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8);
        out.push(PREFIX);
        out.push(VERSION);
        for segment in segments(self.algorithm) {
            put_uvarint(*segment, &mut out);
        }
        put_uvarint(DAG_CBOR, &mut out);
        out
    }

    /// Parse header bytes. Every byte must be accounted for.
    pub fn decode(bytes: &[u8]) -> Result<Self, VarsigError> {
        let rest = bytes.strip_prefix(&[PREFIX]).ok_or(VarsigError::Prefix)?;
        let mut rest = rest.strip_prefix(&[VERSION]).ok_or(VarsigError::Version)?;
        let mut read = Vec::with_capacity(4);
        while !rest.is_empty() {
            let (value, used) = read_uvarint(rest).map_err(|_| VarsigError::Varint)?;
            read.push(value);
            rest = rest.get(used..).ok_or(VarsigError::Varint)?;
        }
        let (encoding, algorithm_segments) = read.split_last().ok_or(VarsigError::Truncated)?;
        let algorithm = Algorithm::ALL
            .into_iter()
            .find(|a| segments(*a) == algorithm_segments)
            .ok_or_else(|| match algorithm_segments.first() {
                Some(&tag)
                    if [EDDSA, ECDSA].contains(&tag)
                        || Algorithm::from_multicodec(tag).is_some() =>
                {
                    VarsigError::UnsupportedParameters
                }
                Some(&tag) => VarsigError::UnknownAlgorithm(tag),
                None => VarsigError::Truncated,
            })?;
        if *encoding != DAG_CBOR {
            return Err(VarsigError::UnsupportedEncoding(*encoding));
        }
        Ok(Header { algorithm })
    }
}

/// The algorithm segments that follow the version byte.
const fn segments(algorithm: Algorithm) -> &'static [u64] {
    match algorithm {
        Algorithm::Ed25519 => &[EDDSA, 0xed, SHA2_512],
        Algorithm::P256 => &[ECDSA, 0x1200, SHA2_256],
        Algorithm::Secp256k1 => &[ECDSA, 0xe7, SHA2_256],
        // Provisional: the public key multicodec stands in for a registry
        // tag, and there is no hash segment because ML-DSA hashes
        // internally.
        Algorithm::MlDsa44 => &[0x1210],
        Algorithm::MlDsa65 => &[0x1211],
        Algorithm::MlDsa87 => &[0x1212],
    }
}

impl fmt::Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "varsig({} over dag-cbor)", self.algorithm)
    }
}

/// Why a header was refused.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum VarsigError {
    /// Does not begin with `0x34`.
    #[error("missing varsig prefix")]
    Prefix,

    /// Not version 1.
    #[error("unsupported varsig version")]
    Version,

    /// A malformed varint segment.
    #[error("malformed varint")]
    Varint,

    /// Ended before the payload encoding.
    #[error("header is truncated")]
    Truncated,

    /// An algorithm tag this crate does not know.
    #[error("unknown signature algorithm {0:#x}")]
    UnknownAlgorithm(u64),

    /// A known algorithm with a curve or hash this crate does not support.
    #[error("unsupported algorithm parameters")]
    UnsupportedParameters,

    /// A payload encoding other than DAG-CBOR.
    #[error("unsupported payload encoding {0:#x}")]
    UnsupportedEncoding(u64),
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn bytes_match_the_wire_format_table() {
        for (algorithm, hex) in [
            (Algorithm::Ed25519, "3401ed01ed011371"),
            (Algorithm::P256, "3401ec0180241271"),
            (Algorithm::Secp256k1, "3401ec01e7011271"),
            (Algorithm::MlDsa44, "3401902471"),
            (Algorithm::MlDsa65, "3401912471"),
            (Algorithm::MlDsa87, "3401922471"),
        ] {
            let header = Header::new(algorithm);
            assert_eq!(hex::encode(header.encode()), hex, "{algorithm}");
            assert_eq!(Header::decode(&header.encode()).unwrap(), header);
        }
    }

    #[test]
    fn refuses_what_it_does_not_understand() {
        assert_eq!(
            Header::decode(&[0x35, 0x01, 0xed, 0x01, 0xed, 0x01, 0x13, 0x71]),
            Err(VarsigError::Prefix)
        );
        assert_eq!(
            Header::decode(&[0x34, 0x02, 0xed, 0x01, 0xed, 0x01, 0x13, 0x71]),
            Err(VarsigError::Version)
        );
        assert_eq!(Header::decode(&[0x34, 0x01]), Err(VarsigError::Truncated));
        // Ed25519 with SHA-256 is a parameter set nobody uses.
        assert_eq!(
            Header::decode(&[0x34, 0x01, 0xed, 0x01, 0xed, 0x01, 0x12, 0x71]),
            Err(VarsigError::UnsupportedParameters)
        );
        // RSA.
        assert_eq!(
            Header::decode(&[0x34, 0x01, 0x85, 0x24, 0x12, 0x80, 0x02, 0x71]),
            Err(VarsigError::UnknownAlgorithm(0x1205))
        );
        // Ed25519 over DAG-JSON.
        assert_eq!(
            Header::decode(&[0x34, 0x01, 0xed, 0x01, 0xed, 0x01, 0x13, 0xa9, 0x02]),
            Err(VarsigError::UnsupportedEncoding(0x0129))
        );
        // A varint cut short.
        assert_eq!(
            Header::decode(&[0x34, 0x01, 0xed, 0x01, 0xed, 0x01, 0x13, 0xf1]),
            Err(VarsigError::Varint)
        );
        // An extra trailing segment is a parameter set nobody defined.
        assert_eq!(
            Header::decode(&[0x34, 0x01, 0xed, 0x01, 0xed, 0x01, 0x13, 0x71, 0x00]),
            Err(VarsigError::UnsupportedParameters)
        );
    }
}
