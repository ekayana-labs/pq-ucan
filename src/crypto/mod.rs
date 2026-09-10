//! Signature algorithms, public keys, signatures and signers.
//!
//! The algorithm is data. A [`PublicKey`] and a [`Signature`] each carry
//! theirs, and a mismatch is an error before any arithmetic happens.
//! Backends are behind features; an algorithm whose backend is not
//! compiled in still parses, and fails only at verification with
//! [`CryptoError::Unsupported`].

use alloc::boxed::Box;
use core::fmt;

use thiserror::Error;

use crate::did::Did;

#[cfg(feature = "ed25519")]
pub mod ed25519;
#[cfg(feature = "ml-dsa")]
pub mod ml_dsa;
#[cfg(feature = "p256")]
pub mod p256;
#[cfg(feature = "secp256k1")]
pub mod secp256k1;

/// A signature algorithm the crate knows how to name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Algorithm {
    /// `EdDSA` over Curve25519, RFC 8032.
    Ed25519,
    /// ECDSA over P-256 with SHA-256 (ES256).
    P256,
    /// ECDSA over secp256k1 with SHA-256 (ES256K).
    Secp256k1,
    /// ML-DSA-44, FIPS 204.
    MlDsa44,
    /// ML-DSA-65, FIPS 204.
    MlDsa65,
    /// ML-DSA-87, FIPS 204.
    MlDsa87,
}

impl Algorithm {
    /// Every algorithm, in registry order.
    pub const ALL: [Algorithm; 6] = [
        Algorithm::Ed25519,
        Algorithm::P256,
        Algorithm::Secp256k1,
        Algorithm::MlDsa44,
        Algorithm::MlDsa65,
        Algorithm::MlDsa87,
    ];

    /// The multicodec of the public key type, which is also the `did:key`
    /// prefix and, for ML-DSA, the varsig tag.
    #[must_use]
    pub const fn multicodec(self) -> u64 {
        match self {
            Algorithm::Ed25519 => 0xed,
            Algorithm::P256 => 0x1200,
            Algorithm::Secp256k1 => 0xe7,
            Algorithm::MlDsa44 => 0x1210,
            Algorithm::MlDsa65 => 0x1211,
            Algorithm::MlDsa87 => 0x1212,
        }
    }

    /// The algorithm for a public key multicodec.
    #[must_use]
    pub fn from_multicodec(code: u64) -> Option<Self> {
        Self::ALL.into_iter().find(|a| a.multicodec() == code)
    }

    /// Public key length in bytes. Elliptic curve keys are compressed.
    #[must_use]
    pub const fn public_key_len(self) -> usize {
        match self {
            Algorithm::Ed25519 => 32,
            Algorithm::P256 | Algorithm::Secp256k1 => 33,
            Algorithm::MlDsa44 => 1312,
            Algorithm::MlDsa65 => 1952,
            Algorithm::MlDsa87 => 2592,
        }
    }

    /// Signature length in bytes.
    #[must_use]
    pub const fn signature_len(self) -> usize {
        match self {
            Algorithm::Ed25519 | Algorithm::P256 | Algorithm::Secp256k1 => 64,
            Algorithm::MlDsa44 => 2420,
            Algorithm::MlDsa65 => 3309,
            Algorithm::MlDsa87 => 4627,
        }
    }

    /// The conventional name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Algorithm::Ed25519 => "Ed25519",
            Algorithm::P256 => "ES256",
            Algorithm::Secp256k1 => "ES256K",
            Algorithm::MlDsa44 => "ML-DSA-44",
            Algorithm::MlDsa65 => "ML-DSA-65",
            Algorithm::MlDsa87 => "ML-DSA-87",
        }
    }

    /// Whether the algorithm resists a cryptographically relevant quantum
    /// computer.
    #[must_use]
    pub const fn is_post_quantum(self) -> bool {
        matches!(
            self,
            Algorithm::MlDsa44 | Algorithm::MlDsa65 | Algorithm::MlDsa87
        )
    }

    /// Whether a backend for this algorithm was compiled in.
    #[must_use]
    pub const fn is_available(self) -> bool {
        match self {
            Algorithm::Ed25519 => cfg!(feature = "ed25519"),
            Algorithm::P256 => cfg!(feature = "p256"),
            Algorithm::Secp256k1 => cfg!(feature = "secp256k1"),
            Algorithm::MlDsa44 | Algorithm::MlDsa65 | Algorithm::MlDsa87 => {
                cfg!(feature = "ml-dsa")
            }
        }
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A public key with its algorithm.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PublicKey {
    algorithm: Algorithm,
    bytes: Box<[u8]>,
}

impl PublicKey {
    /// Wrap raw key bytes. The length is checked for every algorithm and
    /// the encoding is checked when the backend is available, so a key that
    /// constructs is a key that can verify.
    pub fn new(algorithm: Algorithm, bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != algorithm.public_key_len() || !backend::key_is_valid(algorithm, bytes) {
            return Err(CryptoError::InvalidKey(algorithm));
        }
        Ok(PublicKey {
            algorithm,
            bytes: bytes.into(),
        })
    }

    /// The algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// The raw key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The `did:key` for this key.
    #[must_use]
    pub fn did(&self) -> Did {
        Did::from_key(self)
    }

    /// Verify `signature` over `message`.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), CryptoError> {
        if signature.algorithm != self.algorithm {
            return Err(CryptoError::AlgorithmMismatch {
                key: self.algorithm,
                signature: signature.algorithm,
            });
        }
        backend::verify(self.algorithm, &self.bytes, message, &signature.bytes)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({}, {})", self.algorithm, self.did())
    }
}

/// A signature with its algorithm.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Signature {
    algorithm: Algorithm,
    bytes: Box<[u8]>,
}

impl Signature {
    /// Wrap raw signature bytes of the right length.
    pub fn new(algorithm: Algorithm, bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != algorithm.signature_len() {
            return Err(CryptoError::InvalidSignature);
        }
        Ok(Signature {
            algorithm,
            bytes: bytes.into(),
        })
    }

    /// The algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// The raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Signature({}, {} bytes)",
            self.algorithm,
            self.bytes.len()
        )
    }
}

/// Something that can sign on behalf of a DID.
///
/// A builder takes a signer and reads the issuer from it, so a token's
/// `iss` always matches the key that signed it. Types for other DID
/// methods override [`Signer::did`].
pub trait Signer {
    /// The verifying key.
    fn public_key(&self) -> &PublicKey;

    /// Sign `message`.
    fn sign(&self, message: &[u8]) -> Result<Signature, CryptoError>;

    /// The DID that tokens will carry as issuer. `did:key` by default.
    fn did(&self) -> Did {
        self.public_key().did()
    }
}

impl<S: Signer + ?Sized> Signer for &S {
    fn public_key(&self) -> &PublicKey {
        (**self).public_key()
    }

    fn sign(&self, message: &[u8]) -> Result<Signature, CryptoError> {
        (**self).sign(message)
    }

    fn did(&self) -> Did {
        (**self).did()
    }
}

/// A key, signature or algorithm problem.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CryptoError {
    /// The backend for this algorithm is not compiled in.
    #[error("{0} is not available in this build")]
    Unsupported(Algorithm),

    /// Wrong length or not a valid encoding for the algorithm.
    #[error("invalid {0} public key")]
    InvalidKey(Algorithm),

    /// Wrong length or not a valid encoding for the algorithm.
    #[error("invalid signature")]
    InvalidSignature,

    /// The key and the signature name different algorithms.
    #[error("key is {key}, signature is {signature}")]
    AlgorithmMismatch {
        /// The key's algorithm.
        key: Algorithm,
        /// The signature's algorithm.
        signature: Algorithm,
    },

    /// The signature does not verify.
    #[error("signature verification failed")]
    VerificationFailed,

    /// The backend refused to sign or generate.
    #[error("backend failure")]
    Backend,
}

/// Dispatch to whichever backends were compiled in.
mod backend {
    use super::{Algorithm, CryptoError};

    #[allow(unused_variables)]
    pub(super) fn key_is_valid(algorithm: Algorithm, bytes: &[u8]) -> bool {
        match algorithm {
            #[cfg(feature = "ed25519")]
            Algorithm::Ed25519 => super::ed25519::key_is_valid(bytes),
            #[cfg(feature = "p256")]
            Algorithm::P256 => super::p256::key_is_valid(bytes),
            #[cfg(feature = "secp256k1")]
            Algorithm::Secp256k1 => super::secp256k1::key_is_valid(bytes),
            // ML-DSA public keys have no invalid encodings of the right
            // length, so the length check upstream is the whole check.
            #[allow(unreachable_patterns)]
            _ => true,
        }
    }

    #[allow(unused_variables)]
    pub(super) fn verify(
        algorithm: Algorithm,
        key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        match algorithm {
            #[cfg(feature = "ed25519")]
            Algorithm::Ed25519 => super::ed25519::verify(key, message, signature),
            #[cfg(feature = "p256")]
            Algorithm::P256 => super::p256::verify(key, message, signature),
            #[cfg(feature = "secp256k1")]
            Algorithm::Secp256k1 => super::secp256k1::verify(key, message, signature),
            #[cfg(feature = "ml-dsa")]
            Algorithm::MlDsa44 | Algorithm::MlDsa65 | Algorithm::MlDsa87 => {
                super::ml_dsa::verify(algorithm, key, message, signature)
            }
            #[allow(unreachable_patterns)]
            other => Err(CryptoError::Unsupported(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multicodecs_round_trip() {
        for algorithm in Algorithm::ALL {
            assert_eq!(
                Algorithm::from_multicodec(algorithm.multicodec()),
                Some(algorithm)
            );
        }
        assert_eq!(Algorithm::from_multicodec(0x1300), None);
    }

    #[test]
    fn lengths_are_checked_before_anything_else() {
        assert_eq!(
            PublicKey::new(Algorithm::MlDsa87, &[0; 31]),
            Err(CryptoError::InvalidKey(Algorithm::MlDsa87))
        );
        assert_eq!(
            Signature::new(Algorithm::Ed25519, &[0; 63]),
            Err(CryptoError::InvalidSignature)
        );
    }
}
