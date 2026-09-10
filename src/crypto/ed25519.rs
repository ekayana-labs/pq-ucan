//! Ed25519 through `ed25519-dalek`.

use core::fmt;

use ed25519_dalek::{Signer as _, SigningKey, Verifier as _, VerifyingKey};
use rand_core::CryptoRng;

use super::{Algorithm, CryptoError, PublicKey, Signature, Signer};

pub(super) fn key_is_valid(bytes: &[u8]) -> bool {
    <[u8; 32]>::try_from(bytes).is_ok_and(|arr| VerifyingKey::from_bytes(&arr).is_ok())
}

pub(super) fn verify(key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
    let key = <[u8; 32]>::try_from(key).map_err(|_| CryptoError::InvalidKey(Algorithm::Ed25519))?;
    let key =
        VerifyingKey::from_bytes(&key).map_err(|_| CryptoError::InvalidKey(Algorithm::Ed25519))?;
    let signature = ed25519_dalek::Signature::from_slice(signature)
        .map_err(|_| CryptoError::InvalidSignature)?;
    key.verify(message, &signature)
        .map_err(|_| CryptoError::VerificationFailed)
}

/// An Ed25519 signing key and its `did:key`.
pub struct Ed25519Keypair {
    signing: SigningKey,
    public: PublicKey,
}

impl Ed25519Keypair {
    /// A fresh random key.
    pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        Self::wrap(SigningKey::generate(rng))
    }

    /// The key for a 32 byte seed. Deterministic.
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self::wrap(SigningKey::from_bytes(seed))
    }

    /// The 32 byte seed. Secret.
    #[must_use]
    pub fn to_seed(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    fn wrap(signing: SigningKey) -> Self {
        let bytes = signing.verifying_key().to_bytes();
        // A key derived by the backend is always well formed; the fallback
        // cannot be reached and keeps the constructor infallible.
        let public = PublicKey::new(Algorithm::Ed25519, &bytes).unwrap_or_else(|_| PublicKey {
            algorithm: Algorithm::Ed25519,
            bytes: bytes.into(),
        });
        Ed25519Keypair { signing, public }
    }
}

impl Signer for Ed25519Keypair {
    fn public_key(&self) -> &PublicKey {
        &self.public
    }

    fn sign(&self, message: &[u8]) -> Result<Signature, CryptoError> {
        Signature::new(Algorithm::Ed25519, &self.signing.sign(message).to_bytes())
    }
}

impl fmt::Debug for Ed25519Keypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ed25519Keypair({})", self.public.did())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn signs_and_verifies_and_rejects_the_wrong_key() {
        let a = Ed25519Keypair::from_seed(&[1; 32]);
        let b = Ed25519Keypair::from_seed(&[2; 32]);
        let sig = a.sign(b"msg").unwrap();
        a.public_key().verify(b"msg", &sig).unwrap();
        assert_eq!(
            b.public_key().verify(b"msg", &sig),
            Err(CryptoError::VerificationFailed)
        );
        assert_eq!(
            a.public_key().verify(b"other", &sig),
            Err(CryptoError::VerificationFailed)
        );
    }

    #[test]
    fn did_key_uses_the_registered_prefix() {
        let key = Ed25519Keypair::from_seed(&[7; 32]);
        assert!(key.did().as_str().starts_with("did:key:z6Mk"));
    }
}
