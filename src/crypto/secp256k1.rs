//! ES256K: ECDSA over secp256k1 with SHA-256, through `k256`.

use core::fmt;

use k256::{
    ecdsa::{
        signature::{Signer as _, Verifier as _},
        Signature as EcdsaSignature, SigningKey, VerifyingKey,
    },
    elliptic_curve::{sec1::ToSec1Point as _, Generate as _},
    PublicKey as CurvePoint,
};
use rand_core::CryptoRng;

use super::{Algorithm, CryptoError, PublicKey, Signature, Signer};

pub(super) fn key_is_valid(bytes: &[u8]) -> bool {
    VerifyingKey::from_sec1_bytes(bytes).is_ok()
}

pub(super) fn verify(key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
    let key = VerifyingKey::from_sec1_bytes(key)
        .map_err(|_| CryptoError::InvalidKey(Algorithm::Secp256k1))?;
    let signature =
        EcdsaSignature::from_slice(signature).map_err(|_| CryptoError::InvalidSignature)?;
    key.verify(message, &signature)
        .map_err(|_| CryptoError::VerificationFailed)
}

/// A secp256k1 signing key and its `did:key`.
pub struct Secp256k1Keypair {
    signing: SigningKey,
    public: PublicKey,
}

impl Secp256k1Keypair {
    /// A fresh random key.
    pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        Self::wrap(SigningKey::generate_from_rng(rng))
    }

    /// The key for a 32 byte scalar. Fails when the scalar is zero or not
    /// below the curve order.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        SigningKey::from_slice(bytes)
            .map(Self::wrap)
            .map_err(|_| CryptoError::InvalidKey(Algorithm::Secp256k1))
    }

    /// The 32 byte scalar. Secret.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.signing.to_bytes().into()
    }

    fn wrap(signing: SigningKey) -> Self {
        let point = CurvePoint::from(signing.verifying_key()).to_compressed_point();
        let public =
            PublicKey::new(Algorithm::Secp256k1, point.as_slice()).unwrap_or_else(|_| PublicKey {
                algorithm: Algorithm::Secp256k1,
                bytes: point.as_slice().into(),
            });
        Secp256k1Keypair { signing, public }
    }
}

impl Signer for Secp256k1Keypair {
    fn public_key(&self) -> &PublicKey {
        &self.public
    }

    fn sign(&self, message: &[u8]) -> Result<Signature, CryptoError> {
        let signature: EcdsaSignature = self.signing.sign(message);
        Signature::new(Algorithm::Secp256k1, &signature.to_bytes())
    }
}

impl fmt::Debug for Secp256k1Keypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secp256k1Keypair({})", self.public.did())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn signs_and_verifies() {
        let key = Secp256k1Keypair::from_bytes(&[5; 32]).unwrap();
        let sig = key.sign(b"msg").unwrap();
        key.public_key().verify(b"msg", &sig).unwrap();
        assert_eq!(
            key.public_key().verify(b"other", &sig),
            Err(CryptoError::VerificationFailed)
        );
        assert!(key.did().as_str().starts_with("did:key:zQ3s"));
    }
}
