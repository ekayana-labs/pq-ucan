//! ML-DSA (FIPS 204) through `aws-lc-rs`.

use alloc::vec;
use core::fmt;

use aws_lc_rs::signature::{
    KeyPair as _, PqdsaKeyPair, PqdsaSigningAlgorithm, PqdsaVerificationAlgorithm,
    UnparsedPublicKey, ML_DSA_44, ML_DSA_44_SIGNING, ML_DSA_65, ML_DSA_65_SIGNING, ML_DSA_87,
    ML_DSA_87_SIGNING,
};

use super::{Algorithm, CryptoError, PublicKey, Signature, Signer};

fn verification(algorithm: Algorithm) -> Option<&'static PqdsaVerificationAlgorithm> {
    match algorithm {
        Algorithm::MlDsa44 => Some(&ML_DSA_44),
        Algorithm::MlDsa65 => Some(&ML_DSA_65),
        Algorithm::MlDsa87 => Some(&ML_DSA_87),
        _ => None,
    }
}

fn signing(algorithm: Algorithm) -> Option<&'static PqdsaSigningAlgorithm> {
    match algorithm {
        Algorithm::MlDsa44 => Some(&ML_DSA_44_SIGNING),
        Algorithm::MlDsa65 => Some(&ML_DSA_65_SIGNING),
        Algorithm::MlDsa87 => Some(&ML_DSA_87_SIGNING),
        _ => None,
    }
}

pub(super) fn verify(
    algorithm: Algorithm,
    key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    let alg = verification(algorithm).ok_or(CryptoError::Unsupported(algorithm))?;
    UnparsedPublicKey::new(alg, key)
        .verify(message, signature)
        .map_err(|_| CryptoError::VerificationFailed)
}

/// An ML-DSA signing key and its `did:key`, at any of the three parameter
/// sets.
pub struct MlDsaKeypair {
    algorithm: Algorithm,
    pair: PqdsaKeyPair,
    public: PublicKey,
}

impl MlDsaKeypair {
    /// A fresh random key at `algorithm`, which must be an ML-DSA parameter
    /// set.
    pub fn generate(algorithm: Algorithm) -> Result<Self, CryptoError> {
        let alg = signing(algorithm).ok_or(CryptoError::Unsupported(algorithm))?;
        let pair = PqdsaKeyPair::generate(alg).map_err(|_| CryptoError::Backend)?;
        Self::wrap(algorithm, pair)
    }

    /// The key for a 32 byte seed, the `mldsa-*-priv-seed` multicodec form.
    /// Deterministic.
    pub fn from_seed(algorithm: Algorithm, seed: &[u8; 32]) -> Result<Self, CryptoError> {
        let alg = signing(algorithm).ok_or(CryptoError::Unsupported(algorithm))?;
        let pair = PqdsaKeyPair::from_seed(alg, seed).map_err(|_| CryptoError::Backend)?;
        Self::wrap(algorithm, pair)
    }

    /// The parameter set.
    #[must_use]
    pub const fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    fn wrap(algorithm: Algorithm, pair: PqdsaKeyPair) -> Result<Self, CryptoError> {
        let public = PublicKey::new(algorithm, pair.public_key().as_ref())?;
        Ok(MlDsaKeypair {
            algorithm,
            pair,
            public,
        })
    }
}

impl Signer for MlDsaKeypair {
    fn public_key(&self) -> &PublicKey {
        &self.public
    }

    fn sign(&self, message: &[u8]) -> Result<Signature, CryptoError> {
        let mut buffer = vec![0u8; self.algorithm.signature_len()];
        let written = self
            .pair
            .sign(message, &mut buffer)
            .map_err(|_| CryptoError::Backend)?;
        buffer.truncate(written);
        Signature::new(self.algorithm, &buffer)
    }
}

impl fmt::Debug for MlDsaKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MlDsaKeypair({}, {})", self.algorithm, self.public.did())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn every_parameter_set_signs_and_verifies() {
        for algorithm in [Algorithm::MlDsa44, Algorithm::MlDsa65, Algorithm::MlDsa87] {
            let key = MlDsaKeypair::from_seed(algorithm, &[9; 32]).unwrap();
            let sig = key.sign(b"msg").unwrap();
            assert_eq!(sig.as_bytes().len(), algorithm.signature_len());
            key.public_key().verify(b"msg", &sig).unwrap();
            assert_eq!(
                key.public_key().verify(b"other", &sig),
                Err(CryptoError::VerificationFailed)
            );
            let again = MlDsaKeypair::from_seed(algorithm, &[9; 32]).unwrap();
            assert_eq!(again.public_key(), key.public_key());
        }
    }

    #[test]
    fn refuses_a_classical_algorithm() {
        assert_eq!(
            MlDsaKeypair::generate(Algorithm::Ed25519).err(),
            Some(CryptoError::Unsupported(Algorithm::Ed25519))
        );
    }
}
