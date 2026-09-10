//! CIDs as UCAN uses them: v1, DAG-CBOR, SHA-256, shown as base58btc.

use alloc::string::String;

use ipld_core::cid::{multihash::Multihash, Cid};
use sha2::{Digest, Sha256};
use thiserror::Error;

const DAG_CBOR: u64 = 0x71;
const SHA2_256: u64 = 0x12;

/// The CID of a DAG-CBOR block.
#[must_use]
pub fn of_dag_cbor(bytes: &[u8]) -> Cid {
    let digest = Sha256::digest(bytes);
    // A 32 byte digest always fits the 64 byte multihash buffer; the
    // fallback is unreachable and exists to keep this infallible.
    let hash = Multihash::<64>::wrap(SHA2_256, &digest).unwrap_or_default();
    Cid::new_v1(DAG_CBOR, hash)
}

/// The multibase base58btc text form, which begins with `zdpu` for UCAN
/// tokens.
#[must_use]
pub fn to_base58btc(cid: &Cid) -> String {
    let mut text = String::from("z");
    text.push_str(&bs58::encode(cid.to_bytes()).into_string());
    text
}

/// Parse the base58btc (`z…`) or base32 (`b…`) text form.
pub fn parse(text: &str) -> Result<Cid, CidError> {
    match text.strip_prefix('z') {
        Some(b58) => {
            let raw = bs58::decode(b58).into_vec().map_err(|_| CidError::Base58)?;
            Cid::try_from(raw.as_slice()).map_err(|_| CidError::Cid)
        }
        None => Cid::try_from(text).map_err(|_| CidError::Cid),
    }
}

/// Why a CID string was refused.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CidError {
    /// Not base58.
    #[error("invalid base58")]
    Base58,

    /// Decoded, but not a CID.
    #[error("invalid CID")]
    Cid,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn text_form_starts_with_zdpu_and_round_trips() {
        let cid = of_dag_cbor(&[0xa0]);
        let text = to_base58btc(&cid);
        assert!(text.starts_with("zdpu"), "{text}");
        assert_eq!(parse(&text).unwrap(), cid);
        assert_eq!(parse(&cid.to_string()).unwrap(), cid);
        assert_eq!(parse("zzz"), Err(CidError::Cid));
        assert_eq!(parse("z0"), Err(CidError::Base58));
    }
}
