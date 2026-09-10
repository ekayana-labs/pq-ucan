//! Decentralized identifiers, `did:key`, and the resolver that turns a DID
//! into a key.

use alloc::{boxed::Box, string::String, vec::Vec};
use core::fmt;

use thiserror::Error;

use crate::{
    codec::{put_uvarint, read_uvarint},
    crypto::{Algorithm, PublicKey},
};

/// A syntactically valid DID, possibly with DID URL parts.
///
/// Any method is accepted. Only `did:key` can be turned into a key without
/// help; everything else goes through a [`Resolver`]. When two DIDs are
/// compared as principals the path, query and fragment are ignored, as
/// the specification requires.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Did(Box<str>);

impl Did {
    /// Parse a DID string.
    pub fn parse(text: &str) -> Result<Self, DidError> {
        let rest = text.strip_prefix("did:").ok_or(DidError::Scheme)?;
        let (method, tail) = rest.split_once(':').ok_or(DidError::MethodId)?;
        if method.is_empty()
            || !method
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        {
            return Err(DidError::Method);
        }
        let id_end = tail.find(['/', '?', '#']).unwrap_or(tail.len());
        let id = tail.get(..id_end).ok_or(DidError::MethodId)?;
        if id.is_empty() || id.ends_with(':') || !id_chars_are_valid(id) {
            return Err(DidError::MethodId);
        }
        Ok(Did(text.into()))
    }

    /// The `did:key` for a public key.
    #[must_use]
    pub fn from_key(key: &PublicKey) -> Self {
        let mut raw = Vec::with_capacity(2 + key.as_bytes().len());
        put_uvarint(key.algorithm().multicodec(), &mut raw);
        raw.extend_from_slice(key.as_bytes());
        let mut text = String::from("did:key:z");
        text.push_str(&bs58::encode(raw).into_string());
        Did(text.into())
    }

    /// The full string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The method name, `key` in `did:key:z…`.
    #[must_use]
    pub fn method(&self) -> &str {
        self.base()
            .get(4..)
            .and_then(|rest| rest.split(':').next())
            .unwrap_or_default()
    }

    /// The method-specific identifier, without DID URL parts.
    #[must_use]
    pub fn method_id(&self) -> &str {
        self.base()
            .get(4..)
            .and_then(|rest| rest.split_once(':'))
            .map_or("", |(_, id)| id)
    }

    /// `did:method:id`, with any path, query and fragment removed.
    #[must_use]
    pub fn base(&self) -> &str {
        let end = self.0.find(['/', '?', '#']).unwrap_or(self.0.len());
        self.0.get(..end).unwrap_or(&self.0)
    }

    /// The fragment after `#`, if any.
    #[must_use]
    pub fn fragment(&self) -> Option<&str> {
        self.0.split_once('#').map(|(_, f)| f)
    }

    /// Whether two DIDs name the same principal. DID URL parts are ignored.
    #[must_use]
    pub fn same_principal(&self, other: &Did) -> bool {
        self.base() == other.base()
    }

    /// The public key inside a `did:key`.
    pub fn key(&self) -> Result<PublicKey, DidError> {
        if self.method() != "key" {
            return Err(DidError::NotKey);
        }
        let b58 = self
            .method_id()
            .strip_prefix('z')
            .ok_or(DidError::Multibase)?;
        let raw = bs58::decode(b58).into_vec().map_err(|_| DidError::Base58)?;
        let (code, used) = read_uvarint(&raw).map_err(|_| DidError::Multibase)?;
        let algorithm = Algorithm::from_multicodec(code).ok_or(DidError::UnknownKeyType(code))?;
        let key = raw.get(used..).ok_or(DidError::Key)?;
        PublicKey::new(algorithm, key).map_err(|_| DidError::Key)
    }
}

fn id_chars_are_valid(id: &str) -> bool {
    let mut bytes = id.bytes();
    while let Some(b) = bytes.next() {
        let ok = match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'-' | b'_' | b':' => true,
            b'%' => {
                matches!((bytes.next(), bytes.next()), (Some(x), Some(y)) if x.is_ascii_hexdigit() && y.is_ascii_hexdigit())
            }
            _ => false,
        };
        if !ok {
            return false;
        }
    }
    true
}

impl fmt::Display for Did {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for Did {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Did({})", self.0)
    }
}

impl AsRef<str> for Did {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl core::str::FromStr for Did {
    type Err = DidError;

    fn from_str(text: &str) -> Result<Self, DidError> {
        Self::parse(text)
    }
}

/// Turns a DID into the public key that signs for it.
///
/// `did:key` needs no lookup and [`KeyResolver`] handles it. A method with
/// a document behind it, `did:web` or `did:bio`, implements this trait and
/// hands the validator its own resolver.
pub trait Resolver {
    /// The key for `did`.
    fn resolve(&self, did: &Did) -> Result<PublicKey, ResolveError>;
}

impl<R: Resolver + ?Sized> Resolver for &R {
    fn resolve(&self, did: &Did) -> Result<PublicKey, ResolveError> {
        (**self).resolve(did)
    }
}

/// Resolves `did:key` and nothing else.
#[derive(Debug, Clone, Copy, Default)]
pub struct KeyResolver;

impl Resolver for KeyResolver {
    fn resolve(&self, did: &Did) -> Result<PublicKey, ResolveError> {
        if did.method() != "key" {
            return Err(ResolveError::UnsupportedMethod);
        }
        did.key().map_err(ResolveError::Did)
    }
}

/// Why a DID string was refused.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DidError {
    /// Does not begin with `did:`.
    #[error("missing `did:` scheme")]
    Scheme,

    /// The method name is empty or not lowercase alphanumeric.
    #[error("invalid method name")]
    Method,

    /// The method-specific identifier is empty or has invalid characters.
    #[error("invalid method-specific identifier")]
    MethodId,

    /// A key was requested from a DID whose method is not `key`.
    #[error("not a did:key")]
    NotKey,

    /// A `did:key` identifier not in base58btc multibase.
    #[error("did:key must be multibase base58btc")]
    Multibase,

    /// Not valid base58.
    #[error("invalid base58")]
    Base58,

    /// A key multicodec this crate does not know.
    #[error("unknown key type {0:#x}")]
    UnknownKeyType(u64),

    /// The key bytes are the wrong length or not a valid key.
    #[error("invalid key")]
    Key,
}

/// Why a DID could not be turned into a key.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResolveError {
    /// The resolver does not handle this DID method.
    #[error("unsupported DID method")]
    UnsupportedMethod,

    /// The DID itself is malformed.
    #[error("{0}")]
    Did(#[from] DidError),

    /// The method is handled but nothing was found for this DID.
    #[error("DID not found")]
    NotFound,

    /// The lookup failed for a reason the resolver describes.
    #[error("resolution failed: {0}")]
    Failed(String),
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn parses_and_splits() {
        let did = Did::parse("did:example:abc:def/path?q=1#frag").unwrap();
        assert_eq!(did.method(), "example");
        assert_eq!(did.method_id(), "abc:def");
        assert_eq!(did.base(), "did:example:abc:def");
        assert_eq!(did.fragment(), Some("frag"));
        assert!(did.same_principal(&Did::parse("did:example:abc:def#other").unwrap()));
        assert!(!did.same_principal(&Did::parse("did:example:abc").unwrap()));
    }

    #[test]
    fn refuses_malformed_strings() {
        assert_eq!(Did::parse("key:z6Mk"), Err(DidError::Scheme));
        assert_eq!(Did::parse("did:Key:z6Mk"), Err(DidError::Method));
        assert_eq!(Did::parse("did::z6Mk"), Err(DidError::Method));
        assert_eq!(Did::parse("did:key"), Err(DidError::MethodId));
        assert_eq!(Did::parse("did:key:"), Err(DidError::MethodId));
        assert_eq!(Did::parse("did:key:abc:"), Err(DidError::MethodId));
        assert_eq!(Did::parse("did:key:a b"), Err(DidError::MethodId));
        assert_eq!(Did::parse("did:key:a%2"), Err(DidError::MethodId));
        assert!(Did::parse("did:key:a%2F").is_ok());
    }

    #[test]
    fn did_key_rejects_the_near_misses() {
        assert_eq!(
            Did::parse("did:web:example.com").unwrap().key(),
            Err(DidError::NotKey)
        );
        assert_eq!(
            Did::parse("did:key:f6Mk").unwrap().key(),
            Err(DidError::Multibase)
        );
        assert_eq!(
            Did::parse("did:key:z0").unwrap().key(),
            Err(DidError::Base58)
        );
        // `ed25519-priv` is a key multicodec, but not a public one.
        let mut raw = Vec::new();
        put_uvarint(0x1300, &mut raw);
        raw.extend_from_slice(&[0; 32]);
        let text = alloc::format!("did:key:z{}", bs58::encode(raw).into_string());
        assert_eq!(
            Did::parse(&text).unwrap().key(),
            Err(DidError::UnknownKeyType(0x1300))
        );
    }

    #[cfg(feature = "ed25519")]
    #[test]
    fn did_key_round_trips_a_known_vector() {
        // From the did:key specification test vectors.
        let did = Did::parse("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK").unwrap();
        let key = did.key().unwrap();
        assert_eq!(key.algorithm(), Algorithm::Ed25519);
        assert_eq!(Did::from_key(&key), did);
        assert_eq!(KeyResolver.resolve(&did).unwrap(), key);
    }
}
