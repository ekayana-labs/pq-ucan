//! The signed envelope every token type shares.
//!
//! `[signature, {"h": varsig, "<tag>": payload}]`. The signature covers the
//! second element: its bytes exactly as received, or its DAG-JSON form when
//! the varsig header names DAG-JSON. An [`Envelope`] keeps what was signed.

use alloc::{collections::BTreeMap, string::String, sync::Arc, vec::Vec};
use core::ops::Range;

use ipld_core::{cid::Cid, ipld::Ipld};
use thiserror::Error;

use crate::{
    cid, codec,
    crypto::{CryptoError, PublicKey, Signature, Signer},
    did::Did,
    error::PayloadError,
    time::Timestamp,
    varsig::{Encoding, Header},
    Error,
};

/// Which token a tag names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TokenKind {
    /// `ucan/dlg@1.0.0`.
    Delegation,
    /// `ucan/inv@1.0.0`.
    Invocation,
}

impl TokenKind {
    /// The tag the encoder writes.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            TokenKind::Delegation => "ucan/dlg@1.0.0",
            TokenKind::Invocation => "ucan/inv@1.0.0",
        }
    }

    fn from_tag(tag: &str, options: DecodeOptions) -> Result<Self, EnvelopeError> {
        match tag {
            "ucan/dlg@1.0.0" => Ok(TokenKind::Delegation),
            "ucan/inv@1.0.0" => Ok(TokenKind::Invocation),
            "ucan/dlg@1.0.0-rc.1" if options.release_candidate_tags => Ok(TokenKind::Delegation),
            "ucan/inv@1.0.0-rc.1" if options.release_candidate_tags => Ok(TokenKind::Invocation),
            other => Err(EnvelopeError::UnknownTag(String::from(other))),
        }
    }
}

/// What a decoder is willing to accept beyond the released specification.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DecodeOptions {
    release_candidate_tags: bool,
}

impl DecodeOptions {
    /// Released tags only.
    pub const STRICT: DecodeOptions = DecodeOptions {
        release_candidate_tags: false,
    };

    /// Also accept the `1.0.0-rc.1` tags that rs-ucan and the JavaScript
    /// implementation emit.
    #[must_use]
    pub const fn release_candidate_tags(mut self, accept: bool) -> Self {
        self.release_candidate_tags = accept;
        self
    }
}

/// A decoded envelope: the bytes, what they identify, and what was signed.
#[derive(Debug, Clone)]
pub struct Envelope {
    bytes: Arc<[u8]>,
    cid: Cid,
    header: Header,
    signature: Signature,
    signed: Signed,
    kind: TokenKind,
}

/// A token waiting for its signature. `signing` is what the key signs,
/// `sig_payload` the envelope's second element as DAG-CBOR. They are the
/// same bytes unless the header names DAG-JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Unsigned {
    pub(crate) signing: Vec<u8>,
    pub(crate) sig_payload: Vec<u8>,
}

#[derive(Debug, Clone)]
enum Signed {
    Cbor(Range<usize>),
    Json(Arc<[u8]>),
}

impl Envelope {
    /// Sign `payload` and assemble the envelope, then decode the result
    /// under the strict rules so that what the signer holds is exactly what
    /// a verifier will see.
    pub(crate) fn seal(signer: &dyn Signer, kind: TokenKind, payload: Ipld) -> Result<Self, Error> {
        let unsigned = Self::prepare(Header::new(signer.public_key().algorithm()), kind, payload)?;
        let signature = signer.sign(&unsigned.signing)?;
        Self::assemble(&unsigned.sig_payload, signature.as_bytes()).map(|(envelope, _)| envelope)
    }

    /// What a key held elsewhere signs to seal `payload` as `kind` under
    /// `header`, with the envelope element the signature goes with.
    pub(crate) fn prepare(
        header: Header,
        kind: TokenKind,
        payload: Ipld,
    ) -> Result<Unsigned, Error> {
        let value = sig_payload(&header.encode(), kind.tag(), payload);
        let sig_payload = codec::encode(&value)?;
        let signing = match header.encoding() {
            Encoding::DagCbor => sig_payload.clone(),
            Encoding::DagJson => codec::json::encode(&value)?.into_bytes(),
        };
        Ok(Unsigned {
            signing,
            sig_payload,
        })
    }

    /// Assemble `[signature, sig_payload]` and decode it under the strict
    /// rules. `signed` is the envelope's second element as DAG-CBOR, or the
    /// DAG-JSON text a text signer signed. The signature is not checked
    /// here. Verify the token against its issuer's key afterwards.
    pub(crate) fn assemble(signed: &[u8], signature: &[u8]) -> Result<(Self, Ipld), Error> {
        let converted;
        let sig_payload = if signed.first() == Some(&b'{') {
            converted = codec::encode(&codec::json::decode(signed)?)?;
            converted.as_slice()
        } else {
            signed
        };
        let mut bytes = Vec::with_capacity(3 + signature.len() + sig_payload.len());
        codec::head(4, 2, &mut bytes);
        codec::bytes_item(signature, &mut bytes);
        bytes.extend_from_slice(sig_payload);
        Self::open(&bytes, DecodeOptions::STRICT)
    }

    /// Parse an envelope and return it with its payload.
    pub(crate) fn open(bytes: &[u8], options: DecodeOptions) -> Result<(Self, Ipld), Error> {
        let mut reader = codec::Reader::new(bytes);
        if reader.array_len()? != 2 {
            return Err(EnvelopeError::Shape.into());
        }
        let signature_bytes = reader.bytes()?;
        let signed_start = reader.position();
        if reader.map_len()? != 2 || reader.text()? != "h" {
            return Err(EnvelopeError::Shape.into());
        }
        let header_bytes = reader.bytes()?;
        let header = Header::decode(header_bytes)?;
        let tag = reader.text()?;
        let kind = TokenKind::from_tag(tag, options)?;
        let payload = reader.value()?;
        if !matches!(payload, Ipld::Map(_)) {
            return Err(EnvelopeError::PayloadNotMap.into());
        }
        let signed_end = reader.position();
        reader.finish()?;
        let signature = Signature::new(header.algorithm(), signature_bytes)?;
        let signed = match header.encoding() {
            Encoding::DagCbor => Signed::Cbor(signed_start..signed_end),
            Encoding::DagJson => Signed::Json(Arc::from(
                codec::json::encode(&sig_payload(header_bytes, tag, payload.clone()))?.into_bytes(),
            )),
        };
        let envelope = Envelope {
            bytes: Arc::from(bytes),
            cid: cid::of_dag_cbor(bytes),
            header,
            signature,
            signed,
            kind,
        };
        Ok((envelope, payload))
    }

    /// Check the signature under `key`, which must match the header's
    /// algorithm.
    pub fn verify(&self, key: &PublicKey) -> Result<(), Error> {
        if key.algorithm() != self.header.algorithm() {
            return Err(CryptoError::AlgorithmMismatch {
                key: key.algorithm(),
                signature: self.header.algorithm(),
            }
            .into());
        }
        let signed = match &self.signed {
            Signed::Cbor(range) => self.bytes.get(range.clone()).ok_or(EnvelopeError::Shape)?,
            Signed::Json(text) => text,
        };
        key.verify(signed, &self.signature)?;
        Ok(())
    }

    /// The complete token bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The CID of the token bytes.
    #[must_use]
    pub const fn cid(&self) -> &Cid {
        &self.cid
    }

    /// The varsig header.
    #[must_use]
    pub const fn header(&self) -> &Header {
        &self.header
    }

    /// The signature.
    #[must_use]
    pub const fn signature(&self) -> &Signature {
        &self.signature
    }

    /// Which token type the tag named.
    #[must_use]
    pub const fn kind(&self) -> TokenKind {
        self.kind
    }

    /// The whole token as canonical DAG-JSON, for logs and debugging. The
    /// token itself stays DAG-CBOR. A payload that holds a float has no
    /// text form and fails.
    pub fn to_dag_json(&self) -> Result<String, Error> {
        Ok(codec::json::encode(&codec::decode(&self.bytes)?)?)
    }
}

/// Why bytes are not a token envelope.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EnvelopeError {
    /// Not `[bytes, {"h": bytes, tag: map}]`.
    #[error("not a UCAN envelope")]
    Shape,

    /// A tag this crate does not recognise, or one it was told not to
    /// accept.
    #[error("unknown token tag `{0}`")]
    UnknownTag(String),

    /// The item after the tag is not a map.
    #[error("token payload is not a map")]
    PayloadNotMap,

    /// The envelope is a different token type than the caller asked for.
    #[error("expected a {expected:?} token, found {found:?}")]
    WrongKind {
        /// What was asked for.
        expected: TokenKind,
        /// What the tag named.
        found: TokenKind,
    },
}

// `{"h": header, tag: payload}`, the second element of the envelope.
fn sig_payload(header: &[u8], tag: &str, payload: Ipld) -> Ipld {
    let mut map = BTreeMap::new();
    map.insert(String::from("h"), Ipld::Bytes(header.to_vec()));
    map.insert(String::from(tag), payload);
    Ipld::Map(map)
}

/// The fields of a payload map, consumed one at a time so that anything
/// left over is an unknown field.
pub(crate) struct Fields(BTreeMap<String, Ipld>);

impl Fields {
    pub(crate) fn new(payload: Ipld) -> Result<Self, Error> {
        match payload {
            Ipld::Map(map) => Ok(Fields(map)),
            _ => Err(EnvelopeError::PayloadNotMap.into()),
        }
    }

    pub(crate) fn take(&mut self, key: &'static str) -> Option<Ipld> {
        self.0.remove(key)
    }

    pub(crate) fn require(&mut self, key: &'static str) -> Result<Ipld, Error> {
        self.take(key)
            .ok_or_else(|| PayloadError::Missing(key).into())
    }

    pub(crate) fn finish(self) -> Result<(), Error> {
        match self.0.into_keys().next() {
            Some(key) => Err(PayloadError::Unknown(key).into()),
            None => Ok(()),
        }
    }
}

pub(crate) fn text(value: Ipld, field: &'static str) -> Result<String, Error> {
    match value {
        Ipld::String(s) => Ok(s),
        _ => Err(PayloadError::Type(field).into()),
    }
}

pub(crate) fn did(value: Ipld, field: &'static str) -> Result<Did, Error> {
    Ok(Did::parse(&text(value, field)?)?)
}

pub(crate) fn bytes(value: Ipld, field: &'static str) -> Result<Vec<u8>, Error> {
    match value {
        Ipld::Bytes(b) => Ok(b),
        _ => Err(PayloadError::Type(field).into()),
    }
}

pub(crate) fn map(value: Ipld, field: &'static str) -> Result<BTreeMap<String, Ipld>, Error> {
    match value {
        Ipld::Map(m) => Ok(m),
        _ => Err(PayloadError::Type(field).into()),
    }
}

pub(crate) fn list(value: Ipld, field: &'static str) -> Result<Vec<Ipld>, Error> {
    match value {
        Ipld::List(l) => Ok(l),
        _ => Err(PayloadError::Type(field).into()),
    }
}

pub(crate) fn timestamp(value: &Ipld, field: &'static str) -> Result<Timestamp, Error> {
    match value {
        Ipld::Integer(i) => i64::try_from(*i)
            .ok()
            .and_then(|s| Timestamp::from_unix(s).ok())
            .ok_or_else(|| PayloadError::Range(field).into()),
        _ => Err(PayloadError::Type(field).into()),
    }
}

pub(crate) fn link(value: &Ipld, field: &'static str) -> Result<Cid, Error> {
    match value {
        Ipld::Link(cid) => Ok(*cid),
        _ => Err(PayloadError::Type(field).into()),
    }
}
