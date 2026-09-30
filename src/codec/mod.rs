//! Strict DAG-CBOR, and strict DAG-JSON in [`json`].
//!
//! The encoder emits canonical form only. The decoder accepts canonical
//! form only: definite lengths, minimal integers, sorted unique string
//! keys, finite 64-bit floats, tag 42 for links, nothing left over. Two
//! byte strings never decode to the same value, which is what makes
//! signing the bytes safe.

mod decode;
mod encode;
pub mod json;
mod varint;

use thiserror::Error;

pub use decode::{decode, Reader};
pub(crate) use encode::{bytes as bytes_item, head};
pub use encode::{encode, encode_into};
pub use varint::{put_uvarint, read_uvarint};

/// Deepest nesting the codec will follow in either direction.
pub const MAX_DEPTH: u32 = 128;

/// Why bytes were refused, or a value could not be encoded.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CodecError {
    /// The input ended inside an item.
    #[error("unexpected end of input")]
    UnexpectedEnd,

    /// Bytes remain after the value.
    #[error("trailing bytes after the value")]
    TrailingBytes,

    /// An item of indefinite length, which DAG-CBOR forbids.
    #[error("indefinite length")]
    IndefiniteLength,

    /// An integer or length that could have used a shorter encoding.
    #[error("non-minimal integer encoding")]
    NonMinimalInteger,

    /// An integer outside the 64-bit range DAG-CBOR allows.
    #[error("integer out of range")]
    IntegerOutOfRange,

    /// A float that is not a finite 64-bit value.
    #[error("invalid float")]
    InvalidFloat,

    /// A text string that is not UTF-8.
    #[error("invalid UTF-8 in text")]
    InvalidUtf8,

    /// A map key that is not a text string.
    #[error("map key is not text")]
    NonStringKey,

    /// Map keys not sorted by length, then bytewise.
    #[error("map keys out of order")]
    UnsortedKeys,

    /// The same map key twice.
    #[error("duplicate map key")]
    DuplicateKey,

    /// A tag other than 42.
    #[error("unsupported tag {0}")]
    UnsupportedTag(u64),

    /// Tag 42 content that is not a valid CID with identity multibase.
    #[error("invalid CID")]
    InvalidCid,

    /// A simple value other than `false`, `true` or `null`.
    #[error("unsupported simple value")]
    UnsupportedSimple,

    /// A reserved value in the head byte.
    #[error("reserved header")]
    Reserved,

    /// Nesting deeper than [`MAX_DEPTH`].
    #[error("nesting too deep")]
    NestingTooDeep,

    /// A length larger than the platform can address.
    #[error("length too large")]
    LengthTooLarge,

    /// An unsigned varint that is malformed or not minimal.
    #[error("invalid varint")]
    InvalidVarint,

    /// The next item is not of the kind the caller asked for.
    #[error("expected a different item type")]
    UnexpectedType,

    /// Text that is not JSON.
    #[error("invalid JSON")]
    InvalidJson,

    /// JSON that decodes but is not the canonical DAG-JSON of its value.
    #[error("not canonical DAG-JSON")]
    NotCanonical,

    /// A float in DAG-JSON. Implementations write floats differently, so a
    /// float has no single text form to sign.
    #[error("floats have no canonical DAG-JSON form")]
    FloatInText,

    /// A map that uses the `/` key, which DAG-JSON reserves for links and
    /// bytes.
    #[error("the `/` key is reserved")]
    ReservedKey,

    /// Bytes that are not unpadded standard base64.
    #[error("invalid base64")]
    InvalidBase64,
}
