use alloc::vec::Vec;

use ipld_core::ipld::Ipld;

use super::{CodecError, MAX_DEPTH};

const MAJOR_UINT: u8 = 0;
const MAJOR_NINT: u8 = 1;
const MAJOR_BYTES: u8 = 2;
const MAJOR_TEXT: u8 = 3;
const MAJOR_ARRAY: u8 = 4;
const MAJOR_MAP: u8 = 5;
const MAJOR_TAG: u8 = 6;

const FALSE: u8 = 0xf4;
const TRUE: u8 = 0xf5;
const NULL: u8 = 0xf6;
const FLOAT64: u8 = 0xfb;

/// The CID tag and the identity multibase prefix that precedes CID bytes.
pub(crate) const CID_TAG: u64 = 42;
pub(crate) const CID_MULTIBASE_IDENTITY: u8 = 0x00;

/// Encode a value as canonical DAG-CBOR.
pub fn encode(value: &Ipld) -> Result<Vec<u8>, CodecError> {
    let mut out = Vec::new();
    encode_into(value, &mut out)?;
    Ok(out)
}

/// Encode a value as canonical DAG-CBOR, appending to `out`.
pub fn encode_into(value: &Ipld, out: &mut Vec<u8>) -> Result<(), CodecError> {
    item(value, out, 0)
}

/// Write an item head: the major type and its argument in the shortest form.
pub(crate) fn head(major: u8, arg: u64, out: &mut Vec<u8>) {
    let major = major << 5;
    match arg {
        0..=23 => out.push(major | u8::try_from(arg).unwrap_or(23)),
        24..=0xff => {
            out.push(major | 24);
            out.extend_from_slice(&u8::try_from(arg).unwrap_or(u8::MAX).to_be_bytes());
        }
        0x100..=0xffff => {
            out.push(major | 25);
            out.extend_from_slice(&u16::try_from(arg).unwrap_or(u16::MAX).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(major | 26);
            out.extend_from_slice(&u32::try_from(arg).unwrap_or(u32::MAX).to_be_bytes());
        }
        _ => {
            out.push(major | 27);
            out.extend_from_slice(&arg.to_be_bytes());
        }
    }
}

/// Write a byte string item.
pub(crate) fn bytes(value: &[u8], out: &mut Vec<u8>) {
    head(MAJOR_BYTES, value.len() as u64, out);
    out.extend_from_slice(value);
}

/// Write a text string item.
pub(crate) fn text(value: &str, out: &mut Vec<u8>) {
    head(MAJOR_TEXT, value.len() as u64, out);
    out.extend_from_slice(value.as_bytes());
}

fn item(value: &Ipld, out: &mut Vec<u8>, depth: u32) -> Result<(), CodecError> {
    if depth > MAX_DEPTH {
        return Err(CodecError::NestingTooDeep);
    }
    match value {
        Ipld::Null => out.push(NULL),
        Ipld::Bool(false) => out.push(FALSE),
        Ipld::Bool(true) => out.push(TRUE),
        Ipld::Integer(i) => integer(*i, out)?,
        Ipld::Float(f) => {
            if !f.is_finite() {
                return Err(CodecError::InvalidFloat);
            }
            out.push(FLOAT64);
            out.extend_from_slice(&f.to_bits().to_be_bytes());
        }
        Ipld::String(s) => text(s, out),
        Ipld::Bytes(b) => bytes(b, out),
        Ipld::List(items) => {
            head(MAJOR_ARRAY, items.len() as u64, out);
            for entry in items {
                item(entry, out, depth + 1)?;
            }
        }
        Ipld::Map(map) => {
            // Canonical order is by key length, then bytewise; a BTreeMap
            // is bytewise only.
            let mut entries: Vec<(&alloc::string::String, &Ipld)> = map.iter().collect();
            entries.sort_by(|(a, _), (b, _)| {
                a.len()
                    .cmp(&b.len())
                    .then_with(|| a.as_bytes().cmp(b.as_bytes()))
            });
            head(MAJOR_MAP, entries.len() as u64, out);
            for (key, entry) in entries {
                text(key, out);
                item(entry, out, depth + 1)?;
            }
        }
        Ipld::Link(cid) => {
            head(MAJOR_TAG, CID_TAG, out);
            let raw = cid.to_bytes();
            head(MAJOR_BYTES, raw.len() as u64 + 1, out);
            out.push(CID_MULTIBASE_IDENTITY);
            out.extend_from_slice(&raw);
        }
    }
    Ok(())
}

fn integer(value: i128, out: &mut Vec<u8>) -> Result<(), CodecError> {
    if value >= 0 {
        let arg = u64::try_from(value).map_err(|_| CodecError::IntegerOutOfRange)?;
        head(MAJOR_UINT, arg, out);
    } else {
        let arg = u64::try_from(-1 - value).map_err(|_| CodecError::IntegerOutOfRange)?;
        head(MAJOR_NINT, arg, out);
    }
    Ok(())
}
