use alloc::{collections::BTreeMap, string::String, vec::Vec};

use ipld_core::{cid::Cid, ipld::Ipld};

use super::{
    encode::{CID_MULTIBASE_IDENTITY, CID_TAG},
    CodecError, MAX_DEPTH,
};

/// Decode one strict DAG-CBOR value that spans the whole input.
pub fn decode(bytes: &[u8]) -> Result<Ipld, CodecError> {
    let mut reader = Reader::new(bytes);
    let value = reader.value()?;
    reader.finish()?;
    Ok(value)
}

/// A cursor over strict DAG-CBOR.
///
/// Callers that need byte ranges, such as the envelope, walk the outer
/// structure with the typed methods and take [`Reader::position`] between
/// items; [`Reader::value`] parses anything.
#[derive(Debug)]
pub struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

/// A decoded item head: major type and argument.
#[derive(Clone, Copy)]
struct Head {
    major: u8,
    arg: u64,
}

impl<'a> Reader<'a> {
    /// Start reading at the beginning of `bytes`.
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Reader { bytes, pos: 0 }
    }

    /// Offset of the next unread byte.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.pos
    }

    /// Succeeds only when every byte has been consumed.
    pub fn finish(self) -> Result<(), CodecError> {
        if self.pos == self.bytes.len() {
            Ok(())
        } else {
            Err(CodecError::TrailingBytes)
        }
    }

    /// Read an array head and return its length.
    pub fn array_len(&mut self) -> Result<usize, CodecError> {
        self.container(4)
    }

    /// Read a map head and return its entry count.
    pub fn map_len(&mut self) -> Result<usize, CodecError> {
        self.container(5)
    }

    /// Read a byte string.
    pub fn bytes(&mut self) -> Result<&'a [u8], CodecError> {
        let head = self.head()?;
        if head.major != 2 {
            return Err(CodecError::UnexpectedType);
        }
        self.take(head.arg)
    }

    /// Read a text string.
    pub fn text(&mut self) -> Result<&'a str, CodecError> {
        let head = self.head()?;
        if head.major != 3 {
            return Err(CodecError::UnexpectedType);
        }
        core::str::from_utf8(self.take(head.arg)?).map_err(|_| CodecError::InvalidUtf8)
    }

    /// Read any value.
    pub fn value(&mut self) -> Result<Ipld, CodecError> {
        self.item(0)
    }

    fn container(&mut self, major: u8) -> Result<usize, CodecError> {
        let head = self.head()?;
        if head.major != major {
            return Err(CodecError::UnexpectedType);
        }
        usize::try_from(head.arg).map_err(|_| CodecError::LengthTooLarge)
    }

    fn byte(&mut self) -> Result<u8, CodecError> {
        let byte = *self.bytes.get(self.pos).ok_or(CodecError::UnexpectedEnd)?;
        self.pos += 1;
        Ok(byte)
    }

    fn take(&mut self, len: u64) -> Result<&'a [u8], CodecError> {
        let len = usize::try_from(len).map_err(|_| CodecError::LengthTooLarge)?;
        let end = self
            .pos
            .checked_add(len)
            .ok_or(CodecError::LengthTooLarge)?;
        let slice = self
            .bytes
            .get(self.pos..end)
            .ok_or(CodecError::UnexpectedEnd)?;
        self.pos = end;
        Ok(slice)
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], CodecError> {
        let slice = self.take(N as u64)?;
        slice.try_into().map_err(|_| CodecError::UnexpectedEnd)
    }

    /// Read a head for major types 0 to 6, enforcing minimal encoding.
    /// Major type 7 has its own rules and is handled by `item`.
    fn head(&mut self) -> Result<Head, CodecError> {
        let initial = self.byte()?;
        let major = initial >> 5;
        if major == 7 {
            return Err(CodecError::UnexpectedType);
        }
        let arg = self.argument(initial & 0x1f)?;
        Ok(Head { major, arg })
    }

    fn argument(&mut self, info: u8) -> Result<u64, CodecError> {
        Ok(match info {
            0..=23 => u64::from(info),
            24 => {
                let v = u64::from(self.byte()?);
                if v < 24 {
                    return Err(CodecError::NonMinimalInteger);
                }
                v
            }
            25 => {
                let v = u64::from(u16::from_be_bytes(self.fixed()?));
                if v <= 0xff {
                    return Err(CodecError::NonMinimalInteger);
                }
                v
            }
            26 => {
                let v = u64::from(u32::from_be_bytes(self.fixed()?));
                if v <= 0xffff {
                    return Err(CodecError::NonMinimalInteger);
                }
                v
            }
            27 => {
                let v = u64::from_be_bytes(self.fixed()?);
                if v <= 0xffff_ffff {
                    return Err(CodecError::NonMinimalInteger);
                }
                v
            }
            31 => return Err(CodecError::IndefiniteLength),
            _ => return Err(CodecError::Reserved),
        })
    }

    fn item(&mut self, depth: u32) -> Result<Ipld, CodecError> {
        if depth > MAX_DEPTH {
            return Err(CodecError::NestingTooDeep);
        }
        let initial = *self.bytes.get(self.pos).ok_or(CodecError::UnexpectedEnd)?;
        if initial >> 5 == 7 {
            self.pos += 1;
            return self.simple(initial & 0x1f);
        }
        let head = self.head()?;
        Ok(match head.major {
            0 => Ipld::Integer(i128::from(head.arg)),
            1 => Ipld::Integer(-1 - i128::from(head.arg)),
            2 => Ipld::Bytes(self.take(head.arg)?.to_vec()),
            3 => {
                let text = core::str::from_utf8(self.take(head.arg)?)
                    .map_err(|_| CodecError::InvalidUtf8)?;
                Ipld::String(String::from(text))
            }
            4 => {
                let len = usize::try_from(head.arg).map_err(|_| CodecError::LengthTooLarge)?;
                let mut items = Vec::with_capacity(len.min(1024));
                for _ in 0..len {
                    items.push(self.item(depth + 1)?);
                }
                Ipld::List(items)
            }
            5 => self.map(head.arg, depth)?,
            6 => self.link(head.arg)?,
            _ => return Err(CodecError::Reserved),
        })
    }

    fn simple(&mut self, info: u8) -> Result<Ipld, CodecError> {
        match info {
            20 => Ok(Ipld::Bool(false)),
            21 => Ok(Ipld::Bool(true)),
            22 => Ok(Ipld::Null),
            27 => {
                let value = f64::from_bits(u64::from_be_bytes(self.fixed()?));
                if value.is_finite() {
                    Ok(Ipld::Float(value))
                } else {
                    Err(CodecError::InvalidFloat)
                }
            }
            // Half and single precision, `undefined`, and every other
            // simple value are outside DAG-CBOR.
            25 | 26 => Err(CodecError::InvalidFloat),
            31 => Err(CodecError::IndefiniteLength),
            _ => Err(CodecError::UnsupportedSimple),
        }
    }

    fn map(&mut self, len: u64, depth: u32) -> Result<Ipld, CodecError> {
        let len = usize::try_from(len).map_err(|_| CodecError::LengthTooLarge)?;
        let mut map = BTreeMap::new();
        let mut previous: Option<&'a str> = None;
        for _ in 0..len {
            let key = self.text().map_err(|e| match e {
                CodecError::UnexpectedType => CodecError::NonStringKey,
                other => other,
            })?;
            if let Some(prev) = previous {
                match canonical_order(prev, key) {
                    core::cmp::Ordering::Less => {}
                    core::cmp::Ordering::Equal => return Err(CodecError::DuplicateKey),
                    core::cmp::Ordering::Greater => return Err(CodecError::UnsortedKeys),
                }
            }
            previous = Some(key);
            let value = self.item(depth + 1)?;
            map.insert(String::from(key), value);
        }
        Ok(Ipld::Map(map))
    }

    fn link(&mut self, tag: u64) -> Result<Ipld, CodecError> {
        if tag != CID_TAG {
            return Err(CodecError::UnsupportedTag(tag));
        }
        let raw = self.bytes().map_err(|e| match e {
            CodecError::UnexpectedType => CodecError::InvalidCid,
            other => other,
        })?;
        let (prefix, cid) = raw.split_first().ok_or(CodecError::InvalidCid)?;
        if *prefix != CID_MULTIBASE_IDENTITY {
            return Err(CodecError::InvalidCid);
        }
        let cid = Cid::try_from(cid).map_err(|_| CodecError::InvalidCid)?;
        Ok(Ipld::Link(cid))
    }
}

/// DAG-CBOR key order: shorter first, then bytewise.
pub(crate) fn canonical_order(a: &str, b: &str) -> core::cmp::Ordering {
    a.len()
        .cmp(&b.len())
        .then_with(|| a.as_bytes().cmp(b.as_bytes()))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use alloc::{string::ToString, vec};

    use super::*;
    use crate::codec::encode;

    fn map(entries: &[(&str, Ipld)]) -> Ipld {
        Ipld::Map(
            entries
                .iter()
                .map(|(k, v)| ((*k).to_string(), v.clone()))
                .collect(),
        )
    }

    #[test]
    fn integers_use_the_shortest_form() {
        for (value, bytes) in [
            (0, vec![0x00]),
            (23, vec![0x17]),
            (24, vec![0x18, 0x18]),
            (255, vec![0x18, 0xff]),
            (256, vec![0x19, 0x01, 0x00]),
            (-1, vec![0x20]),
            (-25, vec![0x38, 0x18]),
            (
                i128::from(u64::MAX),
                vec![0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            ),
        ] {
            assert_eq!(encode(&Ipld::Integer(value)).unwrap(), bytes, "{value}");
            assert_eq!(decode(&bytes).unwrap(), Ipld::Integer(value), "{value}");
        }
        assert_eq!(decode(&[0x18, 0x17]), Err(CodecError::NonMinimalInteger));
        assert_eq!(
            decode(&[0x19, 0x00, 0xff]),
            Err(CodecError::NonMinimalInteger)
        );
        assert_eq!(
            encode(&Ipld::Integer(i128::from(u64::MAX) + 1)),
            Err(CodecError::IntegerOutOfRange)
        );
    }

    #[test]
    fn maps_sort_by_length_then_bytes() {
        let value = map(&[
            ("nonce", Ipld::Bytes(vec![1])),
            ("aud", Ipld::Null),
            ("meta", Ipld::Null),
            ("cmd", Ipld::Null),
        ]);
        let bytes = encode(&value).unwrap();
        // a4 63 "aud" f6 63 "cmd" f6 64 "meta" f6 65 "nonce" 41 01
        assert_eq!(
            bytes,
            hex::decode("a463617564f663636d64f6646d657461f6656e6f6e63654101").unwrap()
        );
        assert_eq!(decode(&bytes).unwrap(), value);
    }

    #[test]
    fn refuses_unsorted_and_duplicate_keys() {
        // {"b": 1, "a": 1} and {"a": 1, "a": 1}
        assert_eq!(
            decode(&[0xa2, 0x61, 0x62, 0x01, 0x61, 0x61, 0x01]),
            Err(CodecError::UnsortedKeys)
        );
        assert_eq!(
            decode(&[0xa2, 0x61, 0x61, 0x01, 0x61, 0x61, 0x01]),
            Err(CodecError::DuplicateKey)
        );
        // {1: 1}
        assert_eq!(decode(&[0xa1, 0x01, 0x01]), Err(CodecError::NonStringKey));
    }

    #[test]
    fn refuses_indefinite_lengths_trailing_bytes_and_odd_floats() {
        assert_eq!(decode(&[0x9f, 0xff]), Err(CodecError::IndefiniteLength));
        assert_eq!(decode(&[0x01, 0x02]), Err(CodecError::TrailingBytes));
        assert_eq!(decode(&[0xf9, 0x3c, 0x00]), Err(CodecError::InvalidFloat));
        assert_eq!(
            decode(&[0xfb, 0x7f, 0xf0, 0, 0, 0, 0, 0, 0]),
            Err(CodecError::InvalidFloat)
        );
        assert_eq!(
            encode(&Ipld::Float(f64::NAN)),
            Err(CodecError::InvalidFloat)
        );
        assert_eq!(decode(&[0xf7]), Err(CodecError::UnsupportedSimple));
        assert_eq!(
            decode(&[0xd9, 0x01, 0x00, 0x01]),
            Err(CodecError::UnsupportedTag(256))
        );
    }

    #[test]
    fn links_round_trip_with_identity_prefix() {
        let cid = crate::cid::of_dag_cbor(b"hello");
        let bytes = encode(&Ipld::Link(cid)).unwrap();
        assert_eq!(&bytes[..4], &[0xd8, 0x2a, 0x58, 0x25]);
        assert_eq!(bytes[4], 0x00);
        assert_eq!(decode(&bytes).unwrap(), Ipld::Link(cid));
        // A link whose bytes lack the identity prefix is refused.
        let mut wrong = bytes.clone();
        wrong[4] = 0x01;
        assert_eq!(decode(&wrong), Err(CodecError::InvalidCid));
    }

    #[test]
    fn nesting_is_bounded() {
        let mut deep = Ipld::Null;
        for _ in 0..(MAX_DEPTH + 2) {
            deep = Ipld::List(vec![deep]);
        }
        assert_eq!(encode(&deep), Err(CodecError::NestingTooDeep));
        let bytes = vec![0x81; (MAX_DEPTH + 2) as usize];
        assert_eq!(decode(&bytes), Err(CodecError::NestingTooDeep));
    }

    #[test]
    fn agrees_with_serde_ipld_dagcbor_on_sorted_values() {
        let value = map(&[
            (
                "a",
                Ipld::List(vec![Ipld::Integer(1), Ipld::Float(1.5), Ipld::Bool(true)]),
            ),
            ("bb", Ipld::String("x".into())),
            ("c", Ipld::Bytes(vec![0, 1, 2])),
            ("dd", Ipld::Null),
        ]);
        let ours = encode(&value).unwrap();
        let theirs = serde_ipld_dagcbor::to_vec(&value).unwrap();
        assert_eq!(ours, theirs);
        let back: Ipld = serde_ipld_dagcbor::from_slice(&ours).unwrap();
        assert_eq!(back, value);
    }
}
