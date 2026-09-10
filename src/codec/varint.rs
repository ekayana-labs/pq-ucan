use alloc::vec::Vec;

use super::CodecError;

/// Append `value` as an unsigned LEB128 varint.
#[allow(clippy::cast_possible_truncation)] // masked to seven bits first
pub fn put_uvarint(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// Read a minimal unsigned LEB128 varint, returning the value and its
/// length. Ten bytes at most; a continuation into a zero group is refused
/// so that every value has exactly one encoding.
pub fn read_uvarint(bytes: &[u8]) -> Result<(u64, usize), CodecError> {
    let mut value = 0u64;
    for (i, &byte) in bytes.iter().enumerate().take(10) {
        if i == 9 && byte > 1 {
            return Err(CodecError::InvalidVarint);
        }
        let shift = u32::try_from(7 * i).map_err(|_| CodecError::InvalidVarint)?;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            if i > 0 && byte == 0 {
                return Err(CodecError::InvalidVarint);
            }
            return Ok((value, i + 1));
        }
    }
    Err(if bytes.len() < 10 {
        CodecError::UnexpectedEnd
    } else {
        CodecError::InvalidVarint
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn round_trips_the_multicodec_range() {
        for value in [0, 1, 0x7f, 0x80, 0xed, 0xec, 0x1200, 0x1212, u64::MAX] {
            let mut out = Vec::new();
            put_uvarint(value, &mut out);
            assert_eq!(read_uvarint(&out).unwrap(), (value, out.len()));
        }
    }

    #[test]
    fn known_encodings() {
        let mut out = Vec::new();
        put_uvarint(0xed, &mut out);
        assert_eq!(out, [0xed, 0x01]);
        out.clear();
        put_uvarint(0x1212, &mut out);
        assert_eq!(out, [0x92, 0x24]);
    }

    #[test]
    fn refuses_non_minimal_and_overlong() {
        assert_eq!(read_uvarint(&[0x80, 0x00]), Err(CodecError::InvalidVarint));
        assert_eq!(read_uvarint(&[0x80]), Err(CodecError::UnexpectedEnd));
        assert_eq!(read_uvarint(&[0xff; 10]), Err(CodecError::InvalidVarint));
    }
}
