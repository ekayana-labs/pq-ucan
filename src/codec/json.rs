//! Strict DAG-JSON.
//!
//! The encoder emits canonical form: no whitespace, keys sorted bytewise,
//! bytes as `{"/":{"bytes":"..."}}` in unpadded base64, links as
//! `{"/":"<cid>"}`.
//! The decoder accepts exactly what the encoder emits. Floats are refused
//! in both directions because their text form differs between
//! implementations, and a map may not use the reserved `/` key.

use alloc::{collections::BTreeMap, string::String, string::ToString, vec::Vec};

use ipld_core::{cid::Cid, ipld::Ipld};

use super::{CodecError, MAX_DEPTH};

/// Encode a value as canonical DAG-JSON.
pub fn encode(value: &Ipld) -> Result<String, CodecError> {
    let mut out = String::new();
    item(value, &mut out, 0)?;
    Ok(out)
}

/// Decode canonical DAG-JSON that spans the whole input.
pub fn decode(bytes: &[u8]) -> Result<Ipld, CodecError> {
    let text = core::str::from_utf8(bytes).map_err(|_| CodecError::InvalidUtf8)?;
    let mut parser = Parser { text, pos: 0 };
    let value = parser.value(0)?;
    if parser.pos != text.len() {
        return Err(CodecError::TrailingBytes);
    }
    if encode(&value)?.as_bytes() != bytes {
        return Err(CodecError::NotCanonical);
    }
    Ok(value)
}

fn item(value: &Ipld, out: &mut String, depth: u32) -> Result<(), CodecError> {
    if depth > MAX_DEPTH {
        return Err(CodecError::NestingTooDeep);
    }
    match value {
        Ipld::Null => out.push_str("null"),
        Ipld::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Ipld::Integer(i) => {
            check_range(*i)?;
            out.push_str(&i.to_string());
        }
        Ipld::Float(_) => return Err(CodecError::FloatInText),
        Ipld::String(s) => string(s, out),
        Ipld::Bytes(b) => {
            out.push_str(r#"{"/":{"bytes":""#);
            base64_encode(b, out);
            out.push_str(r#""}}"#);
        }
        Ipld::List(items) => {
            out.push('[');
            for (i, entry) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                item(entry, out, depth + 1)?;
            }
            out.push(']');
        }
        Ipld::Map(map) => {
            if map.contains_key("/") {
                return Err(CodecError::ReservedKey);
            }
            out.push('{');
            for (i, (key, entry)) in map.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                string(key, out);
                out.push(':');
                item(entry, out, depth + 1)?;
            }
            out.push('}');
        }
        Ipld::Link(cid) => {
            out.push_str(r#"{"/":""#);
            out.push_str(&cid.to_string());
            out.push_str(r#""}"#);
        }
    }
    Ok(())
}

// The DAG-CBOR integer range, so a value survives the trip to the envelope.
fn check_range(value: i128) -> Result<(), CodecError> {
    let magnitude = if value >= 0 { value } else { -1 - value };
    u64::try_from(magnitude)
        .map(|_| ())
        .map_err(|_| CodecError::IntegerOutOfRange)
}

fn string(value: &str, out: &mut String) {
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if u32::from(c) < 0x20 => {
                let code = u32::from(c);
                out.push_str("\\u00");
                out.push(hex_digit(code >> 4));
                out.push(hex_digit(code & 0xf));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn hex_digit(value: u32) -> char {
    char::from_digit(value, 16).unwrap_or('0')
}

struct Parser<'a> {
    text: &'a str,
    pos: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.text.as_bytes().get(self.pos).copied()
    }

    fn next(&mut self) -> Result<u8, CodecError> {
        let byte = self.peek().ok_or(CodecError::UnexpectedEnd)?;
        self.pos += 1;
        Ok(byte)
    }

    fn expect(&mut self, byte: u8) -> Result<(), CodecError> {
        if self.next()? == byte {
            Ok(())
        } else {
            Err(CodecError::InvalidJson)
        }
    }

    fn literal(&mut self, word: &str) -> Result<(), CodecError> {
        let end = self.pos + word.len();
        if self.text.get(self.pos..end) == Some(word) {
            self.pos = end;
            Ok(())
        } else {
            Err(CodecError::InvalidJson)
        }
    }

    fn value(&mut self, depth: u32) -> Result<Ipld, CodecError> {
        if depth > MAX_DEPTH {
            return Err(CodecError::NestingTooDeep);
        }
        match self.peek().ok_or(CodecError::UnexpectedEnd)? {
            b'n' => self.literal("null").map(|()| Ipld::Null),
            b't' => self.literal("true").map(|()| Ipld::Bool(true)),
            b'f' => self.literal("false").map(|()| Ipld::Bool(false)),
            b'"' => self.string().map(Ipld::String),
            b'[' => self.list(depth),
            b'{' => self.map(depth),
            b'-' | b'0'..=b'9' => self.number(),
            _ => Err(CodecError::InvalidJson),
        }
    }

    fn list(&mut self, depth: u32) -> Result<Ipld, CodecError> {
        self.expect(b'[')?;
        let mut items = Vec::new();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Ipld::List(items));
        }
        loop {
            items.push(self.value(depth + 1)?);
            match self.next()? {
                b',' => {}
                b']' => return Ok(Ipld::List(items)),
                _ => return Err(CodecError::InvalidJson),
            }
        }
    }

    fn map(&mut self, depth: u32) -> Result<Ipld, CodecError> {
        self.expect(b'{')?;
        let mut map = BTreeMap::new();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Ipld::Map(map));
        }
        loop {
            let key = self.string()?;
            self.expect(b':')?;
            let value = self.value(depth + 1)?;
            if map.insert(key, value).is_some() {
                return Err(CodecError::DuplicateKey);
            }
            match self.next()? {
                b',' => {}
                b'}' => return reserved(map),
                _ => return Err(CodecError::InvalidJson),
            }
        }
    }

    fn number(&mut self) -> Result<Ipld, CodecError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        let digits = self.pos;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
        if self.pos == digits {
            return Err(CodecError::InvalidJson);
        }
        if matches!(self.peek(), Some(b'.' | b'e' | b'E')) {
            return Err(CodecError::FloatInText);
        }
        let text = self
            .text
            .get(start..self.pos)
            .ok_or(CodecError::InvalidJson)?;
        let value: i128 = text.parse().map_err(|_| CodecError::IntegerOutOfRange)?;
        check_range(value)?;
        Ok(Ipld::Integer(value))
    }

    fn string(&mut self) -> Result<String, CodecError> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let rest = self.text.get(self.pos..).ok_or(CodecError::UnexpectedEnd)?;
            let run = rest
                .find(|c: char| c == '"' || c == '\\' || u32::from(c) < 0x20)
                .ok_or(CodecError::UnexpectedEnd)?;
            out.push_str(rest.get(..run).ok_or(CodecError::UnexpectedEnd)?);
            self.pos += run;
            match self.next()? {
                b'"' => return Ok(out),
                b'\\' => out.push(self.escape()?),
                _ => return Err(CodecError::InvalidJson),
            }
        }
    }

    fn escape(&mut self) -> Result<char, CodecError> {
        Ok(match self.next()? {
            b'"' => '"',
            b'\\' => '\\',
            b'/' => '/',
            b'b' => '\u{8}',
            b'f' => '\u{c}',
            b'n' => '\n',
            b'r' => '\r',
            b't' => '\t',
            b'u' => {
                let high = self.hex4()?;
                let code = if (0xd800..0xdc00).contains(&high) {
                    self.literal("\\u")?;
                    let low = self.hex4()?;
                    if !(0xdc00..0xe000).contains(&low) {
                        return Err(CodecError::InvalidJson);
                    }
                    0x1_0000 + ((high - 0xd800) << 10) + (low - 0xdc00)
                } else {
                    high
                };
                char::from_u32(code).ok_or(CodecError::InvalidJson)?
            }
            _ => return Err(CodecError::InvalidJson),
        })
    }

    fn hex4(&mut self) -> Result<u32, CodecError> {
        let digits = self
            .text
            .get(self.pos..self.pos + 4)
            .ok_or(CodecError::UnexpectedEnd)?;
        self.pos += 4;
        u32::from_str_radix(digits, 16).map_err(|_| CodecError::InvalidJson)
    }
}

// A map keyed by `/` is a link or bytes, and nothing else.
fn reserved(mut map: BTreeMap<String, Ipld>) -> Result<Ipld, CodecError> {
    let Some(inner) = map.remove("/") else {
        return Ok(Ipld::Map(map));
    };
    if !map.is_empty() {
        return Err(CodecError::ReservedKey);
    }
    match inner {
        Ipld::String(text) => Cid::try_from(text.as_str())
            .map(Ipld::Link)
            .map_err(|_| CodecError::InvalidCid),
        Ipld::Map(mut form) => match (form.remove("bytes"), form.is_empty()) {
            (Some(Ipld::String(text)), true) => base64_decode(&text).map(Ipld::Bytes),
            _ => Err(CodecError::ReservedKey),
        },
        _ => Err(CodecError::ReservedKey),
    }
}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(bytes: &[u8], out: &mut String) {
    for chunk in bytes.chunks(3) {
        let mut group = [0u8; 3];
        for (slot, byte) in group.iter_mut().zip(chunk) {
            *slot = *byte;
        }
        let [a, b, c] = group;
        let bits = (u32::from(a) << 16) | (u32::from(b) << 8) | u32::from(c);
        for i in 0..=chunk.len() {
            let index = usize::try_from((bits >> (18 - 6 * i)) & 0x3f).unwrap_or(0);
            let symbol = ALPHABET.get(index).copied().unwrap_or(b'A');
            out.push(char::from(symbol));
        }
    }
}

fn base64_decode(text: &str) -> Result<Vec<u8>, CodecError> {
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let mut bits = 0u32;
    let mut count = 0u32;
    for symbol in text.bytes() {
        let value = ALPHABET
            .iter()
            .position(|a| *a == symbol)
            .ok_or(CodecError::InvalidBase64)?;
        bits = (bits << 6) | u32::try_from(value).map_err(|_| CodecError::InvalidBase64)?;
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push(u8::try_from((bits >> count) & 0xff).map_err(|_| CodecError::InvalidBase64)?);
        }
    }
    if count >= 6 {
        return Err(CodecError::InvalidBase64);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use alloc::{collections::BTreeMap, format, string::String, vec};

    use ipld_core::ipld::Ipld;

    use super::{decode, encode};
    use crate::codec::CodecError;

    fn map(entries: &[(&str, Ipld)]) -> Ipld {
        Ipld::Map(
            entries
                .iter()
                .map(|(k, v)| (String::from(*k), v.clone()))
                .collect::<BTreeMap<_, _>>(),
        )
    }

    fn round_trip(value: &Ipld, text: &str) {
        assert_eq!(encode(value).unwrap(), text);
        assert_eq!(&decode(text.as_bytes()).unwrap(), value);
    }

    #[test]
    fn scalars_and_containers() {
        round_trip(&Ipld::Null, "null");
        round_trip(&Ipld::Bool(true), "true");
        round_trip(
            &Ipld::Integer(-18_446_744_073_709_551_616),
            "-18446744073709551616",
        );
        round_trip(
            &Ipld::Integer(18_446_744_073_709_551_615),
            "18446744073709551615",
        );
        round_trip(&Ipld::List(vec![]), "[]");
        round_trip(&map(&[]), "{}");
        round_trip(
            &Ipld::List(vec![Ipld::Integer(1), Ipld::String("a".into())]),
            r#"[1,"a"]"#,
        );
    }

    #[test]
    fn keys_sort_bytewise_not_by_length() {
        let value = map(&[
            ("bb", Ipld::Integer(2)),
            ("c", Ipld::Integer(3)),
            ("a", Ipld::Null),
        ]);
        round_trip(&value, r#"{"a":null,"bb":2,"c":3}"#);
    }

    #[test]
    fn strings_escape_only_what_json_requires() {
        let text = "quote\" slash\\ tab\t nl\n bell\u{7} accent\u{e9}";
        let json = format!(
            "\"quote\\\" slash\\\\ tab\\t nl\\n bell\\u{}7 accent\u{e9}\"",
            "000"
        );
        round_trip(&Ipld::String(text.into()), &json);

        let escaped = |codes: &[&str]| {
            let mut out = String::from("\"");
            for code in codes {
                out.push('\\');
                out.push('u');
                out.push_str(code);
            }
            out.push('"');
            out
        };
        assert_eq!(
            decode(escaped(&["00e9"]).as_bytes()),
            Err(CodecError::NotCanonical)
        );
        assert_eq!(
            decode(escaped(&["d83d", "de00"]).as_bytes()),
            Err(CodecError::NotCanonical)
        );
        assert_eq!(decode(br#""\/""#), Err(CodecError::NotCanonical));
        let emoji = format!("\"{}\"", '\u{1f600}');
        assert_eq!(
            decode(emoji.as_bytes()).unwrap(),
            Ipld::String("\u{1f600}".into())
        );
    }

    #[test]
    fn bytes_and_links_use_the_slash_forms() {
        round_trip(&Ipld::Bytes(vec![]), r#"{"/":{"bytes":""}}"#);
        round_trip(&Ipld::Bytes(vec![0xfb, 0xff]), r#"{"/":{"bytes":"+/8"}}"#);
        round_trip(
            &Ipld::Bytes(b"hello".to_vec()),
            r#"{"/":{"bytes":"aGVsbG8"}}"#,
        );
        let cid = crate::cid::of_dag_cbor(b"x");
        round_trip(&Ipld::Link(cid), &format!(r#"{{"/":"{cid}"}}"#));
    }

    #[test]
    fn refuses_what_it_cannot_sign() {
        assert_eq!(encode(&Ipld::Float(1.5)), Err(CodecError::FloatInText));
        assert_eq!(decode(b"1.5"), Err(CodecError::FloatInText));
        assert_eq!(decode(b"1e3"), Err(CodecError::FloatInText));
        assert_eq!(
            encode(&map(&[("/", Ipld::Null)])),
            Err(CodecError::ReservedKey)
        );
        assert_eq!(decode(br#"{"/":1}"#), Err(CodecError::ReservedKey));
        assert_eq!(decode(br#"{"/":"x","a":1}"#), Err(CodecError::ReservedKey));
        assert_eq!(decode(br#"{"/":"not a cid"}"#), Err(CodecError::InvalidCid));
        assert_eq!(
            decode(br#"{"/":{"bytes":"!"}}"#),
            Err(CodecError::InvalidBase64)
        );
        assert_eq!(
            encode(&Ipld::Integer(18_446_744_073_709_551_616)),
            Err(CodecError::IntegerOutOfRange)
        );
        assert_eq!(
            decode(b"18446744073709551616"),
            Err(CodecError::IntegerOutOfRange)
        );
    }

    #[test]
    fn refuses_non_canonical_text() {
        for text in [
            r#"{"b":1,"a":2}"#,
            r#"{ "a":1}"#,
            "[1, 2]",
            "-0",
            r#"{"/":{"bytes":"aGVsbG8="}}"#,
            r#"{"/":{"bytes":"aGVsbG9"}}"#,
        ] {
            assert!(decode(text.as_bytes()).is_err(), "{text}");
        }
        assert_eq!(decode(b"01"), Err(CodecError::NotCanonical));
        assert_eq!(decode(br#"{"a":1,"a":1}"#), Err(CodecError::DuplicateKey));
        assert_eq!(decode(b"[1]x"), Err(CodecError::TrailingBytes));
        assert_eq!(decode(b"\"a"), Err(CodecError::UnexpectedEnd));
    }

    #[test]
    fn nesting_is_bounded() {
        let mut deep = Ipld::Null;
        for _ in 0..200 {
            deep = Ipld::List(vec![deep]);
        }
        assert_eq!(encode(&deep), Err(CodecError::NestingTooDeep));
        let text = "[".repeat(200) + &"]".repeat(200);
        assert_eq!(decode(text.as_bytes()), Err(CodecError::NestingTooDeep));
    }
}
