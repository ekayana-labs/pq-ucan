use alloc::{borrow::Cow, boxed::Box, string::String, vec::Vec};
use core::fmt;

use ipld_core::ipld::Ipld;
use thiserror::Error;

/// A path into an invocation's `args`, in the jq dialect the specification defines.
///
/// Grammar and resolution rules are in `docs/validation.md`. The source
/// text is kept so that a policy re-encodes exactly as it was written.
#[derive(Clone)]
pub struct Selector {
    text: Box<str>,
    segments: Vec<Segment>,
}

#[derive(Clone, Debug)]
struct Segment {
    kind: Kind,
    optional: bool,
}

#[derive(Clone, Debug)]
enum Kind {
    Key(String),
    Values,
    Index(i64),
    Slice(Option<i64>, Option<i64>),
}

impl Selector {
    /// The identity selector `.`.
    #[must_use]
    pub fn identity() -> Self {
        Selector {
            text: ".".into(),
            segments: Vec::new(),
        }
    }

    /// Parse a selector.
    pub fn parse(text: &str) -> Result<Self, SelectorError> {
        let chars: Vec<char> = text.chars().collect();
        if chars.first() != Some(&'.') {
            return Err(if chars.is_empty() {
                SelectorError::Empty
            } else {
                SelectorError::MissingLeadingDot
            });
        }
        let mut segments = Vec::new();
        let mut dot_pending = true;
        let mut i = 1;
        while let Some(&c) = chars.get(i) {
            match c {
                '.' => {
                    if dot_pending {
                        return Err(SelectorError::DoubleDot);
                    }
                    dot_pending = true;
                    i += 1;
                }
                '[' => {
                    let (kind, next) = bracket(&chars, i + 1)?;
                    segments.push(Segment {
                        kind,
                        optional: false,
                    });
                    dot_pending = false;
                    i = next;
                }
                '?' => {
                    match segments.last_mut() {
                        Some(last) if !dot_pending => last.optional = true,
                        _ => return Err(SelectorError::DanglingOptional),
                    }
                    i += 1;
                }
                c if is_ident_start(c) => {
                    if !dot_pending {
                        return Err(SelectorError::Unexpected(i));
                    }
                    let mut name = String::new();
                    while let Some(&c) = chars.get(i) {
                        if !is_ident(c) {
                            break;
                        }
                        name.push(c);
                        i += 1;
                    }
                    segments.push(Segment {
                        kind: Kind::Key(name),
                        optional: false,
                    });
                    dot_pending = false;
                }
                _ => return Err(SelectorError::Unexpected(i)),
            }
        }
        if dot_pending && !segments.is_empty() {
            return Err(SelectorError::TrailingDot);
        }
        Ok(Selector {
            text: text.into(),
            segments,
        })
    }

    /// The selector as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Resolve against `root`. `None` is failure; an optional segment that
    /// fails yields `null`.
    #[must_use]
    pub fn resolve<'a>(&self, root: &'a Ipld) -> Option<Cow<'a, Ipld>> {
        let mut current: Cow<'a, Ipld> = Cow::Borrowed(root);
        for segment in &self.segments {
            let next = match current {
                Cow::Borrowed(value) => step(value, &segment.kind),
                Cow::Owned(value) => {
                    step(&value, &segment.kind).map(|v| Cow::Owned(v.into_owned()))
                }
            };
            match next {
                Some(value) => current = value,
                None if segment.optional => return Some(Cow::Owned(Ipld::Null)),
                None => return None,
            }
        }
        Some(current)
    }
}

fn is_ident_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_'
}

fn is_ident(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Parse the inside of `[...]` starting at `start`; returns the segment and
/// the index just past `]`.
fn bracket(chars: &[char], start: usize) -> Result<(Kind, usize), SelectorError> {
    match chars.get(start) {
        Some(']') => Ok((Kind::Values, start + 1)),
        Some('"') => {
            let (key, next) = quoted(chars, start + 1)?;
            match chars.get(next) {
                Some(']') => Ok((Kind::Key(key), next + 1)),
                _ => Err(SelectorError::Unexpected(next)),
            }
        }
        Some(c) if *c == '-' || *c == ':' || c.is_ascii_digit() => {
            let (first, mut i) = integer(chars, start)?;
            let kind = if chars.get(i) == Some(&':') {
                let (second, next) = integer(chars, i + 1)?;
                i = next;
                Kind::Slice(first, second)
            } else {
                Kind::Index(first.ok_or(SelectorError::BadIndex)?)
            };
            match chars.get(i) {
                Some(']') => Ok((kind, i + 1)),
                _ => Err(SelectorError::Unexpected(i)),
            }
        }
        _ => Err(SelectorError::Unexpected(start)),
    }
}

fn integer(chars: &[char], start: usize) -> Result<(Option<i64>, usize), SelectorError> {
    let mut text = String::new();
    let mut i = start;
    if chars.get(i) == Some(&'-') {
        text.push('-');
        i += 1;
    }
    while let Some(c) = chars.get(i).filter(|c| c.is_ascii_digit()) {
        text.push(*c);
        i += 1;
    }
    if text.is_empty() {
        return Ok((None, i));
    }
    text.parse()
        .map(|n| (Some(n), i))
        .map_err(|_| SelectorError::BadIndex)
}

fn quoted(chars: &[char], start: usize) -> Result<(String, usize), SelectorError> {
    let mut out = String::new();
    let mut i = start;
    loop {
        match chars.get(i) {
            None => return Err(SelectorError::UnterminatedString),
            Some('"') => return Ok((out, i + 1)),
            Some('\\') => {
                i += 1;
                let escaped = match chars.get(i) {
                    Some('"') => '"',
                    Some('\\') => '\\',
                    Some('/') => '/',
                    Some('b') => '\u{8}',
                    Some('f') => '\u{c}',
                    Some('n') => '\n',
                    Some('r') => '\r',
                    Some('t') => '\t',
                    Some('u') => {
                        let hex: String = chars
                            .get(i + 1..i + 5)
                            .ok_or(SelectorError::BadEscape)?
                            .iter()
                            .collect();
                        let code =
                            u32::from_str_radix(&hex, 16).map_err(|_| SelectorError::BadEscape)?;
                        i += 4;
                        char::from_u32(code).ok_or(SelectorError::BadEscape)?
                    }
                    _ => return Err(SelectorError::BadEscape),
                };
                out.push(escaped);
                i += 1;
            }
            Some(c) => {
                out.push(*c);
                i += 1;
            }
        }
    }
}

fn step<'a>(value: &'a Ipld, kind: &Kind) -> Option<Cow<'a, Ipld>> {
    match (kind, value) {
        (Kind::Key(key), Ipld::Map(map)) => {
            Some(map.get(key).map_or(Cow::Owned(Ipld::Null), Cow::Borrowed))
        }
        (Kind::Values, Ipld::List(_)) => Some(Cow::Borrowed(value)),
        (Kind::Values, Ipld::Map(map)) => {
            Some(Cow::Owned(Ipld::List(map.values().cloned().collect())))
        }
        (Kind::Index(i), Ipld::List(list)) => list.get(index(list.len(), *i)?).map(Cow::Borrowed),
        (Kind::Index(i), Ipld::Bytes(bytes)) => bytes
            .get(index(bytes.len(), *i)?)
            .map(|b| Cow::Owned(Ipld::Integer(i128::from(*b)))),
        (Kind::Slice(from, to), Ipld::List(list)) => {
            let (s, e) = bounds(list.len(), *from, *to);
            list.get(s..e)
                .map(|items| Cow::Owned(Ipld::List(items.to_vec())))
        }
        (Kind::Slice(from, to), Ipld::Bytes(bytes)) => {
            let (s, e) = bounds(bytes.len(), *from, *to);
            bytes.get(s..e).map(|b| Cow::Owned(Ipld::Bytes(b.to_vec())))
        }
        _ => None,
    }
}

fn index(len: usize, i: i64) -> Option<usize> {
    if i < 0 {
        len.checked_sub(usize::try_from(i.unsigned_abs()).ok()?)
    } else {
        usize::try_from(i).ok().filter(|n| *n < len)
    }
}

fn bounds(len: usize, from: Option<i64>, to: Option<i64>) -> (usize, usize) {
    let clamp = |i: i64| {
        if i < 0 {
            len.saturating_sub(usize::try_from(i.unsigned_abs()).unwrap_or(usize::MAX))
        } else {
            usize::try_from(i).unwrap_or(usize::MAX).min(len)
        }
    };
    let start = from.map_or(0, clamp);
    let end = to.map_or(len, clamp).max(start);
    (start, end)
}

impl PartialEq for Selector {
    fn eq(&self, other: &Self) -> bool {
        self.text == other.text
    }
}

impl Eq for Selector {}

impl core::hash::Hash for Selector {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.text.hash(state);
    }
}

impl fmt::Display for Selector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

impl fmt::Debug for Selector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Selector({})", self.text)
    }
}

impl core::str::FromStr for Selector {
    type Err = SelectorError;

    fn from_str(text: &str) -> Result<Self, SelectorError> {
        Self::parse(text)
    }
}

/// Why a selector string was refused.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SelectorError {
    /// The empty string.
    #[error("selector is empty")]
    Empty,

    /// Does not begin with `.`.
    #[error("selector must begin with `.`")]
    MissingLeadingDot,

    /// Contains `..`.
    #[error("selector contains `..`")]
    DoubleDot,

    /// Ends with a dot that selects nothing.
    #[error("selector ends with `.`")]
    TrailingDot,

    /// A `?` with nothing before it to make optional.
    #[error("`?` must follow a segment")]
    DanglingOptional,

    /// A character that cannot appear at this position.
    #[error("unexpected character at offset {0}")]
    Unexpected(usize),

    /// A `[`"…"`]` segment without its closing quote.
    #[error("unterminated string")]
    UnterminatedString,

    /// An escape sequence that is not JSON.
    #[error("bad escape sequence")]
    BadEscape,

    /// An index that is not an integer.
    #[error("bad index")]
    BadIndex,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use alloc::{string::ToString, vec};

    use super::*;

    fn args() -> Ipld {
        let text = |s: &str| Ipld::String(s.to_string());
        Ipld::Map(
            [
                ("from", text("alice@example.com")),
                (
                    "to",
                    Ipld::List(vec![
                        text("bob@example.com"),
                        text("carol@not.example.com"),
                        text("dan@example.com"),
                    ]),
                ),
                ("cc", Ipld::List(vec![text("fraud@example.com")])),
                ("title", text("Meeting Confirmation")),
                ("raw", Ipld::Bytes(vec![0xd6, 0xa9, 0xc1, 0x8c, 0xf8, 0xc4])),
            ]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
        )
    }

    fn select(selector: &str) -> Option<Ipld> {
        Selector::parse(selector)
            .unwrap()
            .resolve(&args())
            .map(Cow::into_owned)
    }

    #[test]
    fn specification_table() {
        assert_eq!(select("."), Some(args()));
        assert_eq!(
            select(".title"),
            Some(Ipld::String("Meeting Confirmation".into()))
        );
        assert_eq!(
            select(".to[1]"),
            Some(Ipld::String("carol@not.example.com".into()))
        );
        assert_eq!(
            select(".to[-1]"),
            Some(Ipld::String("dan@example.com".into()))
        );
        assert_eq!(select(".to[99]?"), Some(Ipld::Null));
        assert_eq!(select(".to[99]"), None);
        assert_eq!(select(".raw[3]"), Some(Ipld::Integer(140)));
    }

    #[test]
    fn missing_keys_are_null_but_do_not_chain() {
        assert_eq!(select(".nope"), Some(Ipld::Null));
        assert_eq!(select(".nope.deeper"), None);
        assert_eq!(select(".nope.deeper?"), Some(Ipld::Null));
        // The `?` belongs to a segment that succeeded; the next one fails.
        assert_eq!(select(".nope?.deeper"), None);
        assert_eq!(select(".to.deeper?"), Some(Ipld::Null));
        // A failure without `?` wins even when a later segment has one.
        assert_eq!(select(".to.deeper.more?"), None);
    }

    #[test]
    fn brackets_slices_and_values() {
        assert_eq!(select(".[\"from\"]"), select(".from"));
        assert_eq!(
            select(".to[1:]"),
            Some(Ipld::List(vec![
                Ipld::String("carol@not.example.com".into()),
                Ipld::String("dan@example.com".into()),
            ]))
        );
        assert_eq!(
            select(".to[:1]"),
            Some(Ipld::List(vec![Ipld::String("bob@example.com".into())]))
        );
        assert_eq!(
            select(".to[0:-2]"),
            Some(Ipld::List(vec![Ipld::String("bob@example.com".into())]))
        );
        assert_eq!(select(".to[5:9]"), Some(Ipld::List(vec![])));
        assert_eq!(select(".to[]"), select(".to"));
        assert_eq!(select(".raw[1:3]"), Some(Ipld::Bytes(vec![0xa9, 0xc1])));
        assert!(matches!(select(".[]"), Some(Ipld::List(values)) if values.len() == 5));
        assert_eq!(select(".title[0]"), None);
    }

    #[test]
    fn refuses_bad_syntax() {
        assert_eq!(Selector::parse(""), Err(SelectorError::Empty));
        assert_eq!(
            Selector::parse("foo"),
            Err(SelectorError::MissingLeadingDot)
        );
        assert_eq!(Selector::parse("..foo"), Err(SelectorError::DoubleDot));
        assert_eq!(Selector::parse(".foo."), Err(SelectorError::TrailingDot));
        assert_eq!(Selector::parse(".?"), Err(SelectorError::DanglingOptional));
        assert_eq!(
            Selector::parse(".foo[0]bar"),
            Err(SelectorError::Unexpected(7))
        );
        assert_eq!(
            Selector::parse(".[\"x"),
            Err(SelectorError::UnterminatedString)
        );
        assert_eq!(Selector::parse(".[\"\\q\"]"), Err(SelectorError::BadEscape));
        assert_eq!(Selector::parse(".[-]"), Err(SelectorError::BadIndex));
        assert!(Selector::parse(".foo???").is_ok());
        assert!(Selector::parse(".[\"a\\u0041\"]").is_ok());
    }
}
