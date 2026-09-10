//! Commands: the `/`-separated paths that name what may be done.

use alloc::boxed::Box;
use core::fmt;

use thiserror::Error;

/// A validated command path such as `/crud/read`.
///
/// Shorter commands cover longer ones on segment boundaries: `/crud`
/// covers `/crud/read` and not `/crudite`. The root `/` covers everything.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Command(Box<str>);

impl Command {
    /// Parse and validate. Commands are lowercase, begin with `/`, have no
    /// empty segments and no trailing `/` except the root itself.
    pub fn parse(text: &str) -> Result<Self, CommandError> {
        if text.is_empty() {
            return Err(CommandError::Empty);
        }
        if !text.starts_with('/') {
            return Err(CommandError::MissingLeadingSlash);
        }
        if text.len() > 1 {
            if text.ends_with('/') {
                return Err(CommandError::TrailingSlash);
            }
            if text.contains("//") {
                return Err(CommandError::EmptySegment);
            }
        }
        if text.chars().any(char::is_uppercase) {
            return Err(CommandError::Uppercase);
        }
        Ok(Command(text.into()))
    }

    /// The root command `/`, which covers every other command.
    #[must_use]
    pub fn root() -> Self {
        Command("/".into())
    }

    /// Whether this is the root command.
    #[must_use]
    pub fn is_root(&self) -> bool {
        &*self.0 == "/"
    }

    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The segments between the slashes; empty for the root.
    pub fn segments(&self) -> impl Iterator<Item = &str> {
        self.0.split('/').filter(|s| !s.is_empty())
    }

    /// Whether authority over `self` includes authority over `other`.
    #[must_use]
    pub fn covers(&self, other: &Command) -> bool {
        if self.is_root() {
            return true;
        }
        match other.0.strip_prefix(&*self.0) {
            Some(rest) => rest.is_empty() || rest.starts_with('/'),
            None => false,
        }
    }
}

impl fmt::Display for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Command({})", self.0)
    }
}

impl core::str::FromStr for Command {
    type Err = CommandError;

    fn from_str(text: &str) -> Result<Self, CommandError> {
        Self::parse(text)
    }
}

/// Why a command string was refused.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CommandError {
    /// The empty string.
    #[error("command is empty")]
    Empty,

    /// Does not begin with `/`.
    #[error("command must begin with `/`")]
    MissingLeadingSlash,

    /// Ends with `/` and is not the root.
    #[error("command must not end with `/`")]
    TrailingSlash,

    /// Contains `//`.
    #[error("command has an empty segment")]
    EmptySegment,

    /// Contains an uppercase character.
    #[error("command must be lowercase")]
    Uppercase,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn accepts_the_specification_examples() {
        for text in [
            "/",
            "/crud",
            "/crud/create",
            "/stack/pop",
            "/foo/bar/baz/qux/quux",
            "/ほげ/ふが",
        ] {
            assert_eq!(Command::parse(text).unwrap().as_str(), text);
        }
    }

    #[test]
    fn refuses_malformed_paths() {
        assert_eq!(Command::parse(""), Err(CommandError::Empty));
        assert_eq!(
            Command::parse("crud"),
            Err(CommandError::MissingLeadingSlash)
        );
        assert_eq!(Command::parse("/crud/"), Err(CommandError::TrailingSlash));
        assert_eq!(
            Command::parse("/crud//read"),
            Err(CommandError::EmptySegment)
        );
        assert_eq!(Command::parse("/Crud"), Err(CommandError::Uppercase));
    }

    #[test]
    fn coverage_is_on_segment_boundaries() {
        let root = Command::root();
        let crypto = Command::parse("/crypto").unwrap();
        let sign = Command::parse("/crypto/sign").unwrap();
        let coin = Command::parse("/cryptocurrency").unwrap();
        assert!(root.covers(&sign));
        assert!(crypto.covers(&sign));
        assert!(crypto.covers(&crypto));
        assert!(!crypto.covers(&coin));
        assert!(!sign.covers(&crypto));
        assert!(!sign.covers(&root));
    }
}
