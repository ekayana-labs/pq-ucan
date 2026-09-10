use alloc::{boxed::Box, vec::Vec};
use core::fmt;

/// A `like` pattern: `*` matches any run of characters, `\*` is a literal
/// star, everything else matches itself.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Pattern {
    text: Box<str>,
    tokens: Vec<Token>,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Token {
    Literal(char),
    Any,
}

impl Pattern {
    /// Compile a pattern. Every string is a valid pattern.
    #[must_use]
    pub fn parse(text: &str) -> Self {
        let mut tokens = Vec::with_capacity(text.len());
        let mut chars = text.chars().peekable();
        while let Some(c) = chars.next() {
            match c {
                '\\' if chars.peek() == Some(&'*') => {
                    chars.next();
                    tokens.push(Token::Literal('*'));
                }
                '*' => {
                    if tokens.last() != Some(&Token::Any) {
                        tokens.push(Token::Any);
                    }
                }
                other => tokens.push(Token::Literal(other)),
            }
        }
        Pattern {
            text: text.into(),
            tokens,
        }
    }

    /// The pattern as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Whether the whole of `input` matches.
    #[must_use]
    pub fn matches(&self, input: &str) -> bool {
        let input: Vec<char> = input.chars().collect();
        let (mut s, mut t) = (0usize, 0usize);
        let mut backtrack: Option<(usize, usize)> = None;
        while s < input.len() {
            match self.tokens.get(t) {
                Some(Token::Any) => {
                    backtrack = Some((t, s));
                    t += 1;
                }
                Some(Token::Literal(c)) if input.get(s) == Some(c) => {
                    s += 1;
                    t += 1;
                }
                _ => match backtrack {
                    Some((star, matched)) => {
                        t = star + 1;
                        s = matched + 1;
                        backtrack = Some((star, matched + 1));
                    }
                    None => return false,
                },
            }
        }
        self.tokens
            .get(t..)
            .is_some_and(|rest| rest.iter().all(|tok| *tok == Token::Any))
    }
}

impl fmt::Display for Pattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

impl fmt::Debug for Pattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Pattern({:?})", &*self.text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn specification_vectors() {
        let pattern = Pattern::parse("Alice\\*, Bob*, Carol.");
        for ok in [
            "Alice*, Bob, Carol.",
            "Alice*, Bob, Dan, Erin, Carol.",
            "Alice*, Bob  , Carol.",
            "Alice*, Bob*, Carol.",
        ] {
            assert!(pattern.matches(ok), "{ok}");
        }
        for bad in [
            "Alice*, Bob, Carol",
            "Alice*, Bob*, Carol!",
            "Alice, Bob, Carol.",
            "Alice Cooper, Bob, Carol.",
            " Alice*, Bob, Carol. ",
        ] {
            assert!(!pattern.matches(bad), "{bad}");
        }
    }

    #[test]
    fn stars_at_the_edges_and_in_the_middle() {
        assert!(Pattern::parse("*@example.com").matches("bob@example.com"));
        assert!(!Pattern::parse("*@example.com").matches("bob@example.org"));
        assert!(Pattern::parse("a*b*c").matches("abc"));
        assert!(Pattern::parse("a*b*c").matches("a--b--c"));
        assert!(!Pattern::parse("a*b*c").matches("a--c"));
        assert!(Pattern::parse("*").matches(""));
        assert!(Pattern::parse("").matches(""));
        assert!(!Pattern::parse("").matches("x"));
        assert!(Pattern::parse("\\\\*").matches("\\*"));
    }
}
