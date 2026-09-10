//! The policy language: statements a delegation places on the `args` of
//! any invocation that uses it.
//!
//! Semantics are in `docs/validation.md`. Evaluation never fails: a
//! statement that cannot be evaluated is false.

mod glob;
mod selector;

use alloc::{borrow::Cow, boxed::Box, string::String, vec::Vec};
use core::cmp::Ordering;

use ipld_core::ipld::Ipld;
use thiserror::Error;

pub use glob::Pattern;
pub use selector::{Selector, SelectorError};

/// A list of statements, all of which must hold.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Policy(Vec<Statement>);

impl Policy {
    /// A policy from statements.
    #[must_use]
    pub fn new(statements: Vec<Statement>) -> Self {
        Policy(statements)
    }

    /// The statements.
    #[must_use]
    pub fn statements(&self) -> &[Statement] {
        &self.0
    }

    /// Whether the policy constrains nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Parse the wire form: a list of statements.
    pub fn from_ipld(value: &Ipld) -> Result<Self, PolicyError> {
        match value {
            Ipld::List(items) => items
                .iter()
                .map(Statement::from_ipld)
                .collect::<Result<_, _>>()
                .map(Policy),
            _ => Err(PolicyError::NotAList),
        }
    }

    /// The wire form.
    #[must_use]
    pub fn to_ipld(&self) -> Ipld {
        Ipld::List(self.0.iter().map(Statement::to_ipld).collect())
    }

    /// Check `args` against every statement. On failure, the index of the
    /// first statement that did not hold.
    pub fn check(&self, args: &Ipld) -> Result<(), usize> {
        match self.0.iter().position(|s| !s.holds(args)) {
            None => Ok(()),
            Some(index) => Err(index),
        }
    }
}

/// One predicate.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Statement {
    /// `["==", selector, value]`
    Equal(Selector, Ipld),
    /// `["!=", selector, value]`
    NotEqual(Selector, Ipld),
    /// `["<", selector, number]`
    Less(Selector, Number),
    /// `["<=", selector, number]`
    LessOrEqual(Selector, Number),
    /// `[">", selector, number]`
    Greater(Selector, Number),
    /// `[">=", selector, number]`
    GreaterOrEqual(Selector, Number),
    /// `["like", selector, pattern]`
    Like(Selector, Pattern),
    /// `["and", [statements]]`
    And(Vec<Statement>),
    /// `["or", [statements]]`
    Or(Vec<Statement>),
    /// `["not", statement]`
    Not(Box<Statement>),
    /// `["all", selector, statement]`
    All(Selector, Box<Statement>),
    /// `["any", selector, statement]`
    Any(Selector, Box<Statement>),
}

impl Statement {
    /// Parse the wire form of one statement.
    pub fn from_ipld(value: &Ipld) -> Result<Self, PolicyError> {
        let Ipld::List(items) = value else {
            return Err(PolicyError::StatementNotAList);
        };
        let op = match items.first() {
            Some(Ipld::String(op)) => op.as_str(),
            _ => return Err(PolicyError::MissingOperator),
        };
        let arity = |n: usize| {
            if items.len() == n {
                Ok(())
            } else {
                Err(PolicyError::Arity(String::from(op)))
            }
        };
        let selector = || match items.get(1) {
            Some(Ipld::String(text)) => Selector::parse(text).map_err(PolicyError::Selector),
            _ => Err(PolicyError::ExpectedSelector),
        };
        let number = || {
            items
                .get(2)
                .and_then(Number::from_ipld)
                .ok_or(PolicyError::ExpectedNumber)
        };
        let statement = |i: usize| {
            items
                .get(i)
                .ok_or(PolicyError::MissingOperand)
                .and_then(Statement::from_ipld)
        };
        let statements = |i: usize| match items.get(i) {
            Some(Ipld::List(list)) => list.iter().map(Statement::from_ipld).collect(),
            _ => Err(PolicyError::ExpectedStatementList),
        };
        Ok(match op {
            "==" => {
                arity(3)?;
                Statement::Equal(
                    selector()?,
                    items.get(2).cloned().ok_or(PolicyError::MissingOperand)?,
                )
            }
            "!=" => {
                arity(3)?;
                Statement::NotEqual(
                    selector()?,
                    items.get(2).cloned().ok_or(PolicyError::MissingOperand)?,
                )
            }
            "<" => {
                arity(3)?;
                Statement::Less(selector()?, number()?)
            }
            "<=" => {
                arity(3)?;
                Statement::LessOrEqual(selector()?, number()?)
            }
            ">" => {
                arity(3)?;
                Statement::Greater(selector()?, number()?)
            }
            ">=" => {
                arity(3)?;
                Statement::GreaterOrEqual(selector()?, number()?)
            }
            "like" => {
                arity(3)?;
                let pattern = match items.get(2) {
                    Some(Ipld::String(text)) => Pattern::parse(text),
                    _ => return Err(PolicyError::ExpectedString),
                };
                Statement::Like(selector()?, pattern)
            }
            "and" => {
                arity(2)?;
                Statement::And(statements(1)?)
            }
            "or" => {
                arity(2)?;
                Statement::Or(statements(1)?)
            }
            "not" => {
                arity(2)?;
                Statement::Not(Box::new(statement(1)?))
            }
            "all" => {
                arity(3)?;
                Statement::All(selector()?, Box::new(statement(2)?))
            }
            "any" => {
                arity(3)?;
                Statement::Any(selector()?, Box::new(statement(2)?))
            }
            other => return Err(PolicyError::UnknownOperator(String::from(other))),
        })
    }

    /// The wire form.
    #[must_use]
    pub fn to_ipld(&self) -> Ipld {
        let text = |s: &str| Ipld::String(String::from(s));
        let triple = |op: &str, sel: &Selector, value: Ipld| {
            Ipld::List(alloc::vec![text(op), text(sel.as_str()), value])
        };
        match self {
            Statement::Equal(sel, value) => triple("==", sel, value.clone()),
            Statement::NotEqual(sel, value) => triple("!=", sel, value.clone()),
            Statement::Less(sel, n) => triple("<", sel, n.to_ipld()),
            Statement::LessOrEqual(sel, n) => triple("<=", sel, n.to_ipld()),
            Statement::Greater(sel, n) => triple(">", sel, n.to_ipld()),
            Statement::GreaterOrEqual(sel, n) => triple(">=", sel, n.to_ipld()),
            Statement::Like(sel, pattern) => triple("like", sel, text(pattern.as_str())),
            Statement::And(list) => Ipld::List(alloc::vec![
                text("and"),
                Ipld::List(list.iter().map(Statement::to_ipld).collect())
            ]),
            Statement::Or(list) => Ipld::List(alloc::vec![
                text("or"),
                Ipld::List(list.iter().map(Statement::to_ipld).collect())
            ]),
            Statement::Not(inner) => Ipld::List(alloc::vec![text("not"), inner.to_ipld()]),
            Statement::All(sel, inner) => triple("all", sel, inner.to_ipld()),
            Statement::Any(sel, inner) => triple("any", sel, inner.to_ipld()),
        }
    }

    /// Whether the statement holds for `args`.
    #[must_use]
    pub fn holds(&self, args: &Ipld) -> bool {
        match self {
            Statement::Equal(sel, value) => {
                sel.resolve(args).is_some_and(|found| equal(&found, value))
            }
            Statement::NotEqual(sel, value) => {
                !sel.resolve(args).is_some_and(|found| equal(&found, value))
            }
            Statement::Less(sel, n) => compare(sel, args, n, Ordering::is_lt),
            Statement::LessOrEqual(sel, n) => compare(sel, args, n, Ordering::is_le),
            Statement::Greater(sel, n) => compare(sel, args, n, Ordering::is_gt),
            Statement::GreaterOrEqual(sel, n) => compare(sel, args, n, Ordering::is_ge),
            Statement::Like(sel, pattern) => sel
                .resolve(args)
                .is_some_and(|found| matches!(&*found, Ipld::String(s) if pattern.matches(s))),
            Statement::And(list) => list.iter().all(|s| s.holds(args)),
            Statement::Or(list) => list.is_empty() || list.iter().any(|s| s.holds(args)),
            Statement::Not(inner) => !inner.holds(args),
            Statement::All(sel, inner) => {
                elements(sel, args).is_some_and(|items| items.iter().all(|item| inner.holds(item)))
            }
            Statement::Any(sel, inner) => elements(sel, args).is_some_and(|items| {
                items.is_empty() || items.iter().any(|item| inner.holds(item))
            }),
        }
    }
}

fn compare(sel: &Selector, args: &Ipld, right: &Number, accept: fn(Ordering) -> bool) -> bool {
    sel.resolve(args)
        .and_then(|found| Number::from_ipld(&found))
        .and_then(|left| left.partial_cmp(right))
        .is_some_and(accept)
}

/// The items a quantifier ranges over: a list's elements or a map's values.
fn elements<'a>(sel: &Selector, args: &'a Ipld) -> Option<Cow<'a, [Ipld]>> {
    match sel.resolve(args)? {
        Cow::Borrowed(Ipld::List(list)) => Some(Cow::Borrowed(list.as_slice())),
        Cow::Borrowed(Ipld::Map(map)) => Some(Cow::Owned(map.values().cloned().collect())),
        Cow::Owned(Ipld::List(list)) => Some(Cow::Owned(list)),
        Cow::Owned(Ipld::Map(map)) => Some(Cow::Owned(map.into_values().collect())),
        _ => None,
    }
}

/// Deep equality in which `1`, `1.0` and `1.00` are the same number.
#[must_use]
pub fn equal(a: &Ipld, b: &Ipld) -> bool {
    match (a, b) {
        (Ipld::Integer(_) | Ipld::Float(_), Ipld::Integer(_) | Ipld::Float(_)) => {
            Number::from_ipld(a)
                .zip(Number::from_ipld(b))
                .is_some_and(|(x, y)| x.partial_cmp(&y) == Some(Ordering::Equal))
        }
        (Ipld::List(x), Ipld::List(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(p, q)| equal(p, q))
        }
        (Ipld::Map(x), Ipld::Map(y)) => {
            x.len() == y.len() && x.iter().all(|(k, v)| y.get(k).is_some_and(|w| equal(v, w)))
        }
        _ => a == b,
    }
}

/// A number in a comparison. Integers and floats compare by value.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Number {
    /// An integer.
    Integer(i128),
    /// A float.
    Float(f64),
}

impl Number {
    /// The number inside an IPLD value, if it is one.
    #[must_use]
    pub fn from_ipld(value: &Ipld) -> Option<Self> {
        match value {
            Ipld::Integer(i) => Some(Number::Integer(*i)),
            Ipld::Float(f) => Some(Number::Float(*f)),
            _ => None,
        }
    }

    /// The IPLD value.
    #[must_use]
    pub fn to_ipld(self) -> Ipld {
        match self {
            Number::Integer(i) => Ipld::Integer(i),
            Number::Float(f) => Ipld::Float(f),
        }
    }
}

impl PartialOrd for Number {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match (self, other) {
            (Number::Integer(a), Number::Integer(b)) => Some(a.cmp(b)),
            (Number::Float(a), Number::Float(b)) => a.partial_cmp(b),
            (Number::Integer(a), Number::Float(b)) => int_float(*a, *b),
            (Number::Float(a), Number::Integer(b)) => int_float(*b, *a).map(Ordering::reverse),
        }
    }
}

/// Compare an integer with a float exactly where the float is integral.
/// `core` has no `fract`, so integrality is a cast round trip: an `f64`
/// that survives truncation to `i128` and back had no fractional part.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::float_cmp
)]
fn int_float(i: i128, f: f64) -> Option<Ordering> {
    if !f.is_finite() {
        return None;
    }
    if f > -1.0e38 && f < 1.0e38 {
        let truncated = f as i128;
        if truncated as f64 == f {
            return Some(i.cmp(&truncated));
        }
    }
    (i as f64).partial_cmp(&f)
}

/// Why a policy did not parse.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PolicyError {
    /// The policy is not a list.
    #[error("policy is not a list")]
    NotAList,

    /// A statement is not a list.
    #[error("statement is not a list")]
    StatementNotAList,

    /// A statement does not begin with an operator string.
    #[error("statement has no operator")]
    MissingOperator,

    /// An operator this crate does not know.
    #[error("unknown operator `{0}`")]
    UnknownOperator(String),

    /// The wrong number of operands for the operator.
    #[error("wrong number of operands for `{0}`")]
    Arity(String),

    /// An operand is absent.
    #[error("missing operand")]
    MissingOperand,

    /// The operand where a selector belongs is not a selector.
    #[error("expected a selector")]
    ExpectedSelector,

    /// The selector does not parse.
    #[error("selector: {0}")]
    Selector(#[from] SelectorError),

    /// The operand where a number belongs is not one.
    #[error("expected a number")]
    ExpectedNumber,

    /// The operand where a string belongs is not one.
    #[error("expected a string")]
    ExpectedString,

    /// The operand where a list of statements belongs is not one.
    #[error("expected a list of statements")]
    ExpectedStatementList,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use alloc::{string::ToString, vec};

    use super::*;

    fn text(s: &str) -> Ipld {
        Ipld::String(s.to_string())
    }

    fn list(items: Vec<Ipld>) -> Ipld {
        Ipld::List(items)
    }

    fn statement(items: Vec<Ipld>) -> Statement {
        Statement::from_ipld(&list(items)).unwrap()
    }

    fn args() -> Ipld {
        Ipld::Map(
            [
                ("from", text("alice@example.com")),
                (
                    "to",
                    list(vec![
                        text("bob@example.com"),
                        text("carol@elsewhere.example.com"),
                    ]),
                ),
                ("count", Ipld::Integer(3)),
                ("ratio", Ipld::Float(1.0)),
                (
                    "a",
                    list(vec![
                        Ipld::Map([("b".to_string(), Ipld::Integer(1))].into()),
                        Ipld::Map([("b".to_string(), Ipld::Integer(2))].into()),
                        Ipld::Map([("z".to_string(), list(vec![Ipld::Integer(7)]))].into()),
                    ]),
                ),
            ]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
        )
    }

    #[test]
    fn specification_walkthrough() {
        let policy = Policy::from_ipld(&list(vec![
            list(vec![text("=="), text(".from"), text("alice@example.com")]),
            list(vec![
                text("any"),
                text(".to"),
                list(vec![text("like"), text("."), text("*@example.com")]),
            ]),
        ]))
        .unwrap();
        assert_eq!(policy.check(&args()), Ok(()));

        let strict = Policy::from_ipld(&list(vec![list(vec![
            text("all"),
            text(".to"),
            list(vec![text("like"), text("."), text("*@example.com")]),
        ])]))
        .unwrap();
        assert_eq!(strict.check(&args()), Err(0));
    }

    #[test]
    fn quantifiers_reduce_as_the_specification_shows() {
        assert!(!statement(vec![
            text("all"),
            text(".a"),
            list(vec![text(">"), text(".b"), Ipld::Integer(0)])
        ])
        .holds(&args()));
        assert!(statement(vec![
            text("any"),
            text(".a"),
            list(vec![text("=="), text(".b"), Ipld::Integer(2)])
        ])
        .holds(&args()));
        // Quantifying over something that is not a collection is false, not an error.
        assert!(!statement(vec![
            text("all"),
            text(".count"),
            list(vec![text(">"), text("."), Ipld::Integer(0)])
        ])
        .holds(&args()));
        // Empty collections: `all` is vacuously true and `any` follows `or`.
        let empty = Ipld::Map([("xs".to_string(), list(vec![]))].into());
        assert!(statement(vec![
            text("all"),
            text(".xs"),
            list(vec![text("=="), text("."), Ipld::Integer(1)])
        ])
        .holds(&empty));
        assert!(statement(vec![
            text("any"),
            text(".xs"),
            list(vec![text("=="), text("."), Ipld::Integer(1)])
        ])
        .holds(&empty));
    }

    #[test]
    fn numbers_compare_across_types_and_non_numbers_are_false() {
        assert!(statement(vec![text(">="), text(".count"), Ipld::Float(3.0)]).holds(&args()));
        assert!(statement(vec![text("<"), text(".ratio"), Ipld::Integer(2)]).holds(&args()));
        assert!(statement(vec![text("=="), text(".ratio"), Ipld::Integer(1)]).holds(&args()));
        assert!(!statement(vec![text(">"), text(".from"), Ipld::Integer(0)]).holds(&args()));
        assert!(!statement(vec![text(">"), text(".missing"), Ipld::Integer(0)]).holds(&args()));
        assert!(
            statement(vec![text("!="), text(".missing.deeper"), Ipld::Integer(0)]).holds(&args())
        );
    }

    #[test]
    fn connectives() {
        assert!(statement(vec![text("and"), list(vec![])]).holds(&args()));
        assert!(statement(vec![text("or"), list(vec![])]).holds(&args()));
        assert!(!statement(vec![
            text("not"),
            list(vec![text("=="), text(".count"), Ipld::Integer(3)])
        ])
        .holds(&args()));
        assert!(statement(vec![
            text("or"),
            list(vec![
                list(vec![text("=="), text(".count"), Ipld::Integer(4)]),
                list(vec![text("=="), text(".count"), Ipld::Integer(3)]),
            ]),
        ])
        .holds(&args()));
    }

    #[test]
    fn deep_equality_is_exact_on_structure() {
        let exact = list(vec![
            text("bob@example.com"),
            text("carol@elsewhere.example.com"),
        ]);
        assert!(statement(vec![text("=="), text(".to"), exact]).holds(&args()));
        assert!(!statement(vec![
            text("=="),
            text(".to"),
            list(vec![text("bob@example.com")])
        ])
        .holds(&args()));
    }

    #[test]
    fn wire_form_round_trips_verbatim() {
        let wire = list(vec![
            list(vec![text("=="), text(".status"), text("draft")]),
            list(vec![
                text("all"),
                text(".reviewer"),
                list(vec![text("like"), text(".email"), text("*@example.com")]),
            ]),
            list(vec![
                text("not"),
                list(vec![
                    text("and"),
                    list(vec![list(vec![text("<="), text(".n"), Ipld::Float(2.5)])]),
                ]),
            ]),
        ]);
        assert_eq!(Policy::from_ipld(&wire).unwrap().to_ipld(), wire);
    }

    #[test]
    fn refuses_malformed_statements() {
        assert_eq!(Policy::from_ipld(&text("x")), Err(PolicyError::NotAList));
        assert_eq!(
            Statement::from_ipld(&list(vec![])),
            Err(PolicyError::MissingOperator)
        );
        assert_eq!(
            Statement::from_ipld(&list(vec![text("==")])),
            Err(PolicyError::Arity("==".into()))
        );
        assert_eq!(
            Statement::from_ipld(&list(vec![text("<"), text(".a"), text("1")])),
            Err(PolicyError::ExpectedNumber)
        );
        assert_eq!(
            Statement::from_ipld(&list(vec![text("match"), text(".a"), text("x")])),
            Err(PolicyError::UnknownOperator("match".into()))
        );
        assert_eq!(
            Statement::from_ipld(&list(vec![text("and"), text(".a")])),
            Err(PolicyError::ExpectedStatementList)
        );
        assert!(matches!(
            Statement::from_ipld(&list(vec![text("=="), text("a"), text("x")])),
            Err(PolicyError::Selector(_))
        ));
    }
}
