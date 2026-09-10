//! The policy language: statements a delegation places on the `args` of
//! any invocation that uses it.

mod glob;
mod selector;

pub use glob::Pattern;
pub use selector::{Selector, SelectorError};
