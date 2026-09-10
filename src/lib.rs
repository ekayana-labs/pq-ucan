//! UCAN 1.0 delegation, invocation and proof chain validation, with
//! classical and post-quantum `did:key` principals in the same chain.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod cid;
pub mod codec;
pub mod command;
pub mod crypto;
pub mod delegation;
pub mod did;
pub mod envelope;
mod error;
pub mod invocation;
pub mod nonce;
pub mod policy;
pub mod rng;
pub mod time;
pub mod varsig;

pub use error::Error;
pub use ipld_core::{cid::Cid, ipld::Ipld};
