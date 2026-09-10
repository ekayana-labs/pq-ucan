//! UCAN 1.0 delegation, invocation and proof chain validation, with
//! classical and post-quantum `did:key` principals in the same chain.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod cid;

pub use ipld_core::{cid::Cid, ipld::Ipld};
