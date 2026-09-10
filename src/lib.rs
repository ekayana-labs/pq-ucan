//! UCAN 1.0 delegation, invocation and proof chain validation, with
//! classical and post-quantum `did:key` principals in the same chain.
//!
//! Principals are values: any DID may appear in any position, and the
//! signature algorithm is read from the token, not from a type parameter.
//! Decoded tokens keep their bytes, so signatures and CIDs are checked over
//! what was received. The DAG-CBOR codec is strict in both directions.
//! Execution-time validation runs a fixed pipeline and reports the hop and
//! rule that rejected a chain.
//!
//! The design is in `docs/design.md`; the wire format in
//! `docs/wire-format.md`; the validation rules in `docs/validation.md`.
//!
//! ```
//! use pq_ucan::{
//!     command::Command,
//!     crypto::{ed25519::Ed25519Keypair, Signer},
//!     delegation::{Delegation, Subject},
//!     invocation::Invocation,
//!     nonce::Nonce,
//!     time::Timestamp,
//!     validate::{MemoryStore, Validator},
//! };
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut rng = pq_ucan::rng::system();
//! let alice = Ed25519Keypair::generate(&mut rng);
//! let bob = Ed25519Keypair::generate(&mut rng);
//! let now = Timestamp::from_unix(1_800_000_000)?;
//!
//! // Alice lets Bob read from her store until `exp`.
//! let grant = Delegation::builder(bob.did(), Subject::Did(alice.did()), Command::parse("/crud/read")?)
//!     .nonce(Nonce::random(&mut rng))
//!     .expires_at(now.plus_seconds(3600))
//!     .sign(&alice)?;
//!
//! // Bob exercises it.
//! let invocation = Invocation::builder(alice.did(), Command::parse("/crud/read")?)
//!     .proof(*grant.cid())
//!     .nonce(Nonce::random(&mut rng))
//!     .expires_at(now.plus_seconds(60))
//!     .sign(&bob)?;
//!
//! // Alice, as executor, validates the chain before acting.
//! let mut store = MemoryStore::new();
//! store.insert(grant);
//! let proof = Validator::new(&store, now).executor(&alice.did()).validate(&invocation)?;
//! assert_eq!(proof.chain().len(), 1);
//! # Ok(())
//! # }
//! ```

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
pub mod validate;
pub mod varsig;

pub use error::Error;
pub use ipld_core::{cid::Cid, ipld::Ipld};
