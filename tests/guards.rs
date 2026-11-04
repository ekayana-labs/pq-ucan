//! The guards a validator only applies when asked to.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use pq_ucan::{
    command::Command,
    crypto::{ed25519::Ed25519Keypair, Signer},
    delegation::{Delegation, Subject},
    invocation::Invocation,
    nonce::Nonce,
    policy::Policy,
    time::Timestamp,
    validate::{MemoryReplayGuard, MemoryStore, ValidationError, Validator},
    Cid, Ipld,
};

fn now() -> Timestamp {
    Timestamp::from_unix(1_800_000_000).unwrap()
}

fn cmd() -> Command {
    Command::parse("/mcp/read_file").unwrap()
}

/// A straight chain: each key delegates to the next, and the last key invokes.
struct Chain {
    keys: Vec<Ed25519Keypair>,
    links: Vec<Delegation>,
}

impl Chain {
    fn new(hops: u8) -> Self {
        Self::with_root_policy(hops, Policy::default())
    }

    fn with_root_policy(hops: u8, root_policy: Policy) -> Self {
        let keys: Vec<_> = (0..=hops)
            .map(|i| Ed25519Keypair::from_seed(&[i + 1; 32]))
            .collect();
        let mut root_policy = Some(root_policy);
        let links = (0..usize::from(hops))
            .map(|hop| {
                Delegation::builder(keys[hop + 1].did(), Subject::Did(keys[0].did()), cmd())
                    .policy(root_policy.take().unwrap_or_default())
                    .nonce(Nonce::from_bytes(&[u8::try_from(hop).unwrap(); 12]))
                    .expires_at(now().plus_seconds(3600))
                    .sign(&keys[hop])
                    .unwrap()
            })
            .collect();
        Chain { keys, links }
    }

    fn store(&self) -> MemoryStore {
        let mut store = MemoryStore::new();
        for link in &self.links {
            store.insert(link.clone());
        }
        store
    }

    fn invoke_naming(&self, proofs: impl IntoIterator<Item = Cid>, path: &str) -> Invocation {
        Invocation::builder(self.keys[0].did(), cmd())
            .arg("path", Ipld::String(path.into()))
            .proofs(proofs)
            .nonce(Nonce::from_bytes(&[42; 12]))
            .expires_at(now().plus_seconds(60))
            .sign(self.keys.last().unwrap())
            .unwrap()
    }

    fn invoke(&self, path: &str) -> Invocation {
        self.invoke_naming(self.links.iter().map(|link| *link.cid()), path)
    }
}

#[test]
fn a_chain_of_any_length_passes_without_a_limit() {
    let chain = Chain::new(12);
    let proof = Validator::new(&chain.store(), now())
        .validate(&chain.invoke("/data/file"))
        .unwrap();
    assert_eq!(proof.chain().len(), 12);
}

#[test]
fn the_limit_allows_its_own_length_and_refuses_one_more() {
    let chain = Chain::new(3);
    let store = chain.store();
    let inv = chain.invoke("/data/file");

    assert!(Validator::new(&store, now())
        .max_proofs(3)
        .validate(&inv)
        .is_ok());
    assert!(matches!(
        Validator::new(&store, now()).max_proofs(2).validate(&inv),
        Err(ValidationError::TooManyProofs { count: 3, max: 2 })
    ));
}

#[test]
fn the_limit_is_checked_before_any_proof_is_looked_up() {
    let chain = Chain::new(3);
    assert!(matches!(
        Validator::new(&MemoryStore::new(), now())
            .max_proofs(2)
            .validate(&chain.invoke("/data/file")),
        Err(ValidationError::TooManyProofs { .. })
    ));
}

#[test]
fn a_chain_over_the_limit_is_not_recorded_by_the_guard() {
    let chain = Chain::new(3);
    let store = chain.store();
    let inv = chain.invoke("/data/file");
    let mut guard = MemoryReplayGuard::new();

    assert!(Validator::new(&store, now())
        .max_proofs(2)
        .replay_guard(&mut guard)
        .validate(&inv)
        .is_err());
    assert!(Validator::new(&store, now())
        .replay_guard(&mut guard)
        .validate(&inv)
        .is_ok());
}

#[test]
fn no_proofs_is_still_an_empty_chain_under_a_limit_of_zero() {
    let chain = Chain::new(1);
    assert!(matches!(
        Validator::new(&chain.store(), now())
            .max_proofs(0)
            .validate(&chain.invoke_naming([], "/data/file")),
        Err(ValidationError::EmptyChain)
    ));
}
