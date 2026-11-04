//! The guards a validator only applies when asked to.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use core::cell::Cell;

use pq_ucan::{
    command::Command,
    crypto::{ed25519::Ed25519Keypair, Signer},
    delegation::{Delegation, Subject},
    did::Did,
    invocation::Invocation,
    nonce::Nonce,
    policy::{Pattern, Policy, Selector, Statement},
    time::Timestamp,
    validate::{
        Hop, MemoryReplayGuard, MemoryRevocationStore, MemoryStore, ProofStore, RevocationStore,
        ValidationError, Validator,
    },
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

fn revoking(cid: &Cid) -> MemoryRevocationStore {
    let mut revocations = MemoryRevocationStore::new();
    revocations.revoke(*cid);
    revocations
}

#[test]
fn a_revoked_delegation_passes_without_a_store() {
    let chain = Chain::new(3);
    assert!(Validator::new(&chain.store(), now())
        .validate(&chain.invoke("/data/file"))
        .is_ok());
}

#[test]
fn a_revocation_at_any_hop_rejects_the_chain_and_names_the_hop() {
    let chain = Chain::new(3);
    let store = chain.store();
    let inv = chain.invoke("/data/file");
    for (hop, link) in chain.links.iter().enumerate() {
        let revocations = revoking(link.cid());
        match Validator::new(&store, now())
            .revocations(&revocations)
            .validate(&inv)
        {
            Err(ValidationError::Revoked { hop: at, cid }) => {
                assert_eq!(at, Hop::Proof(hop));
                assert_eq!(cid, *link.cid());
            }
            other => panic!("hop {hop}: {other:?}"),
        }
    }
}

#[test]
fn a_revocation_elsewhere_does_not_touch_this_chain() {
    let chain = Chain::new(3);
    let elsewhere = Delegation::builder(chain.keys[1].did(), Subject::Powerline, cmd())
        .nonce(Nonce::from_bytes(&[77; 12]))
        .expires_at(now().plus_seconds(3600))
        .sign(&chain.keys[0])
        .unwrap();
    let revocations = revoking(elsewhere.cid());
    assert!(Validator::new(&chain.store(), now())
        .revocations(&revocations)
        .validate(&chain.invoke("/data/file"))
        .is_ok());
}

/// Resolves any CID with the right digest, as a store keyed by hash does.
struct ByHash(Vec<Delegation>);

impl ProofStore for ByHash {
    fn get(&self, cid: &Cid) -> Option<Delegation> {
        self.0
            .iter()
            .find(|link| link.cid().hash() == cid.hash())
            .cloned()
    }
}

#[test]
fn a_revoked_delegation_named_by_another_cid_is_still_revoked() {
    const RAW: u64 = 0x55;
    let chain = Chain::new(2);
    let store = ByHash(chain.links.clone());
    let aliases = chain
        .links
        .iter()
        .map(|link| Cid::new_v1(RAW, *link.cid().hash()));
    let inv = chain.invoke_naming(aliases, "/data/file");
    assert!(Validator::new(&store, now()).validate(&inv).is_ok());

    let revocations = revoking(chain.links[1].cid());
    assert!(matches!(
        Validator::new(&store, now()).revocations(&revocations).validate(&inv),
        Err(ValidationError::Revoked { hop: Hop::Proof(1), cid }) if cid == *chain.links[1].cid()
    ));
}

#[test]
fn a_revoked_chain_is_not_recorded_by_the_guard() {
    let chain = Chain::new(3);
    let store = chain.store();
    let inv = chain.invoke("/data/file");
    let revocations = revoking(chain.links[0].cid());
    let mut guard = MemoryReplayGuard::new();

    assert!(Validator::new(&store, now())
        .revocations(&revocations)
        .replay_guard(&mut guard)
        .validate(&inv)
        .is_err());
    assert!(Validator::new(&store, now())
        .replay_guard(&mut guard)
        .validate(&inv)
        .is_ok());
}

#[derive(Default)]
struct Counting(Cell<usize>);

impl RevocationStore for Counting {
    fn is_revoked(&self, _: &Cid, _: &[&Did]) -> bool {
        self.0.set(self.0.get() + 1);
        false
    }
}

#[test]
fn the_store_is_not_asked_about_an_unsigned_chain() {
    let chain = Chain::new(2);
    let mut altered = chain.links[0].bytes().to_vec();
    *altered.last_mut().unwrap() ^= 0x01;
    let altered = Delegation::decode(&altered).unwrap();
    let mut store = MemoryStore::new();
    let cids = [store.insert(altered), store.insert(chain.links[1].clone())];
    let counting = Counting::default();

    assert!(matches!(
        Validator::new(&store, now())
            .revocations(&counting)
            .validate(&chain.invoke_naming(cids, "/data/file")),
        Err(ValidationError::BadSignature { hop: Hop::Proof(0) })
    ));
    assert_eq!(counting.0.get(), 0);

    assert!(Validator::new(&chain.store(), now())
        .revocations(&counting)
        .validate(&chain.invoke("/data/file"))
        .is_ok());
    assert_eq!(counting.0.get(), 2);
}

const CLIMBS_OUT: &str = "/data/h1/../../../etc/passwd";

fn path_like(pattern: &str) -> Statement {
    Statement::Like(Selector::parse(".path").unwrap(), Pattern::parse(pattern))
}

fn in_normal_form(path: &str) -> bool {
    path.split('/')
        .all(|segment| segment != ".." && segment != ".")
}

#[test]
fn the_glob_lets_a_path_climb_out_and_the_documented_check_stops_it() {
    let chain = Chain::with_root_policy(2, Policy::new(vec![path_like("/data/h1/*")]));
    let store = chain.store();

    let inv = chain.invoke(CLIMBS_OUT);
    assert!(Validator::new(&store, now()).validate(&inv).is_ok());
    let Some(Ipld::String(path)) = inv.args().get("path") else {
        panic!("the invocation has a path");
    };
    assert!(!in_normal_form(path));

    assert!(in_normal_form("/data/h1/file"));
    assert!(!in_normal_form("/data/h1/.."));
    assert!(!in_normal_form("/data/./h1/file"));
}

#[test]
fn a_policy_can_refuse_parent_segments() {
    let policy = Policy::new(vec![
        path_like("/data/h1/*"),
        Statement::Not(Box::new(path_like("*/../*"))),
        Statement::Not(Box::new(path_like("*/.."))),
    ]);
    let chain = Chain::with_root_policy(2, policy);
    let store = chain.store();

    assert!(Validator::new(&store, now())
        .validate(&chain.invoke("/data/h1/notes..txt"))
        .is_ok());
    for (path, statement) in [(CLIMBS_OUT, 1), ("/data/h1/..", 2)] {
        match Validator::new(&store, now()).validate(&chain.invoke(path)) {
            Err(ValidationError::PolicyRejected {
                hop: Hop::Proof(0),
                statement: at,
            }) => assert_eq!(at, statement, "{path}"),
            other => panic!("{path}: {other:?}"),
        }
    }
}
