//! A mixed algorithm delegation chain, validated at execution time, and
//! every way the validator can reject one.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::too_many_lines
)]

use pq_ucan::{
    command::Command,
    crypto::{ed25519::Ed25519Keypair, p256::P256Keypair, secp256k1::Secp256k1Keypair, Signer},
    delegation::{Delegation, Subject},
    did::Did,
    invocation::Invocation,
    nonce::Nonce,
    policy::Policy,
    time::Timestamp,
    validate::{Hop, MemoryReplayGuard, MemoryStore, ValidationError, Validator},
    Ipld,
};

fn text(s: &str) -> Ipld {
    Ipld::String(s.into())
}

fn policy(statements: &[&[&str]]) -> Policy {
    Policy::from_ipld(&Ipld::List(
        statements
            .iter()
            .map(|s| Ipld::List(s.iter().map(|t| text(t)).collect()))
            .collect(),
    ))
    .unwrap()
}

fn cmd(s: &str) -> Command {
    Command::parse(s).unwrap()
}

/// Alice owns the store. Bob, Carol and Dan each sign with a different
/// algorithm, which is the point: one chain, four principals, three suites.
struct World {
    alice: Ed25519Keypair,
    bob: P256Keypair,
    carol: Secp256k1Keypair,
    dan: Ed25519Keypair,
    now: Timestamp,
}

impl World {
    fn new() -> Self {
        World {
            alice: Ed25519Keypair::from_seed(&[1; 32]),
            bob: P256Keypair::from_bytes(&[2; 32]).unwrap(),
            carol: Secp256k1Keypair::from_bytes(&[3; 32]).unwrap(),
            dan: Ed25519Keypair::from_seed(&[4; 32]),
            now: Timestamp::from_unix(1_800_000_000).unwrap(),
        }
    }

    fn delegate(
        &self,
        signer: &impl Signer,
        audience: Did,
        subject: Subject,
        command: &str,
        policy: Policy,
        nonce: u8,
    ) -> Delegation {
        Delegation::builder(audience, subject, cmd(command))
            .policy(policy)
            .nonce(Nonce::from_bytes(&[nonce; 12]))
            .expires_at(self.now.plus_seconds(3600))
            .sign(signer)
            .unwrap()
    }

    /// Alice -> Bob (`/crud`, table must be `posts`) -> Carol
    /// (`/crud/read`) -> Dan (powerline, `/crud/read`, table like `p*`).
    fn chain(&self) -> Vec<Delegation> {
        let alice = Subject::Did(self.alice.did());
        vec![
            self.delegate(
                &self.alice,
                self.bob.did(),
                alice.clone(),
                "/crud",
                policy(&[&["==", ".table", "posts"]]),
                1,
            ),
            self.delegate(
                &self.bob,
                self.carol.did(),
                alice,
                "/crud/read",
                Policy::default(),
                2,
            ),
            self.delegate(
                &self.carol,
                self.dan.did(),
                Subject::Powerline,
                "/crud/read",
                policy(&[&["like", ".table", "p*"]]),
                3,
            ),
        ]
    }

    fn store(chain: &[Delegation]) -> MemoryStore {
        let mut store = MemoryStore::new();
        for d in chain {
            store.insert(d.clone());
        }
        store
    }

    fn invoke(
        &self,
        signer: &impl Signer,
        chain: &[Delegation],
        command: &str,
        table: &str,
        expires: Timestamp,
    ) -> Invocation {
        Invocation::builder(self.alice.did(), cmd(command))
            .arg("table", text(table))
            .proofs(chain.iter().map(|d| *d.cid()))
            .nonce(Nonce::from_bytes(&[9; 12]))
            .expires_at(expires)
            .sign(signer)
            .unwrap()
    }
}

#[test]
fn a_mixed_algorithm_chain_validates() {
    let w = World::new();
    let chain = w.chain();
    let store = World::store(&chain);
    let inv = w.invoke(
        &w.dan,
        &chain,
        "/crud/read",
        "posts",
        w.now.plus_seconds(60),
    );

    let mut guard = MemoryReplayGuard::new();
    let alice = w.alice.did();
    let proof = Validator::new(&store, w.now)
        .executor(&alice)
        .replay_guard(&mut guard)
        .validate(&inv)
        .unwrap();
    assert_eq!(proof.chain().len(), 3);
    assert_eq!(proof.subject(), &alice);
    assert_eq!(proof.invocation(), inv.cid());
    assert_eq!(proof.chain()[2].subject(), &Subject::Powerline);
}

#[test]
fn every_rejection_names_its_hop() {
    let w = World::new();
    let chain = w.chain();
    let store = World::store(&chain);
    let alice = w.alice.did();
    let ok = w.invoke(
        &w.dan,
        &chain,
        "/crud/read",
        "posts",
        w.now.plus_seconds(60),
    );

    // 1: a proof the store does not hold.
    let mut partial = World::store(&chain);
    partial.remove(chain[1].cid());
    assert!(matches!(
        Validator::new(&partial, w.now).validate(&ok),
        Err(ValidationError::MissingProof(cid)) if cid == *chain[1].cid()
    ));

    // 2: no proofs at all.
    let bare = w.invoke(&w.dan, &[], "/crud/read", "posts", w.now.plus_seconds(60));
    assert!(matches!(
        Validator::new(&store, w.now).validate(&bare),
        Err(ValidationError::EmptyChain)
    ));

    // 3: the invocation claims a subject that did not issue the root.
    let wrong_subject = Invocation::builder(w.bob.did(), cmd("/crud/read"))
        .proofs(chain.iter().map(|d| *d.cid()))
        .nonce(Nonce::empty())
        .expires_at(w.now.plus_seconds(60))
        .sign(&w.dan)
        .unwrap();
    assert!(matches!(
        Validator::new(&store, w.now).validate(&wrong_subject),
        Err(ValidationError::RootNotSubject { .. })
    ));

    // 4: a powerline at the root.
    let root_powerline = w.delegate(
        &w.alice,
        w.dan.did(),
        Subject::Powerline,
        "/",
        Policy::default(),
        5,
    );
    let mut with_powerline = World::store(&chain);
    with_powerline.insert(root_powerline.clone());
    let via_powerline = w.invoke(
        &w.dan,
        &[root_powerline],
        "/crud/read",
        "posts",
        w.now.plus_seconds(60),
    );
    assert!(matches!(
        Validator::new(&with_powerline, w.now).validate(&via_powerline),
        Err(ValidationError::PowerlineAtRoot)
    ));

    // 5: a hop about someone else's authority.
    let about_bob = w.delegate(
        &w.bob,
        w.carol.did(),
        Subject::Did(w.bob.did()),
        "/crud/read",
        Policy::default(),
        6,
    );
    let swapped = vec![chain[0].clone(), about_bob, chain[2].clone()];
    let swapped_store = World::store(&swapped);
    let inv = w.invoke(
        &w.dan,
        &swapped,
        "/crud/read",
        "posts",
        w.now.plus_seconds(60),
    );
    assert!(matches!(
        Validator::new(&swapped_store, w.now).validate(&inv),
        Err(ValidationError::SubjectMismatch { hop: Hop::Proof(1) })
    ));

    // 6: the last hop's audience is not the invoker.
    let eve = Ed25519Keypair::from_seed(&[99; 32]);
    let by_eve = w.invoke(&eve, &chain, "/crud/read", "posts", w.now.plus_seconds(60));
    assert!(matches!(
        Validator::new(&store, w.now).validate(&by_eve),
        Err(ValidationError::PrincipalMismatch {
            hop: Hop::Proof(2),
            ..
        })
    ));

    // 7: the invocation asks for more than the last hop grants.
    let write = w.invoke(
        &w.dan,
        &chain,
        "/crud/write",
        "posts",
        w.now.plus_seconds(60),
    );
    assert!(matches!(
        Validator::new(&store, w.now).validate(&write),
        Err(ValidationError::CommandNotCovered {
            hop: Hop::Proof(2),
            ..
        })
    ));

    // 8: a hop outside its window, and an invocation past its own.
    assert!(matches!(
        Validator::new(&store, w.now.plus_seconds(7200)).validate(&ok),
        Err(ValidationError::Expired {
            hop: Hop::Proof(0),
            ..
        })
    ));
    let stale = w.invoke(
        &w.dan,
        &chain,
        "/crud/read",
        "posts",
        w.now.minus_seconds(120),
    );
    assert!(matches!(
        Validator::new(&store, w.now).validate(&stale),
        Err(ValidationError::Expired {
            hop: Hop::Invocation,
            ..
        })
    ));
    let early = Delegation::builder(w.bob.did(), Subject::Did(alice.clone()), cmd("/crud"))
        .not_before(w.now.plus_seconds(600))
        .nonce(Nonce::from_bytes(&[8; 12]))
        .expires_at(w.now.plus_seconds(3600))
        .sign(&w.alice)
        .unwrap();
    let mut early_store = World::store(&chain[1..]);
    early_store.insert(early.clone());
    let not_yet = w.invoke(
        &w.dan,
        &[early, chain[1].clone(), chain[2].clone()],
        "/crud/read",
        "posts",
        w.now.plus_seconds(60),
    );
    assert!(matches!(
        Validator::new(&early_store, w.now).validate(&not_yet),
        Err(ValidationError::NotYetValid {
            hop: Hop::Proof(0),
            ..
        })
    ));

    // 9: a hop whose bytes were altered after signing.
    let mut altered = chain[0].bytes().to_vec();
    if let Some(last) = altered.last_mut() {
        *last ^= 0x01;
    }
    let altered = Delegation::decode(&altered).unwrap();
    let forged = vec![altered, chain[1].clone(), chain[2].clone()];
    let forged_store = World::store(&forged);
    let inv = w.invoke(
        &w.dan,
        &forged,
        "/crud/read",
        "posts",
        w.now.plus_seconds(60),
    );
    assert!(matches!(
        Validator::new(&forged_store, w.now).validate(&inv),
        Err(ValidationError::BadSignature { hop: Hop::Proof(0) })
    ));

    // 10: arguments a policy in the chain refuses.
    let users = w.invoke(
        &w.dan,
        &chain,
        "/crud/read",
        "users",
        w.now.plus_seconds(60),
    );
    assert!(matches!(
        Validator::new(&store, w.now).validate(&users),
        Err(ValidationError::PolicyRejected {
            hop: Hop::Proof(0),
            statement: 0
        })
    ));
    let pages = w.invoke(
        &w.dan,
        &chain,
        "/crud/read",
        "pages",
        w.now.plus_seconds(60),
    );
    assert!(matches!(
        Validator::new(&store, w.now).validate(&pages),
        Err(ValidationError::PolicyRejected {
            hop: Hop::Proof(0),
            statement: 0
        })
    ));

    // 11: addressed to someone other than this executor.
    let bob = w.bob.did();
    assert!(matches!(
        Validator::new(&store, w.now).executor(&bob).validate(&ok),
        Err(ValidationError::WrongExecutor { .. })
    ));

    // 12: seen before.
    let mut guard = MemoryReplayGuard::new();
    Validator::new(&store, w.now)
        .replay_guard(&mut guard)
        .validate(&ok)
        .unwrap();
    assert!(matches!(
        Validator::new(&store, w.now).replay_guard(&mut guard).validate(&ok),
        Err(ValidationError::Replay(cid)) if cid == *ok.cid()
    ));
}

#[test]
fn skew_is_applied_to_every_bound() {
    let w = World::new();
    let chain = w.chain();
    let store = World::store(&chain);
    // Expired half a minute ago: inside the default allowance, outside zero.
    let inv = w.invoke(
        &w.dan,
        &chain,
        "/crud/read",
        "posts",
        w.now.minus_seconds(30),
    );
    assert!(Validator::new(&store, w.now).validate(&inv).is_ok());
    assert!(matches!(
        Validator::new(&store, w.now).skew(0).validate(&inv),
        Err(ValidationError::Expired {
            hop: Hop::Invocation,
            ..
        })
    ));
}

#[test]
fn a_rejected_invocation_is_not_recorded_by_the_guard() {
    let w = World::new();
    let chain = w.chain();
    let store = World::store(&chain);
    let mut guard = MemoryReplayGuard::new();
    let users = w.invoke(
        &w.dan,
        &chain,
        "/crud/read",
        "users",
        w.now.plus_seconds(60),
    );
    assert!(Validator::new(&store, w.now)
        .replay_guard(&mut guard)
        .validate(&users)
        .is_err());
    // Nothing was recorded, so a corrected invocation with the same CID
    // would not be mistaken for a replay; a different one certainly is not.
    let ok = w.invoke(
        &w.dan,
        &chain,
        "/crud/read",
        "posts",
        w.now.plus_seconds(60),
    );
    assert!(Validator::new(&store, w.now)
        .replay_guard(&mut guard)
        .validate(&ok)
        .is_ok());
}

#[test]
fn stores_prune_by_expiry() {
    let w = World::new();
    let chain = w.chain();
    let mut store = World::store(&chain);
    store.prune_expired(w.now.plus_seconds(3600 + 61), 0);
    assert!(store.is_empty());
}

#[cfg(feature = "ml-dsa")]
#[test]
fn a_post_quantum_leaf_invokes_a_classical_chain() {
    use pq_ucan::crypto::{ml_dsa::MlDsaKeypair, Algorithm};

    let w = World::new();
    let device = MlDsaKeypair::from_seed(Algorithm::MlDsa87, &[7; 32]).unwrap();
    let alice = Subject::Did(w.alice.did());
    let chain = vec![
        w.delegate(
            &w.alice,
            w.bob.did(),
            alice.clone(),
            "/crud",
            Policy::default(),
            1,
        ),
        w.delegate(
            &w.bob,
            device.did(),
            alice,
            "/crud/read",
            Policy::default(),
            2,
        ),
    ];
    let store = World::store(&chain);
    let inv = w.invoke(
        &device,
        &chain,
        "/crud/read",
        "posts",
        w.now.plus_seconds(60),
    );
    assert_eq!(inv.algorithm(), Algorithm::MlDsa87);
    let proof = Validator::new(&store, w.now).validate(&inv).unwrap();
    assert_eq!(proof.chain().len(), 2);
}
