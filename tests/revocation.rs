//! Who may revoke what: `/ucan/revoke` invocations checked against the chain
//! of the delegation they revoke.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use pq_ucan::{
    command::Command,
    crypto::{ed25519::Ed25519Keypair, Algorithm, PublicKey, Signer},
    delegation::{Delegation, Subject},
    did::{Did, KeyResolver, ResolveError, Resolver},
    invocation::Invocation,
    nonce::Nonce,
    policy::Policy,
    time::Timestamp,
    validate::{
        AcceptedRevocation, Hop, MemoryReplayGuard, MemoryRevocationStore, MemoryStore, Revocation,
        RevocationError, ValidationError, Validator, REVOKE_COMMAND,
    },
    Cid, Ipld,
};

fn now() -> Timestamp {
    Timestamp::from_unix(1_800_000_000).unwrap()
}

fn cmd(text: &str) -> Command {
    Command::parse(text).unwrap()
}

fn read_file() -> Command {
    cmd("/mcp/read_file")
}

fn revoke() -> Command {
    cmd(REVOKE_COMMAND)
}

fn key(seed: u8) -> Ed25519Keypair {
    Ed25519Keypair::from_seed(&[seed; 32])
}

fn delegate(
    from: &Ed25519Keypair,
    to: &Ed25519Keypair,
    subject: &Ed25519Keypair,
    command: Command,
) -> Delegation {
    Delegation::builder(to.did(), Subject::Did(subject.did()), command)
        .nonce(Nonce::from_bytes(&[9; 12]))
        .expires_at(now().plus_seconds(3600))
        .sign(from)
        .unwrap()
}

/// Alice owns the resource. Alice grants to Bob, Bob to Carol, Carol to Dan.
/// Mallory has never held anything from any of them.
struct World {
    alice: Ed25519Keypair,
    bob: Ed25519Keypair,
    carol: Ed25519Keypair,
    dan: Ed25519Keypair,
    mallory: Ed25519Keypair,
    zelda: Ed25519Keypair,
    alice_bob: Delegation,
    bob_carol: Delegation,
    carol_dan: Delegation,
}

impl World {
    fn new() -> Self {
        let (alice, bob, carol, dan) = (key(1), key(2), key(3), key(4));
        World {
            alice_bob: delegate(&alice, &bob, &alice, read_file()),
            bob_carol: delegate(&bob, &carol, &alice, read_file()),
            carol_dan: delegate(&carol, &dan, &alice, read_file()),
            alice,
            bob,
            carol,
            dan,
            mallory: key(5),
            zelda: key(6),
        }
    }

    /// The chain to Carol, whose last delegation is the one usually revoked.
    fn to_carol(&self) -> Vec<Delegation> {
        vec![self.alice_bob.clone(), self.bob_carol.clone()]
    }
}

/// A revocation with `sub` set to `subject` and nothing else filled in.
fn revoking(target: &Cid, subject: &Did) -> pq_ucan::invocation::InvocationBuilder<true, true> {
    Invocation::builder(subject.clone(), revoke())
        .arg("revoke", Ipld::Link(*target))
        .nonce(Nonce::empty())
        .expires_at(now().plus_seconds(60))
}

fn signed_by(signer: &Ed25519Keypair, target: &Cid, subject: &Did) -> Invocation {
    revoking(target, subject).sign(signer).unwrap()
}

fn check(
    subject: &Did,
    invocation: &Invocation,
    chain: &[Delegation],
) -> Result<AcceptedRevocation, RevocationError> {
    Validator::new(&MemoryStore::new(), now()).check_revocation(subject, invocation, chain)
}

fn only_this(target: &Cid) -> Policy {
    Policy::from_ipld(&Ipld::List(vec![Ipld::List(vec![
        Ipld::String("==".into()),
        Ipld::String(".revoke".into()),
        Ipld::Link(*target),
    ])]))
    .unwrap()
}

#[test]
fn the_issuer_of_the_delegation_may_revoke_it() {
    let w = World::new();
    let inv = signed_by(&w.bob, w.bob_carol.cid(), &w.alice.did());
    let accepted = check(&w.alice.did(), &inv, &w.to_carol()).unwrap();
    assert_eq!(accepted.target(), w.bob_carol.cid());
    assert_eq!(accepted.revoker(), &w.bob.did());
    assert_eq!(accepted.hop(), 1);
    assert!(!accepted.is_delegated());
    assert!(!accepted.rests_on_intermediate_issuer());
}

#[test]
fn the_root_may_revoke_anything_below_it() {
    let w = World::new();
    let chain = [
        w.alice_bob.clone(),
        w.bob_carol.clone(),
        w.carol_dan.clone(),
    ];
    let inv = signed_by(&w.alice, w.carol_dan.cid(), &w.alice.did());
    let accepted = check(&w.alice.did(), &inv, &chain).unwrap();
    assert_eq!(accepted.hop(), 0);
    assert!(!accepted.rests_on_intermediate_issuer());
}

#[test]
fn an_issuer_above_the_delegation_may_revoke_it() {
    let w = World::new();
    let chain = [
        w.alice_bob.clone(),
        w.bob_carol.clone(),
        w.carol_dan.clone(),
    ];
    let inv = signed_by(&w.bob, w.carol_dan.cid(), &w.alice.did());
    let accepted = check(&w.alice.did(), &inv, &chain).unwrap();
    assert_eq!(accepted.hop(), 1);
    assert!(accepted.rests_on_intermediate_issuer());
}

#[test]
fn someone_downstream_may_not_revoke() {
    let w = World::new();
    for (name, signer) in [("carol", &w.carol), ("dan", &w.dan)] {
        let inv = signed_by(signer, w.bob_carol.cid(), &w.alice.did());
        match check(&w.alice.did(), &inv, &w.to_carol()) {
            Err(RevocationError::NotAuthorized { revoker }) => assert_eq!(revoker, signer.did()),
            other => panic!("{name}: {other:?}"),
        }
    }
}

#[test]
fn someone_unrelated_may_not_revoke() {
    let w = World::new();
    let inv = signed_by(&w.mallory, w.bob_carol.cid(), &w.alice.did());
    assert!(matches!(
        check(&w.alice.did(), &inv, &w.to_carol()),
        Err(RevocationError::NotAuthorized { .. })
    ));
}

#[test]
fn naming_yourself_as_subject_gains_nothing() {
    let w = World::new();
    let inv = signed_by(&w.carol, w.bob_carol.cid(), &w.carol.did());
    assert!(matches!(
        check(&w.alice.did(), &inv, &w.to_carol()),
        Err(RevocationError::SubjectNotInChain { subject }) if subject == w.carol.did()
    ));
}

#[test]
fn a_subject_outside_the_chain_is_refused_even_from_an_issuer_in_it() {
    let w = World::new();
    let inv = signed_by(&w.bob, w.bob_carol.cid(), &w.mallory.did());
    assert!(matches!(
        check(&w.alice.did(), &inv, &w.to_carol()),
        Err(RevocationError::SubjectNotInChain { .. })
    ));
}

#[test]
fn a_longer_chain_does_not_put_someone_downstream_above_the_target() {
    let w = World::new();
    let chain = [
        w.alice_bob.clone(),
        w.bob_carol.clone(),
        w.carol_dan.clone(),
    ];
    let inv = signed_by(&w.carol, w.bob_carol.cid(), &w.alice.did());
    assert!(matches!(
        check(&w.alice.did(), &inv, &chain),
        Err(RevocationError::WrongTarget { named }) if named == *w.bob_carol.cid()
    ));
}

#[test]
fn a_chain_rooted_in_a_powerline_is_refused() {
    let w = World::new();
    let powerline = Delegation::builder(w.bob.did(), Subject::Powerline, read_file())
        .nonce(Nonce::from_bytes(&[3; 12]))
        .expires_at(now().plus_seconds(3600))
        .sign(&w.alice)
        .unwrap();
    let chain = [powerline, w.bob_carol.clone()];
    let inv = signed_by(&w.bob, w.bob_carol.cid(), &w.alice.did());
    assert!(matches!(
        check(&w.alice.did(), &inv, &chain),
        Err(RevocationError::Invalid(ValidationError::PowerlineAtRoot))
    ));
}

/// Carol signs a delegation back to Bob, which needs nobody's consent, and so
/// appears above the delegation that gave Carol her authority.
#[test]
fn a_loop_does_not_put_someone_downstream_above_the_target() {
    let w = World::new();
    let carol_bob = delegate(&w.carol, &w.bob, &w.alice, read_file());
    let chain = [
        w.alice_bob.clone(),
        w.bob_carol.clone(),
        carol_bob,
        w.bob_carol.clone(),
    ];
    let inv = signed_by(&w.carol, w.bob_carol.cid(), &w.alice.did());
    match check(&w.alice.did(), &inv, &chain) {
        Err(RevocationError::RepeatedIssuer { hop, issuer }) => {
            assert_eq!(hop, Hop::Proof(3));
            assert_eq!(issuer, w.bob.did());
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_chain_mallory_rooted_herself_is_refused() {
    let w = World::new();
    // Mallory signs a delegation about Alice's resource to Bob and puts it on
    // top of the delegation she wants gone.
    let forged_root = delegate(&w.mallory, &w.bob, &w.alice, read_file());
    let chain = [forged_root, w.bob_carol.clone()];
    let inv = signed_by(&w.mallory, w.bob_carol.cid(), &w.alice.did());
    assert!(matches!(
        check(&w.alice.did(), &inv, &chain),
        Err(RevocationError::Invalid(ValidationError::RootNotSubject { issuer, .. }))
            if issuer == w.mallory.did()
    ));
}

/// A powerline has no subject of its own, so Mallory can root a path to one in
/// her own authority. That says nothing about Alice's resource.
#[test]
fn a_powerline_under_someone_elses_subject_is_refused() {
    let w = World::new();
    let powerline = Delegation::builder(w.carol.did(), Subject::Powerline, read_file())
        .nonce(Nonce::from_bytes(&[3; 12]))
        .expires_at(now().plus_seconds(3600))
        .sign(&w.bob)
        .unwrap();
    let mallory_bob = delegate(&w.mallory, &w.bob, &w.mallory, read_file());
    let chain = [mallory_bob, powerline.clone()];
    let inv = signed_by(&w.mallory, powerline.cid(), &w.mallory.did());

    assert!(check(&w.mallory.did(), &inv, &chain).is_ok());
    assert!(matches!(
        check(&w.alice.did(), &inv, &chain),
        Err(RevocationError::Invalid(
            ValidationError::RootNotSubject { .. }
        ))
    ));

    // Under Alice's own chain the same powerline can be revoked.
    let chain = [w.alice_bob.clone(), powerline.clone()];
    let inv = signed_by(&w.bob, powerline.cid(), &w.alice.did());
    assert!(check(&w.alice.did(), &inv, &chain).is_ok());
}

#[test]
fn a_chain_about_another_subject_is_refused() {
    let w = World::new();
    let about_mallory = delegate(&w.bob, &w.carol, &w.mallory, read_file());
    let chain = [w.alice_bob.clone(), about_mallory.clone()];
    let inv = signed_by(&w.bob, about_mallory.cid(), &w.alice.did());
    assert!(matches!(
        check(&w.alice.did(), &inv, &chain),
        Err(RevocationError::Invalid(ValidationError::SubjectMismatch {
            hop: Hop::Proof(1)
        }))
    ));
}

#[test]
fn a_chain_with_a_gap_is_refused() {
    let w = World::new();
    let chain = [w.alice_bob.clone(), w.carol_dan.clone()];
    let inv = signed_by(&w.carol, w.carol_dan.cid(), &w.alice.did());
    assert!(matches!(
        check(&w.alice.did(), &inv, &chain),
        Err(RevocationError::Invalid(
            ValidationError::PrincipalMismatch {
                hop: Hop::Proof(0),
                ..
            }
        ))
    ));
}

/// A grant of something else gives no standing over a delegation of this.
#[test]
fn a_chain_whose_commands_do_not_line_up_is_refused() {
    let w = World::new();
    let unrelated_grant = delegate(&w.alice, &w.mallory, &w.alice, cmd("/msg/send"));
    let mallory_bob = delegate(&w.mallory, &w.bob, &w.alice, cmd("/msg/send"));
    let chain = [unrelated_grant, mallory_bob, w.bob_carol.clone()];
    let inv = signed_by(&w.mallory, w.bob_carol.cid(), &w.alice.did());
    assert!(matches!(
        check(&w.alice.did(), &inv, &chain),
        Err(RevocationError::Invalid(
            ValidationError::CommandNotCovered {
                hop: Hop::Proof(1),
                ..
            }
        ))
    ));
}

/// What the check cannot see. Mallory really holds this command from Alice, and
/// signing to Bob needs nobody's consent, so her path looks like any other. It
/// is reported, and a careful caller can refuse it. See `docs/validation.md`.
#[test]
fn overlapping_authority_can_present_a_path_and_is_reported() {
    let w = World::new();
    let alice_mallory = delegate(&w.alice, &w.mallory, &w.alice, read_file());
    let mallory_bob = delegate(&w.mallory, &w.bob, &w.alice, read_file());
    let chain = [alice_mallory, mallory_bob, w.bob_carol.clone()];
    let inv = signed_by(&w.mallory, w.bob_carol.cid(), &w.alice.did());
    let accepted = check(&w.alice.did(), &inv, &chain).unwrap();
    assert_eq!(accepted.hop(), 1);
    assert!(accepted.rests_on_intermediate_issuer());
}

#[test]
fn a_revocation_signed_by_someone_else_is_refused() {
    let w = World::new();
    let unsigned = revoking(w.bob_carol.cid(), &w.alice.did())
        .prepare(w.bob.did(), Algorithm::Ed25519)
        .unwrap();
    let signature = w.mallory.sign(unsigned.signing_bytes()).unwrap();
    let forged = Invocation::assemble(unsigned.signing_bytes(), signature.as_bytes()).unwrap();
    assert_eq!(forged.issuer(), &w.bob.did());
    assert!(matches!(
        check(&w.alice.did(), &forged, &w.to_carol()),
        Err(RevocationError::Invalid(ValidationError::BadSignature {
            hop: Hop::Invocation
        }))
    ));
}

#[test]
fn a_chain_with_a_forged_delegation_is_refused() {
    let w = World::new();
    let unsigned = Delegation::builder(w.mallory.did(), Subject::Did(w.alice.did()), read_file())
        .nonce(Nonce::from_bytes(&[1; 12]))
        .expires_at(now().plus_seconds(3600))
        .prepare(w.alice.did(), Algorithm::Ed25519)
        .unwrap();
    let signature = w.mallory.sign(unsigned.signing_bytes()).unwrap();
    let forged = Delegation::assemble(unsigned.signing_bytes(), signature.as_bytes()).unwrap();
    let mallory_bob = delegate(&w.mallory, &w.bob, &w.alice, read_file());
    let chain = [forged, mallory_bob, w.bob_carol.clone()];
    let inv = signed_by(&w.mallory, w.bob_carol.cid(), &w.alice.did());
    assert!(matches!(
        check(&w.alice.did(), &inv, &chain),
        Err(RevocationError::Invalid(ValidationError::BadSignature {
            hop: Hop::Proof(0)
        }))
    ));
}

#[test]
fn an_expired_revocation_is_refused_and_null_expiry_is_not() {
    let w = World::new();
    let target = w.bob_carol.cid();
    let build = || {
        Invocation::builder(w.alice.did(), revoke())
            .arg("revoke", Ipld::Link(*target))
            .nonce(Nonce::empty())
    };
    let expired = build()
        .expires_at(now().minus_seconds(3600))
        .sign(&w.bob)
        .unwrap();
    assert!(matches!(
        check(&w.alice.did(), &expired, &w.to_carol()),
        Err(RevocationError::Invalid(ValidationError::Expired {
            hop: Hop::Invocation,
            ..
        }))
    ));
    let lasting = build().never_expires().sign(&w.bob).unwrap();
    assert!(check(&w.alice.did(), &lasting, &w.to_carol()).is_ok());
}

/// A revoker who has lost their authority must not be able to take others down
/// with them.
#[test]
fn a_revoker_whose_own_authority_expired_is_refused() {
    let w = World::new();
    let lapsed = Delegation::builder(w.bob.did(), Subject::Did(w.alice.did()), read_file())
        .nonce(Nonce::from_bytes(&[2; 12]))
        .expires_at(now().minus_seconds(3600))
        .sign(&w.alice)
        .unwrap();
    let chain = [lapsed, w.bob_carol.clone()];
    let inv = signed_by(&w.bob, w.bob_carol.cid(), &w.alice.did());
    assert!(matches!(
        check(&w.alice.did(), &inv, &chain),
        Err(RevocationError::Invalid(ValidationError::Expired {
            hop: Hop::Proof(0),
            ..
        }))
    ));
}

#[test]
fn a_revoker_whose_own_authority_was_revoked_is_refused() {
    let w = World::new();
    let mut revoked = MemoryRevocationStore::new();
    revoked.revoke(*w.alice_bob.cid());
    let inv = signed_by(&w.bob, w.bob_carol.cid(), &w.alice.did());
    assert!(matches!(
        Validator::new(&MemoryStore::new(), now())
            .revocations(&revoked)
            .check_revocation(&w.alice.did(), &inv, &w.to_carol()),
        Err(RevocationError::Invalid(ValidationError::Revoked { hop: Hop::Proof(0), cid }))
            if cid == *w.alice_bob.cid()
    ));
}

#[test]
fn a_delegation_that_lapsed_or_has_not_begun_can_still_be_revoked() {
    let w = World::new();
    let lapsed = Delegation::builder(w.carol.did(), Subject::Did(w.alice.did()), read_file())
        .nonce(Nonce::from_bytes(&[4; 12]))
        .expires_at(now().minus_seconds(3600))
        .sign(&w.bob)
        .unwrap();
    let not_begun = Delegation::builder(w.carol.did(), Subject::Did(w.alice.did()), read_file())
        .nonce(Nonce::from_bytes(&[5; 12]))
        .not_before(now().plus_seconds(3600))
        .expires_at(now().plus_seconds(7200))
        .sign(&w.bob)
        .unwrap();
    for target in [lapsed, not_begun] {
        let chain = [w.alice_bob.clone(), target.clone()];
        let inv = signed_by(&w.bob, target.cid(), &w.alice.did());
        assert!(check(&w.alice.did(), &inv, &chain).is_ok());
    }
}

#[test]
fn another_command_is_not_a_revocation() {
    let w = World::new();
    let inv = Invocation::builder(w.alice.did(), read_file())
        .arg("revoke", Ipld::Link(*w.bob_carol.cid()))
        .nonce(Nonce::empty())
        .expires_at(now().plus_seconds(60))
        .sign(&w.bob)
        .unwrap();
    assert!(matches!(
        check(&w.alice.did(), &inv, &w.to_carol()),
        Err(RevocationError::NotARevocation(command)) if command == read_file()
    ));
}

#[test]
fn the_older_command_spelling_does_not_parse() {
    assert!(Command::parse("ucan/revoke").is_err());
}

#[test]
fn arguments_are_read_strictly() {
    let w = World::new();
    let with = |args: Vec<(&str, Ipld)>| {
        let mut builder = Invocation::builder(w.alice.did(), revoke());
        for (name, value) in args {
            builder = builder.arg(name, value);
        }
        builder
            .nonce(Nonce::empty())
            .expires_at(now().plus_seconds(60))
            .sign(&w.bob)
            .unwrap()
    };
    let link = Ipld::Link(*w.bob_carol.cid());

    assert!(matches!(
        Revocation::read(&with(vec![])),
        Err(RevocationError::MissingTarget)
    ));
    assert!(matches!(
        Revocation::read(&with(vec![("revoke", Ipld::String("cid".into()))])),
        Err(RevocationError::MalformedArgument("revoke"))
    ));
    assert!(matches!(
        Revocation::read(&with(vec![
            ("revoke", link.clone()),
            ("path", link.clone())
        ])),
        Err(RevocationError::MalformedArgument("path"))
    ));
    assert!(matches!(
        Revocation::read(&with(vec![
            ("revoke", link.clone()),
            ("path", Ipld::List(vec![Ipld::Null]))
        ])),
        Err(RevocationError::MalformedArgument("path"))
    ));
    // The names in the specification's schema file, which its text does not use.
    assert!(matches!(
        Revocation::read(&with(vec![("rev", link.clone())])),
        Err(RevocationError::UnknownArgument(name)) if name == "rev"
    ));
    assert!(matches!(
        Revocation::read(&with(vec![("revoke", link.clone()), ("pth", Ipld::List(vec![]))])),
        Err(RevocationError::UnknownArgument(name)) if name == "pth"
    ));

    let read = Revocation::read(&with(vec![("revoke", link)])).unwrap();
    assert_eq!(read.target(), w.bob_carol.cid());
    assert_eq!(read.path(), None);
}

#[test]
fn the_target_must_be_named_by_its_own_cid() {
    const RAW: u64 = 0x55;
    let w = World::new();
    let alias = Cid::new_v1(RAW, *w.bob_carol.cid().hash());
    let inv = signed_by(&w.bob, &alias, &w.alice.did());
    assert!(matches!(
        check(&w.alice.did(), &inv, &w.to_carol()),
        Err(RevocationError::WrongTarget { named, .. }) if named == alias
    ));
}

#[test]
fn a_path_must_list_the_chain_root_first() {
    let w = World::new();
    let link = |d: &Delegation| Ipld::Link(*d.cid());
    let with_path = |path: Vec<Ipld>| {
        revoking(w.bob_carol.cid(), &w.alice.did())
            .arg("path", Ipld::List(path))
            .sign(&w.bob)
            .unwrap()
    };

    let good = with_path(vec![link(&w.alice_bob), link(&w.bob_carol)]);
    assert_eq!(
        Revocation::read(&good).unwrap().path().unwrap(),
        [*w.alice_bob.cid(), *w.bob_carol.cid()]
    );
    assert!(check(&w.alice.did(), &good, &w.to_carol()).is_ok());

    for path in [
        vec![link(&w.bob_carol), link(&w.alice_bob)],
        vec![link(&w.bob_carol)],
        vec![],
    ] {
        assert!(matches!(
            check(&w.alice.did(), &with_path(path), &w.to_carol()),
            Err(RevocationError::PathMismatch)
        ));
    }
}

#[test]
fn an_empty_chain_is_refused() {
    let w = World::new();
    let inv = signed_by(&w.alice, w.bob_carol.cid(), &w.alice.did());
    assert!(matches!(
        check(&w.alice.did(), &inv, &[]),
        Err(RevocationError::Invalid(ValidationError::EmptyChain))
    ));
}

#[test]
fn the_proof_limit_applies_to_the_chain() {
    let w = World::new();
    let inv = signed_by(&w.bob, w.bob_carol.cid(), &w.alice.did());
    assert!(matches!(
        Validator::new(&MemoryStore::new(), now())
            .max_proofs(1)
            .check_revocation(&w.alice.did(), &inv, &w.to_carol()),
        Err(RevocationError::Invalid(ValidationError::TooManyProofs {
            count: 2,
            max: 1
        }))
    ));
}

/// The grant and a revocation under it, through their bytes, as they would
/// arrive.
fn over_the_wire(grant: &Delegation, inv: &Invocation) -> (MemoryStore, Invocation) {
    let mut store = MemoryStore::new();
    store.insert(Delegation::decode(grant.bytes()).unwrap());
    (store, Invocation::decode(inv.bytes()).unwrap())
}

fn grant_of(
    from: &Ed25519Keypair,
    to: &Ed25519Keypair,
    subject: &Ed25519Keypair,
    command: Command,
    policy: Policy,
) -> Delegation {
    Delegation::builder(to.did(), Subject::Did(subject.did()), command)
        .policy(policy)
        .nonce(Nonce::from_bytes(&[8; 12]))
        .expires_at(now().plus_seconds(3600))
        .sign(from)
        .unwrap()
}

#[test]
fn a_holder_of_delegated_revoke_may_revoke_what_it_names() {
    let w = World::new();
    let target = w.bob_carol.cid();
    let grant = grant_of(&w.alice, &w.zelda, &w.alice, revoke(), only_this(target));
    let inv = revoking(target, &w.alice.did())
        .proof(*grant.cid())
        .sign(&w.zelda)
        .unwrap();
    let (store, inv) = over_the_wire(&grant, &inv);

    let accepted = Validator::new(&store, now())
        .check_revocation(&w.alice.did(), &inv, &w.to_carol())
        .unwrap();
    assert!(accepted.is_delegated());
    assert_eq!(accepted.hop(), 0);
    assert_eq!(accepted.revoker(), &w.zelda.did());
    assert!(!accepted.rests_on_intermediate_issuer());
}

#[test]
fn a_wider_command_carries_revoke() {
    let w = World::new();
    let target = w.bob_carol.cid();
    for command in [cmd("/ucan"), Command::root()] {
        let grant = grant_of(&w.alice, &w.zelda, &w.alice, command, Policy::default());
        let inv = revoking(target, &w.alice.did())
            .proof(*grant.cid())
            .sign(&w.zelda)
            .unwrap();
        let (store, inv) = over_the_wire(&grant, &inv);
        assert!(Validator::new(&store, now())
            .check_revocation(&w.alice.did(), &inv, &w.to_carol())
            .is_ok());
    }
}

/// `sub` says whose right is being used. Bob can hand on his own right to
/// revoke, in a chain rooted in Bob, though he holds no `/ucan/revoke` from
/// Alice.
#[test]
fn an_intermediate_issuer_may_hand_on_its_own_right() {
    let w = World::new();
    let target = w.bob_carol.cid();
    let grant = grant_of(&w.bob, &w.zelda, &w.bob, revoke(), only_this(target));
    let inv = revoking(target, &w.bob.did())
        .proof(*grant.cid())
        .sign(&w.zelda)
        .unwrap();
    let (store, inv) = over_the_wire(&grant, &inv);
    let accepted = Validator::new(&store, now())
        .check_revocation(&w.alice.did(), &inv, &w.to_carol())
        .unwrap();
    assert!(accepted.is_delegated());
    assert_eq!(accepted.hop(), 1);
}

/// With the subject check gone this is the attack: Mallory roots a perfectly
/// good `/ucan/revoke` chain in herself.
#[test]
fn a_grant_from_outside_the_chain_is_refused() {
    let w = World::new();
    let target = w.bob_carol.cid();
    let grant = grant_of(
        &w.mallory,
        &w.zelda,
        &w.mallory,
        revoke(),
        only_this(target),
    );
    let inv = revoking(target, &w.mallory.did())
        .proof(*grant.cid())
        .sign(&w.zelda)
        .unwrap();
    let (store, inv) = over_the_wire(&grant, &inv);
    assert!(matches!(
        Validator::new(&store, now()).check_revocation(&w.alice.did(), &inv, &w.to_carol()),
        Err(RevocationError::SubjectNotInChain { subject }) if subject == w.mallory.did()
    ));
}

#[test]
fn a_grant_not_rooted_in_the_named_subject_is_refused() {
    let w = World::new();
    let target = w.bob_carol.cid();
    let grant = grant_of(&w.mallory, &w.zelda, &w.alice, revoke(), only_this(target));
    let inv = revoking(target, &w.alice.did())
        .proof(*grant.cid())
        .sign(&w.zelda)
        .unwrap();
    let (store, inv) = over_the_wire(&grant, &inv);
    assert!(matches!(
        Validator::new(&store, now()).check_revocation(&w.alice.did(), &inv, &w.to_carol()),
        Err(RevocationError::Grant(
            ValidationError::RootNotSubject { .. }
        ))
    ));
}

#[test]
fn a_grant_for_another_delegation_is_refused() {
    let w = World::new();
    let grant = grant_of(
        &w.alice,
        &w.zelda,
        &w.alice,
        revoke(),
        only_this(w.alice_bob.cid()),
    );
    let inv = revoking(w.bob_carol.cid(), &w.alice.did())
        .proof(*grant.cid())
        .sign(&w.zelda)
        .unwrap();
    let (store, inv) = over_the_wire(&grant, &inv);
    assert!(matches!(
        Validator::new(&store, now()).check_revocation(&w.alice.did(), &inv, &w.to_carol()),
        Err(RevocationError::Grant(ValidationError::PolicyRejected {
            hop: Hop::Proof(0),
            statement: 0
        }))
    ));
}

#[test]
fn a_grant_of_another_command_is_refused() {
    let w = World::new();
    let grant = grant_of(&w.alice, &w.zelda, &w.alice, read_file(), Policy::default());
    let inv = revoking(w.bob_carol.cid(), &w.alice.did())
        .proof(*grant.cid())
        .sign(&w.zelda)
        .unwrap();
    let (store, inv) = over_the_wire(&grant, &inv);
    assert!(matches!(
        Validator::new(&store, now()).check_revocation(&w.alice.did(), &inv, &w.to_carol()),
        Err(RevocationError::Grant(
            ValidationError::CommandNotCovered { .. }
        ))
    ));
}

#[test]
fn a_grant_to_someone_else_is_refused() {
    let w = World::new();
    let grant = grant_of(&w.alice, &w.bob, &w.alice, revoke(), Policy::default());
    let inv = revoking(w.bob_carol.cid(), &w.alice.did())
        .proof(*grant.cid())
        .sign(&w.zelda)
        .unwrap();
    let (store, inv) = over_the_wire(&grant, &inv);
    assert!(matches!(
        Validator::new(&store, now()).check_revocation(&w.alice.did(), &inv, &w.to_carol()),
        Err(RevocationError::Grant(
            ValidationError::PrincipalMismatch { .. }
        ))
    ));
}

#[test]
fn a_grant_the_store_does_not_hold_is_refused() {
    let w = World::new();
    let grant = grant_of(&w.alice, &w.zelda, &w.alice, revoke(), Policy::default());
    let inv = revoking(w.bob_carol.cid(), &w.alice.did())
        .proof(*grant.cid())
        .sign(&w.zelda)
        .unwrap();
    assert!(matches!(
        check(&w.alice.did(), &inv, &w.to_carol()),
        Err(RevocationError::Grant(ValidationError::MissingProof(cid))) if cid == *grant.cid()
    ));
}

#[test]
fn an_expired_grant_is_refused() {
    let w = World::new();
    let grant = Delegation::builder(w.zelda.did(), Subject::Did(w.alice.did()), revoke())
        .nonce(Nonce::from_bytes(&[6; 12]))
        .expires_at(now().minus_seconds(3600))
        .sign(&w.alice)
        .unwrap();
    let inv = revoking(w.bob_carol.cid(), &w.alice.did())
        .proof(*grant.cid())
        .sign(&w.zelda)
        .unwrap();
    let (store, inv) = over_the_wire(&grant, &inv);
    assert!(matches!(
        Validator::new(&store, now()).check_revocation(&w.alice.did(), &inv, &w.to_carol()),
        Err(RevocationError::Grant(ValidationError::Expired {
            hop: Hop::Proof(0),
            ..
        }))
    ));
}

#[test]
fn a_revoked_grant_is_refused() {
    let w = World::new();
    let grant = grant_of(&w.alice, &w.zelda, &w.alice, revoke(), Policy::default());
    let inv = revoking(w.bob_carol.cid(), &w.alice.did())
        .proof(*grant.cid())
        .sign(&w.zelda)
        .unwrap();
    let (store, inv) = over_the_wire(&grant, &inv);
    let mut revoked = MemoryRevocationStore::new();
    revoked.revoke(*grant.cid());
    assert!(matches!(
        Validator::new(&store, now())
            .revocations(&revoked)
            .check_revocation(&w.alice.did(), &inv, &w.to_carol()),
        Err(RevocationError::Grant(ValidationError::Revoked { .. }))
    ));
}

#[test]
fn the_proof_limit_applies_to_the_grant() {
    let w = World::new();
    let mallory_grant = grant_of(&w.alice, &w.mallory, &w.alice, revoke(), Policy::default());
    let grant = grant_of(&w.mallory, &w.zelda, &w.alice, revoke(), Policy::default());
    let inv = revoking(w.alice_bob.cid(), &w.alice.did())
        .proofs([*mallory_grant.cid(), *grant.cid()])
        .sign(&w.zelda)
        .unwrap();
    let mut store = MemoryStore::new();
    store.insert(mallory_grant);
    store.insert(grant);
    let chain = [w.alice_bob.clone()];

    let limited = Validator::new(&store, now()).max_proofs(1);
    assert!(matches!(
        limited.check_revocation(&w.alice.did(), &inv, &chain),
        Err(RevocationError::Grant(ValidationError::TooManyProofs {
            count: 2,
            max: 1
        }))
    ));
    assert!(Validator::new(&store, now())
        .max_proofs(2)
        .check_revocation(&w.alice.did(), &inv, &chain)
        .is_ok());
}

#[test]
fn the_skew_applies_to_the_grant() {
    let w = World::new();
    let grant = Delegation::builder(w.zelda.did(), Subject::Did(w.alice.did()), revoke())
        .nonce(Nonce::from_bytes(&[6; 12]))
        .expires_at(now().minus_seconds(30))
        .sign(&w.alice)
        .unwrap();
    let inv = revoking(w.bob_carol.cid(), &w.alice.did())
        .proof(*grant.cid())
        .sign(&w.zelda)
        .unwrap();
    let (store, inv) = over_the_wire(&grant, &inv);
    assert!(Validator::new(&store, now())
        .check_revocation(&w.alice.did(), &inv, &w.to_carol())
        .is_ok());
    assert!(matches!(
        Validator::new(&store, now())
            .skew(0)
            .check_revocation(&w.alice.did(), &inv, &w.to_carol()),
        Err(RevocationError::Grant(ValidationError::Expired { .. }))
    ));
}

struct Refusing(Did);

impl Resolver for Refusing {
    fn resolve(&self, did: &Did) -> Result<PublicKey, ResolveError> {
        if did.same_principal(&self.0) {
            return Err(ResolveError::NotFound);
        }
        KeyResolver.resolve(did)
    }
}

#[test]
fn the_resolver_applies_to_the_grant() {
    let w = World::new();
    let mallory_grant = grant_of(&w.alice, &w.mallory, &w.alice, revoke(), Policy::default());
    let grant = grant_of(&w.mallory, &w.zelda, &w.alice, revoke(), Policy::default());
    let inv = revoking(w.bob_carol.cid(), &w.alice.did())
        .proofs([*mallory_grant.cid(), *grant.cid()])
        .sign(&w.zelda)
        .unwrap();
    let mut store = MemoryStore::new();
    store.insert(mallory_grant);
    store.insert(grant);
    let refusing = Refusing(w.mallory.did());
    assert!(matches!(
        Validator::new(&store, now())
            .resolver(&refusing)
            .check_revocation(&w.alice.did(), &inv, &w.to_carol()),
        Err(RevocationError::Grant(ValidationError::Unresolvable {
            hop: Hop::Proof(1),
            ..
        }))
    ));
}

/// An issuer's right comes from the chain, so `prf` adds nothing to it. The
/// specification's example carries both.
#[test]
fn an_issuer_does_not_need_its_proofs_to_resolve() {
    let w = World::new();
    let inv = revoking(w.bob_carol.cid(), &w.alice.did())
        .proof(*w.carol_dan.cid())
        .sign(&w.bob)
        .unwrap();
    assert!(check(&w.alice.did(), &inv, &w.to_carol()).is_ok());
}

#[test]
fn checking_twice_is_fine_because_revocation_is_idempotent() {
    let w = World::new();
    let inv = signed_by(&w.bob, w.bob_carol.cid(), &w.alice.did());
    let store = MemoryStore::new();
    let mut guard = MemoryReplayGuard::new();
    let validator = Validator::new(&store, now()).replay_guard(&mut guard);
    assert!(validator
        .check_revocation(&w.alice.did(), &inv, &w.to_carol())
        .is_ok());
    assert!(validator
        .check_revocation(&w.alice.did(), &inv, &w.to_carol())
        .is_ok());
}

#[test]
fn an_accepted_revocation_fills_the_store_and_cuts_off_the_chain() {
    let w = World::new();
    let proofs = {
        let mut store = MemoryStore::new();
        store.insert(w.alice_bob.clone());
        store.insert(w.bob_carol.clone());
        store
    };
    let use_it = Invocation::builder(w.alice.did(), read_file())
        .proofs([*w.alice_bob.cid(), *w.bob_carol.cid()])
        .nonce(Nonce::from_bytes(&[7; 12]))
        .expires_at(now().plus_seconds(60))
        .sign(&w.carol)
        .unwrap();

    let mut revoked = MemoryRevocationStore::new();
    assert!(Validator::new(&proofs, now())
        .revocations(&revoked)
        .validate(&use_it)
        .is_ok());

    let revocation = signed_by(&w.bob, w.bob_carol.cid(), &w.alice.did());
    let accepted = Validator::new(&proofs, now())
        .check_revocation(&w.alice.did(), &revocation, &w.to_carol())
        .unwrap();
    revoked.revoke(*accepted.target());

    assert!(matches!(
        Validator::new(&proofs, now()).revocations(&revoked).validate(&use_it),
        Err(ValidationError::Revoked { hop: Hop::Proof(1), cid }) if cid == *w.bob_carol.cid()
    ));
}
