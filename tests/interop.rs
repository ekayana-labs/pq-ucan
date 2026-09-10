//! Interoperability: the working group's fixture, and byte level round
//! trips for every algorithm.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use pq_ucan::{
    cid,
    command::Command,
    crypto::{
        ed25519::Ed25519Keypair, p256::P256Keypair, secp256k1::Secp256k1Keypair, Algorithm, Signer,
    },
    delegation::{Delegation, Subject},
    did::{Did, KeyResolver},
    envelope::{DecodeOptions, EnvelopeError},
    invocation::Invocation,
    nonce::Nonce,
    time::{Expiry, Timestamp},
    Error, Ipld,
};

/// The delegation fixture from rs-ucan's test suite: an rc.1 powerline
/// delegation signed with Ed25519 by the JavaScript implementation.
const FIXTURE_HEX: &str = "825840d2b89cb798709e25e7879e18edbd2ffd910335294f741c74aeca160d80b6625bfe5330ebd34b3ba233ec7ef370ae87ea288b4af75d5918982065291e4080770ea26168483401ed01ed011371737563616e2f646c6740312e302e302d72632e31a96361756478386469643a6b65793a7a364d6b66464a4278534246676f417154514c533762546650384d67794479707661356936434c35504a4e38524a5a7263636d64612f63657870f66369737378386469643a6b65793a7a364d6b72417371314d3774456650765735645232554643775a537a524d4e58596554573874475a534b76556d39455a636e62661a6924f1a763706f6c8063737562f6646d657461a0656e6f6e63654c5640c579a6fee7ca7c48ca56";
const FIXTURE_CID: &str = "zdpuArQp5MJCq5msG542vnzaNHnx2AUyb8U7FqqRGBhV1dGX9";

fn fixture() -> Vec<u8> {
    hex::decode(FIXTURE_HEX).unwrap()
}

fn now() -> Timestamp {
    Timestamp::from_unix(1_800_000_000).unwrap()
}

fn rc1() -> DecodeOptions {
    DecodeOptions::STRICT.release_candidate_tags(true)
}

#[test]
fn released_tags_only_unless_asked() {
    let err = Delegation::decode(&fixture()).unwrap_err();
    assert!(
        matches!(err, Error::Envelope(EnvelopeError::UnknownTag(tag)) if tag == "ucan/dlg@1.0.0-rc.1")
    );
    assert!(Delegation::decode_with(&fixture(), rc1()).is_ok());
}

#[test]
fn working_group_fixture_decodes_and_verifies() {
    let bytes = fixture();
    let dlg = Delegation::decode_with(&bytes, rc1()).unwrap();
    assert_eq!(
        dlg.issuer().as_str(),
        "did:key:z6MkrAsq1M7tEfPvW5dR2UFCwZSzRMNXYeTW8tGZSKvUm9EZ"
    );
    assert_eq!(
        dlg.audience().as_str(),
        "did:key:z6MkfFJBxSBFgoAqTQLS7bTfP8MgyDypva5i6CL5PJN8RJZr"
    );
    assert_eq!(dlg.subject(), &Subject::Powerline);
    assert!(dlg.command().is_root());
    assert!(dlg.policy().is_empty());
    assert_eq!(dlg.expiration(), Expiry::Never);
    assert_eq!(
        dlg.not_before(),
        Some(Timestamp::from_unix(1_764_028_839).unwrap())
    );
    assert!(dlg.meta().is_empty());
    assert_eq!(
        hex::encode(dlg.nonce().as_bytes()),
        "5640c579a6fee7ca7c48ca56"
    );
    assert_eq!(dlg.algorithm(), Algorithm::Ed25519);
    assert_eq!(
        hex::encode(dlg.envelope().header().encode()),
        "3401ed01ed011371"
    );
    assert_eq!(dlg.bytes(), bytes.as_slice());
    assert_eq!(cid::to_base58btc(dlg.cid()), FIXTURE_CID);
    dlg.verify(&KeyResolver).unwrap();
}

#[test]
fn a_flipped_byte_still_decodes_but_no_longer_verifies() {
    let mut bytes = fixture();
    // The nonce is the last field, so the last byte is signed content that
    // stays valid CBOR when changed.
    if let Some(last) = bytes.last_mut() {
        *last ^= 0x01;
    }
    let dlg = Delegation::decode_with(&bytes, rc1()).unwrap();
    assert_ne!(cid::to_base58btc(dlg.cid()), FIXTURE_CID);
    assert!(matches!(dlg.verify(&KeyResolver), Err(Error::Crypto(_))));
}

#[test]
fn a_delegation_is_not_an_invocation() {
    let err = Invocation::decode_with(&fixture(), rc1()).unwrap_err();
    assert!(matches!(
        err,
        Error::Envelope(EnvelopeError::WrongKind { .. })
    ));
}

fn round_trip(signer: &impl Signer, header: &str, did_prefix: &str) {
    let audience = Did::parse("did:key:z6MkfFJBxSBFgoAqTQLS7bTfP8MgyDypva5i6CL5PJN8RJZr").unwrap();
    let dlg = Delegation::builder(
        audience,
        Subject::Did(signer.did()),
        Command::parse("/crud/read").unwrap(),
    )
    .nonce(Nonce::from_bytes(&[7; 12]))
    .expires_at(now())
    .sign(signer)
    .unwrap();
    assert!(
        signer.did().as_str().starts_with(did_prefix),
        "{}",
        signer.did()
    );
    assert_eq!(hex::encode(dlg.envelope().header().encode()), header);
    assert_eq!(dlg.issuer(), &signer.did());

    let decoded = Delegation::decode(dlg.bytes()).unwrap();
    assert_eq!(decoded.payload(), dlg.payload());
    assert_eq!(decoded.cid(), dlg.cid());
    assert_eq!(decoded.cid(), &cid::of_dag_cbor(dlg.bytes()));
    decoded.verify(&KeyResolver).unwrap();

    // The same bytes under another key do not verify.
    let stranger = Ed25519Keypair::from_seed(&[42; 32]);
    assert!(decoded.envelope().verify(stranger.public_key()).is_err());
}

#[test]
fn ed25519_round_trip() {
    round_trip(
        &Ed25519Keypair::from_seed(&[1; 32]),
        "3401ed01ed011371",
        "did:key:z6Mk",
    );
}

#[test]
fn p256_round_trip() {
    round_trip(
        &P256Keypair::from_bytes(&[2; 32]).unwrap(),
        "3401ec0180241271",
        "did:key:zDn",
    );
}

#[test]
fn secp256k1_round_trip() {
    round_trip(
        &Secp256k1Keypair::from_bytes(&[3; 32]).unwrap(),
        "3401ec01e7011271",
        "did:key:zQ3s",
    );
}

#[cfg(feature = "ml-dsa")]
#[test]
fn ml_dsa_round_trips() {
    use pq_ucan::crypto::ml_dsa::MlDsaKeypair;
    for (algorithm, header) in [
        (Algorithm::MlDsa44, "3401902471"),
        (Algorithm::MlDsa65, "3401912471"),
        (Algorithm::MlDsa87, "3401922471"),
    ] {
        let key = MlDsaKeypair::from_seed(algorithm, &[4; 32]).unwrap();
        round_trip(&key, header, "did:key:z");
    }
}

#[test]
fn invocation_wire_rules() {
    let alice = Ed25519Keypair::from_seed(&[1; 32]);
    let bob = Ed25519Keypair::from_seed(&[2; 32]);
    let inv = Invocation::builder(alice.did(), Command::parse("/crud/read").unwrap())
        // Equal to the subject, so it must not appear on the wire.
        .audience(alice.did())
        .arg("table", Ipld::String("posts".into()))
        .nonce(Nonce::empty())
        .expires_at(now())
        .sign(&bob)
        .unwrap();
    assert_eq!(inv.audience(), None);
    assert_eq!(inv.executor(), &alice.did());
    assert!(inv.meta().is_empty());

    let decoded = Invocation::decode(inv.bytes()).unwrap();
    assert_eq!(decoded.payload(), inv.payload());
    decoded.verify(&KeyResolver).unwrap();

    // Canonical key order on the wire: keys of three letters, then `args`,
    // then `nonce`; no `aud`, no `meta`.
    let at = |key: &[u8]| {
        inv.bytes()
            .windows(key.len())
            .position(|w| w == key)
            .unwrap()
    };
    assert!(at(b"\x63cmd") < at(b"\x63iss"));
    assert!(at(b"\x63sub") < at(b"\x64args"));
    assert!(at(b"\x64args") < at(b"\x65nonce"));
    assert!(inv.bytes().windows(4).all(|w| w != b"\x63aud"));
    assert!(inv.bytes().windows(5).all(|w| w != b"\x64meta"));
}

#[test]
fn task_id_depends_only_on_the_task() {
    let alice = Ed25519Keypair::from_seed(&[1; 32]);
    let bob = Ed25519Keypair::from_seed(&[2; 32]);
    let build = |nonce: Nonce, exp: Timestamp| {
        Invocation::builder(alice.did(), Command::parse("/crud/read").unwrap())
            .arg("table", Ipld::String("posts".into()))
            .nonce(nonce)
            .expires_at(exp)
            .sign(&bob)
            .unwrap()
    };
    let a = build(Nonce::empty(), now());
    let b = build(Nonce::empty(), now().plus_seconds(1));
    let c = build(Nonce::from_bytes(&[1]), now());
    assert_ne!(a.cid(), b.cid());
    assert_eq!(a.task_id().unwrap(), b.task_id().unwrap());
    assert_ne!(a.task_id().unwrap(), c.task_id().unwrap());
}
