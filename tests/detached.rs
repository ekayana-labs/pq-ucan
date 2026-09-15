//! Tokens signed by a key the builder never sees: a wallet, a browser key.
//! The builder hands out the bytes to sign, the key signs them elsewhere,
//! and the assembled token is what a signer-held key would have produced.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use pq_ucan::{
    command::Command,
    crypto::{ed25519::Ed25519Keypair, Algorithm, Signer},
    delegation::{Delegation, Subject},
    did::KeyResolver,
    invocation::Invocation,
    nonce::Nonce,
    time::Timestamp,
    validate::{MemoryStore, Validator},
    Ipld,
};

fn now() -> Timestamp {
    Timestamp::from_unix(1_800_000_000).unwrap()
}

fn cmd(s: &str) -> Command {
    Command::parse(s).unwrap()
}

#[test]
fn a_prepared_delegation_equals_a_signed_one() {
    let wallet = Ed25519Keypair::from_seed(&[7; 32]);
    let bob = Ed25519Keypair::from_seed(&[8; 32]);
    let build = || {
        Delegation::builder(bob.did(), Subject::Did(wallet.did()), cmd("/file/read"))
            .nonce(Nonce::from_bytes(&[1; 12]))
            .expires_at(now().plus_seconds(3600))
    };

    let signed = build().sign(&wallet).unwrap();
    let unsigned = build().prepare(wallet.did(), Algorithm::Ed25519).unwrap();
    // The wallet signs the bytes on its own and hands the signature back.
    let signature = wallet.sign(unsigned.signing_bytes()).unwrap();
    let assembled = Delegation::assemble(unsigned.signing_bytes(), signature.as_bytes()).unwrap();

    assert_eq!(assembled.bytes(), signed.bytes());
    assert_eq!(assembled.cid(), signed.cid());
    assert_eq!(assembled.issuer(), &wallet.did());
    assembled.verify(&KeyResolver).unwrap();
}

#[test]
fn a_wrong_key_or_a_tampered_payload_is_caught() {
    let wallet = Ed25519Keypair::from_seed(&[7; 32]);
    let stranger = Ed25519Keypair::from_seed(&[9; 32]);
    let bob = Ed25519Keypair::from_seed(&[8; 32]);
    let unsigned = Delegation::builder(bob.did(), Subject::Did(wallet.did()), cmd("/file/read"))
        .nonce(Nonce::from_bytes(&[1; 12]))
        .expires_at(now().plus_seconds(3600))
        .prepare(wallet.did(), Algorithm::Ed25519)
        .unwrap();

    // Another key's signature assembles (the shape is fine) but never verifies.
    let forged = stranger.sign(unsigned.signing_bytes()).unwrap();
    let token = Delegation::assemble(unsigned.signing_bytes(), forged.as_bytes()).unwrap();
    assert!(token.verify(&KeyResolver).is_err());

    // A signature of the wrong size is not a token at all.
    assert!(Delegation::assemble(unsigned.signing_bytes(), &[0; 63]).is_err());

    // Bytes altered after signing fail verification.
    let signature = wallet.sign(unsigned.signing_bytes()).unwrap();
    let mut altered = unsigned.signing_bytes().to_vec();
    if let Some(last) = altered.last_mut() {
        *last ^= 1;
    }
    if let Ok(token) = Delegation::assemble(&altered, signature.as_bytes()) {
        assert!(token.verify(&KeyResolver).is_err());
    }

    // Delegation bytes are not an invocation.
    assert!(Invocation::assemble(unsigned.signing_bytes(), signature.as_bytes()).is_err());
}

#[test]
fn a_browser_key_invokes_through_a_wallet_signed_chain() {
    let owner = Ed25519Keypair::from_seed(&[1; 32]);
    let recipient_wallet = Ed25519Keypair::from_seed(&[2; 32]);
    let session = Ed25519Keypair::from_seed(&[3; 32]);
    let service = Ed25519Keypair::from_seed(&[4; 32]);

    // The owner's wallet grants the recipient's wallet, which grants a
    // short-lived browser key; each signature is produced away from the
    // builder. A leaf may only narrow, so the browser key gets the exact
    // command it will invoke.
    let share = Delegation::builder(
        recipient_wallet.did(),
        Subject::Did(owner.did()),
        cmd("/file/read"),
    )
    .nonce(Nonce::from_bytes(&[1; 12]))
    .expires_at(now().plus_seconds(86_400))
    .prepare(owner.did(), Algorithm::Ed25519)
    .unwrap();
    let share = Delegation::assemble(
        share.signing_bytes(),
        owner.sign(share.signing_bytes()).unwrap().as_bytes(),
    )
    .unwrap();

    let session_grant = Delegation::builder(session.did(), Subject::Powerline, cmd("/file/read"))
        .nonce(Nonce::from_bytes(&[2; 12]))
        .expires_at(now().plus_seconds(3600))
        .prepare(recipient_wallet.did(), Algorithm::Ed25519)
        .unwrap();
    let session_grant = Delegation::assemble(
        session_grant.signing_bytes(),
        recipient_wallet
            .sign(session_grant.signing_bytes())
            .unwrap()
            .as_bytes(),
    )
    .unwrap();

    let invocation = Invocation::builder(owner.did(), cmd("/file/read"))
        .audience(service.did())
        .arg("cid", Ipld::String("bafy".into()))
        .proofs([*share.cid(), *session_grant.cid()])
        .nonce(Nonce::from_bytes(&[3; 12]))
        .expires_at(now().plus_seconds(60))
        .prepare(session.did(), Algorithm::Ed25519)
        .unwrap();
    let invocation = Invocation::assemble(
        invocation.signing_bytes(),
        session.sign(invocation.signing_bytes()).unwrap().as_bytes(),
    )
    .unwrap();

    let mut store = MemoryStore::new();
    store.insert(share.clone());
    store.insert(session_grant.clone());
    Validator::new(&store, now())
        .executor(&service.did())
        .validate(&invocation)
        .unwrap();

    // The same browser key cannot widen what the wallet gave it.
    let widened = Invocation::builder(owner.did(), cmd("/file/write"))
        .audience(service.did())
        .arg("cid", Ipld::String("bafy".into()))
        .proofs([*share.cid(), *session_grant.cid()])
        .nonce(Nonce::from_bytes(&[4; 12]))
        .expires_at(now().plus_seconds(60))
        .prepare(session.did(), Algorithm::Ed25519)
        .unwrap();
    let widened = Invocation::assemble(
        widened.signing_bytes(),
        session.sign(widened.signing_bytes()).unwrap().as_bytes(),
    )
    .unwrap();
    assert!(Validator::new(&store, now())
        .executor(&service.did())
        .validate(&widened)
        .is_err());
}
