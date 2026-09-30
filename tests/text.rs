//! Tokens signed by wallets that sign only UTF-8 text. The header names
//! DAG-JSON, the key signs the canonical DAG-JSON form of the envelope's
//! second element, and the token on the wire stays DAG-CBOR.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use pq_ucan::{
    cid,
    codec::CodecError,
    command::Command,
    crypto::{ed25519::Ed25519Keypair, Algorithm, Signer},
    delegation::{Delegation, Subject, UnsignedDelegation},
    did::KeyResolver,
    invocation::Invocation,
    nonce::Nonce,
    time::Timestamp,
    validate::{MemoryStore, Validator},
    varsig::{Encoding, Header},
    Error, Ipld,
};

fn now() -> Timestamp {
    Timestamp::from_unix(1_800_000_000).unwrap()
}

fn cmd(s: &str) -> Command {
    Command::parse(s).unwrap()
}

fn text() -> Header {
    Header::new(Algorithm::Ed25519).with_encoding(Encoding::DagJson)
}

fn sign(key: &Ed25519Keypair, unsigned: &UnsignedDelegation) -> Delegation {
    let signature = key.sign(unsigned.signing_bytes()).unwrap();
    Delegation::assemble(unsigned.signing_bytes(), signature.as_bytes()).unwrap()
}

#[test]
fn a_wallet_signs_text_and_the_token_stays_cbor() {
    let wallet = Ed25519Keypair::from_seed(&[7; 32]);
    let bob = Ed25519Keypair::from_seed(&[8; 32]);
    let build = || {
        Delegation::builder(bob.did(), Subject::Did(wallet.did()), cmd("/file/read"))
            .nonce(Nonce::from_bytes(&[1; 12]))
            .expires_at(now().plus_seconds(3600))
    };

    let unsigned = build().prepare_with(wallet.did(), text()).unwrap();
    let message = std::str::from_utf8(unsigned.signing_bytes()).unwrap();
    assert!(
        message.starts_with(r#"{"h":{"/":{"bytes":"NAHtAe0BE6kC"}},"ucan/dlg@1.0.0":{"aud":"#),
        "{message}"
    );

    let token = sign(&wallet, &unsigned);
    assert_eq!(token.envelope().header(), &text());
    assert_eq!(token.cid(), &cid::of_dag_cbor(token.bytes()));
    let received = Delegation::decode(token.bytes()).unwrap();
    assert_eq!(received.payload(), token.payload());
    received.verify(&KeyResolver).unwrap();

    // A client that assembles the envelope itself gets the same token.
    let signature = token.signature().as_bytes();
    let same = Delegation::assemble(unsigned.sig_payload(), signature).unwrap();
    assert_eq!(same.bytes(), token.bytes());

    // Under DAG-CBOR the key signs the envelope element itself.
    let binary = build().prepare(wallet.did(), Algorithm::Ed25519).unwrap();
    assert_eq!(binary.sig_payload(), binary.signing_bytes());
    assert_ne!(binary.sig_payload(), unsigned.sig_payload());
}

#[test]
fn a_text_signature_binds_the_header_and_every_field() {
    let wallet = Ed25519Keypair::from_seed(&[7; 32]);
    let bob = Ed25519Keypair::from_seed(&[8; 32]);
    let build = || {
        Delegation::builder(bob.did(), Subject::Did(wallet.did()), cmd("/file/read"))
            .nonce(Nonce::from_bytes(&[1; 12]))
            .expires_at(now().plus_seconds(3600))
    };
    let unsigned = build().prepare_with(wallet.did(), text()).unwrap();
    let message = std::str::from_utf8(unsigned.signing_bytes()).unwrap();
    let signature = wallet.sign(unsigned.signing_bytes()).unwrap();

    // The signature does not carry over to a DAG-CBOR header.
    let binary = build().prepare(wallet.did(), Algorithm::Ed25519).unwrap();
    let relabeled = Delegation::assemble(binary.signing_bytes(), signature.as_bytes()).unwrap();
    assert!(relabeled.verify(&KeyResolver).is_err());

    // An edited field is still canonical text and no longer verifies.
    let edited = message.replace("/file/read", "/file/write");
    let token = Delegation::assemble(edited.as_bytes(), signature.as_bytes()).unwrap();
    assert!(token.verify(&KeyResolver).is_err());

    // Text that is not in canonical form is refused outright.
    let spaced = message.replacen(':', ": ", 1);
    assert!(matches!(
        Delegation::assemble(spaced.as_bytes(), signature.as_bytes()),
        Err(Error::Codec(CodecError::InvalidJson))
    ));
}

#[test]
fn a_chain_mixes_text_and_binary_signatures() {
    let owner = Ed25519Keypair::from_seed(&[1; 32]);
    let recipient = Ed25519Keypair::from_seed(&[2; 32]);
    let session = Ed25519Keypair::from_seed(&[3; 32]);
    let service = Ed25519Keypair::from_seed(&[4; 32]);

    let share = sign(
        &owner,
        &Delegation::builder(
            recipient.did(),
            Subject::Did(owner.did()),
            cmd("/file/read"),
        )
        .nonce(Nonce::from_bytes(&[1; 12]))
        .expires_at(now().plus_seconds(86_400))
        .prepare_with(owner.did(), text())
        .unwrap(),
    );
    let grant = sign(
        &recipient,
        &Delegation::builder(session.did(), Subject::Powerline, cmd("/file/read"))
            .nonce(Nonce::from_bytes(&[2; 12]))
            .expires_at(now().plus_seconds(3600))
            .prepare_with(recipient.did(), text())
            .unwrap(),
    );
    let mut store = MemoryStore::new();
    store.insert(share.clone());
    store.insert(grant.clone());
    let executor = service.did();
    let mut validator = Validator::new(&store, now()).executor(&executor);

    let build = |proofs: &[&Delegation], nonce: u8| {
        Invocation::builder(owner.did(), cmd("/file/read"))
            .audience(service.did())
            .arg("cid", Ipld::String("bafy".into()))
            .proofs(proofs.iter().map(|proof| *proof.cid()))
            .nonce(Nonce::from_bytes(&[nonce; 12]))
            .expires_at(now().plus_seconds(60))
    };

    // The browser key signs binary under the wallets' text signatures.
    let by_session = build(&[&share, &grant], 3).sign(&session).unwrap();
    validator.validate(&by_session).unwrap();

    // The recipient's wallet invokes as text.
    let unsigned = build(&[&share], 4)
        .prepare_with(recipient.did(), text())
        .unwrap();
    let signature = recipient.sign(unsigned.signing_bytes()).unwrap();
    let by_wallet = Invocation::assemble(unsigned.signing_bytes(), signature.as_bytes()).unwrap();
    validator.validate(&by_wallet).unwrap();
}

#[test]
fn a_float_cannot_be_signed_as_text() {
    let wallet = Ed25519Keypair::from_seed(&[7; 32]);
    let build = || {
        Invocation::builder(wallet.did(), cmd("/crud/update"))
            .arg("ratio", Ipld::Float(0.5))
            .nonce(Nonce::empty())
            .expires_at(now())
    };
    assert!(matches!(
        build().prepare_with(wallet.did(), text()),
        Err(Error::Codec(CodecError::FloatInText))
    ));
    assert!(build().prepare(wallet.did(), Algorithm::Ed25519).is_ok());
}
