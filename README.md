# pq-ucan

[![CI](https://github.com/ekayana-labs/pq-ucan/actions/workflows/main.yml/badge.svg)](https://github.com/ekayana-labs/pq-ucan/actions/workflows/main.yml)
[![MSRV](https://img.shields.io/badge/MSRV-1.90.0-blue)](rust-toolchain.toml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/ekayana-labs/pq-ucan/badge)](https://scorecard.dev/viewer/?uri=github.com/ekayana-labs/pq-ucan)

UCAN 1.0 for Rust: delegation, invocation, the policy language, and
execution-time validation of a proof chain, with post-quantum principals as
an ordinary algorithm.

A chain may mix `did:key` principals of any supported algorithm. Every
decoded token keeps its bytes, so signatures and CIDs are checked over what
was received rather than over a re-encoding. The DAG-CBOR codec is strict in
both directions. A validator reports the hop and the rule that rejected a
chain.

| Algorithm | `did:key` | Varsig | Feature      |
|-----------|-----------|--------|--------------|
| Ed25519   | `z6Mk…`   | spec   | `ed25519`    |
| ES256     | `zDn…`    | spec   | `p256`       |
| ES256K    | `zQ3s…`   | spec   | `secp256k1`  |
| ML-DSA-44 / 65 / 87 (FIPS 204) | registered multicodec | provisional | `ml-dsa` |

The core is `no_std` with `alloc`. `std` adds the system clock and the
system random source. `ml-dsa` needs a C toolchain for `aws-lc-rs`.

## Use

```rust
use pq_ucan::{
    command::Command,
    crypto::{ed25519::Ed25519Keypair, Signer},
    delegation::{Delegation, Subject},
    invocation::Invocation,
    nonce::Nonce,
    time::Timestamp,
    validate::{MemoryStore, Validator},
};

let mut rng = pq_ucan::rng::system();
let alice = Ed25519Keypair::generate(&mut rng);
let bob = Ed25519Keypair::generate(&mut rng);
let now = Timestamp::from_unix(1_800_000_000)?;

// Alice lets Bob read from her store for an hour.
let grant = Delegation::builder(bob.did(), Subject::Did(alice.did()), Command::parse("/crud/read")?)
    .nonce(Nonce::random(&mut rng))
    .expires_at(now.plus_seconds(3600))
    .sign(&alice)?;

// Bob exercises it.
let invocation = Invocation::builder(alice.did(), Command::parse("/crud/read")?)
    .proof(*grant.cid())
    .nonce(Nonce::random(&mut rng))
    .expires_at(now.plus_seconds(60))
    .sign(&bob)?;

// Alice validates the chain before acting on it.
let mut store = MemoryStore::new();
store.insert(grant);
let proof = Validator::new(&store, now)
    .executor(&alice.did())
    .validate(&invocation)?;
```

A builder takes no issuer: the signer's DID is the issuer, so a token whose
`iss` does not match its key cannot exist. It will not sign until an expiry
and a nonce have been chosen; both are decisions, not defaults.

Tokens are bytes. `Delegation::decode` and `Invocation::decode` accept the
released `ucan/…@1.0.0` tags; `decode_with(DecodeOptions::STRICT.release_candidate_tags(true))`
also accepts the `-rc.1` tags rs-ucan and the JavaScript implementation
emit.

## Documents

- [docs/design.md](docs/design.md): the decisions behind the crate and how
  it differs from prior implementations.
- [docs/wire-format.md](docs/wire-format.md): envelope, varsig headers,
  payload layouts, CIDs, `did:key`.
- [docs/validation.md](docs/validation.md): the validation pipeline and the
  policy language, rule by rule.
- [docs/roadmap.md](docs/roadmap.md): what is not here yet.

## Status

Pre-release. The wire format follows UCAN 1.0.0 and interoperates with the
working group's fixtures. The ML-DSA varsig headers are provisional until
the varsig registry assigns tags; they are self-describing and intended for
deployments that control both ends. The crate has not had an external
audit.

## Acknowledgments

UCAN is the work of the [UCAN working group](https://github.com/ucan-wg).
The specifications this crate implements were written by Brooklyn Zelenka,
Irakli Gozalishvili, Daniel Holmgren, Philipp Krüger, Hugo Dias and Zeeshan
Lakhani; varsig by Brooklyn Zelenka, Irakli Gozalishvili, Hugo Dias, Joel
Thorstensson and Quinn Wilton.

[rs-ucan](https://github.com/ucan-wg/rs-ucan), by Brooklyn Zelenka,
Christopher Joel and contributors, is the reference Rust implementation.
It is where this crate learned the wire format, and its fixtures are the
interoperability vectors here. pq-ucan is written from the specifications
rather than from rs-ucan's code, and takes different positions on principal
typing, canonical form and validation; those differences are set out in
[docs/design.md](docs/design.md#relation-to-rs-ucan).

## License

MIT
