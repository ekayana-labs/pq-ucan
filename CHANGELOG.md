# Changelog

All notable changes to this crate are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the crate
adheres to [Semantic Versioning](https://semver.org/).

## [0.1.3] - 2026-11-05

### Added

- `Validator::max_proofs`, an optional limit on the number of proofs an
  invocation may name. It is checked before any lookup and fails with
  `ValidationError::TooManyProofs`. There is no limit unless one is set.
- `Validator::revocations`, an optional check of every delegation in a chain
  against a `RevocationStore`, failing with `ValidationError::Revoked`.
  `MemoryRevocationStore` keeps them in memory, and `prune_expired` drops those
  whose target has expired. Nothing is checked unless a store is attached.
- `Validator::check_revocation`, which reads a `/ucan/revoke` invocation and
  accepts it only if it is signed and its issuer may revoke the delegation it
  names, given that delegation's chain: the delegation's issuer, an issuer above
  it, or a holder of a delegated `/ucan/revoke`. A refusal is a named
  `RevocationError`. A recorded revocation reaches only chains its authority
  issued in, because a path shows no more than that. Other implementations have
  no `/ucan/revoke` yet, so this has no fixture, and the Revocation specification
  is a release candidate that still uses older names. `docs/validation.md` lists
  how each one was read.
- Fuzz targets in `fuzz/` for both codecs, tokens, policies and the small
  parsers. The codecs are checked against `serde_ipld_dagcbor` and
  `serde_ipld_dagjson`. They are not part of the published crate.

### Fixed

- The DAG-CBOR decoder accepted `-0.0` and the encoder wrote it, which the
  DAG-CBOR specification forbids, since it gives one value two encodings. It is
  now refused on decode and written as `0.0`, as `serde_ipld_dagcbor` does. A
  token holding `-0.0` that decoded under 0.1.2 no longer decodes. Found by
  fuzzing.
- A link with bytes after its CID decoded as if they were not there, so one
  token could have many encodings. Links in DAG-CBOR, links in DAG-JSON and
  `cid::parse` now refuse them, and a DAG-JSON link must spell its CID the way
  the encoder does. Only the signer can produce such a token, since the bytes
  are signed. Found by fuzzing.

### Documentation

- `like` compares text, so `/data/h1/*` matches
  `/data/h1/../../../etc/passwd`. The specification requires this, so matching
  has not changed. `docs/validation.md` explains how to close it, in the
  executor and in a policy.

## [0.1.2] - 2026-10-01

### Added

- Signatures over DAG-JSON for wallets that sign only UTF-8 text. A varsig
  header can name DAG-JSON as its payload encoding
  (`Header::with_encoding(Encoding::DagJson)`). With that header
  `DelegationBuilder::prepare_with` and `InvocationBuilder::prepare_with`
  return the payload's canonical DAG-JSON text to sign, and `assemble`
  accepts that text. Tokens stay DAG-CBOR on the wire. UCAN 1.0 signs
  DAG-CBOR, so this is an extension.
- `UnsignedDelegation::sig_payload` and `UnsignedInvocation::sig_payload`,
  the envelope's second element for a client that assembles the token
  itself.
- `to_dag_json` on `Envelope`, `Delegation` and `Invocation`, for logs and
  debugging.
- `codec::json`, a strict DAG-JSON codec.

### Changed

- A varsig header whose payload encoding is DAG-JSON now decodes instead of
  failing with `UnsupportedEncoding`.

## [0.1.1] - 2026-09-17

### Added

- Detached signing for keys the builder never holds, such as a wallet or a
  key in a browser: `DelegationBuilder::prepare` and
  `InvocationBuilder::prepare` return the exact bytes to sign
  (`UnsignedDelegation`, `UnsignedInvocation`), and `Delegation::assemble`
  and `Invocation::assemble` build the token from those bytes and the
  signature. The result is byte for byte what `sign` produces.

## [0.1.0] - 2026-09-10

First release.

### Added

- Strict DAG-CBOR codec: canonical encoding, a decoder that refuses
  non-canonical input, and a reader that reports byte ranges.
- `Did` with `did:key` for Ed25519, P-256, secp256k1 and ML-DSA 44/65/87,
  and the `Resolver` trait for every other method.
- Signing and verification for those algorithms behind features, with the
  algorithm carried by keys and signatures rather than by types.
- Varsig v1 headers, including provisional headers for ML-DSA.
- `Delegation` and `Invocation` with builders that take the issuer from the
  signer and require an expiry and a nonce before signing. Decoded tokens
  keep their bytes; signatures and CIDs are checked over them.
- The policy language: statements, jq-style selectors, glob patterns, and
  evaluation with the specification's numeric and quantifier rules.
- `Validator`: the execution-time pipeline over an invocation and its proof
  chain, with positioned errors; `MemoryStore` and `MemoryReplayGuard`.
- `no_std` support with `alloc`.
