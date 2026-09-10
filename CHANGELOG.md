# Changelog

All notable changes to this crate are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the crate
adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
