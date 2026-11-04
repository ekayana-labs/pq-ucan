# Roadmap

## 0.1

Delegation, invocation, policy, varsig, `did:key` for Ed25519, P-256,
secp256k1 and ML-DSA 44/65/87, execution-time chain validation, in-memory
proof store and replay guard, `no_std` core.

0.1.2 adds signatures over DAG-JSON for wallets that sign only text, and a
DAG-JSON presentation of tokens.

## 0.2

- Receipts and promise pipelining (`ucan/await/*`) per the UCAN Promise
  specification.
- Reading and checking `/ucan/revoke` invocations per the UCAN Revocation
  specification, to fill the `RevocationStore`: done in
  `Validator::check_revocation`. Still open: a fixture from another
  implementation once one exists.
- A `did:web` resolver behind a `resolve-web` feature.
- A pure-Rust ML-DSA backend (RustCrypto `ml-dsa`) so post-quantum
  principals work on `wasm32` and in `no_std`.

## Assurance

- Run the fuzz targets in `fuzz/` on a schedule. They run by hand today, and
  cover both codecs differentially against `serde_ipld_dagcbor` and
  `serde_ipld_dagjson`, plus tokens, policies and the small parsers.
- Cross-implementation vectors generated with the working group's
  JavaScript implementation, checked in as fixtures.
- Benchmarks for decode, verify and validate on the reference chain.
- External audit once the ML-DSA varsig header is registered.
