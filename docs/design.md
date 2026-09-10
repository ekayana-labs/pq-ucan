# Design

pq-ucan is a UCAN 1.0 implementation for Rust: delegation, invocation, the
policy language, and execution-time validation of a proof chain, with
post-quantum principals as a supported algorithm rather than a fork.

This document records the decisions that shape the crate and why they were
made. The wire format is in [wire-format.md](wire-format.md); the rules a
validator enforces are in [validation.md](validation.md).

## Goals

- Implement UCAN 1.0.0 as published: delegation, invocation, policy, varsig,
  and the cryptosuite the specification requires (Ed25519, P-256,
  secp256k1, `did:key`).
- Add ML-DSA (FIPS 204) at parameter sets 44, 65 and 87 as ordinary
  algorithms, so a chain may mix classical and post-quantum principals.
- Validate a complete proof chain at execution time and say precisely which
  hop and which rule rejected it.
- Interoperate byte for byte with other implementations: a token produced
  here verifies elsewhere and vice versa.
- Run in `no_std` with `alloc`, so the same code serves servers, browsers
  and embedded validators.

## Non-goals

- Transport, storage, or key management. The crate signs and validates
  tokens; where they travel and where keys live is the caller's problem.
- Hand-written assembly. Every primitive comes from an audited backend that
  already carries vetted assembly where it matters. Adding our own would
  make the crate harder to review and would not make it faster.
- Backward compatibility with pre-1.0 UCAN (JWT-based) tokens.

## Decisions

### 1. Principals are values

A `Did` is a parsed value. The algorithm behind it is data carried by the
token (the varsig header) and by the identifier (the `did:key` multicodec),
never a type parameter of the token.

This is the largest departure from prior Rust implementations, where a
delegation was `Delegation<D: Did>` and every principal in a chain had to
share one type. Real chains do not: a `did:bio` identity delegates to an
ML-DSA device which re-delegates to an Ed25519 colleague. Modelling that as
types forces every application to build its own composite principal.

Consequence: verification resolves an issuer to a public key through a
`Resolver`. `did:key` resolves inline; any other method plugs in by
implementing one trait.

### 2. The bytes are the truth

A decoded token keeps the bytes it was decoded from. The signature is
checked over the received `SigPayload` bytes and the CID is computed over
the received envelope bytes. Nothing is re-encoded in order to verify it.

Re-encoding a parsed value to verify a signature assumes that the encoder
on both sides agrees on every detail of canonical form. When it does not,
the token fails to verify and nobody can say why; when it does, a
malleable field may slip through. Keeping the bytes removes the assumption.

Consequence: building a token encodes once, signs, and then decodes its own
output. What a signer holds is exactly what a verifier will see.

### 3. Strict canonical DAG-CBOR, owned

The crate carries its own DAG-CBOR codec. The decoder rejects anything
that is not strict canonical form: indefinite lengths, non-minimal
integers, unsorted or duplicate map keys, floats that are not 64-bit and
finite, tags other than 42, and trailing bytes. The encoder produces only
that form.

Canonicalization attacks are the documented reason varsig exists. A
permissive decoder that accepts two encodings of the same value gives an
attacker two byte strings for one signature. Refusing the second is
cheaper than reasoning about it.

Owning the codec also gives the scanner needed by decision 2: the decoder
reports where the signed region starts and ends, which a serde-based codec
cannot.

### 4. Validation is a pipeline with named failures

`Validator::validate` runs a fixed sequence of checks over an invocation
and its proof chain. Each check has a name, an error variant, and a
position in the chain it points at. The order is fixed and documented.

Authorization bugs are diagnosed under pressure. "invalid token" is not a
diagnosis; "hop 2: audience `did:key:zBob` does not match issuer
`did:key:zCarol`" is.

### 5. The issuer comes from the signer

A builder never takes an `iss`. It takes a `Signer`, reads the DID from it,
and signs with it. A token whose issuer does not match its signing key
cannot be constructed.

### 6. Expiry is a decision

A delegation builder will not sign until the caller has chosen between
`expires_at` and `never_expires`. Forgetting an expiry is the most common
way to issue more authority than intended; the type system is the right
place to refuse it.

### 7. Post-quantum is an algorithm, not a fork

ML-DSA lives in the same algorithm registry as Ed25519. It has a `did:key`
prefix (`mldsa-*-pub`, registered in multicodec), a varsig header, a
signer and a verifier, and nothing else in the crate knows it is
post-quantum.

The varsig tag for ML-DSA is not yet in the varsig registry. The crate
emits the public key multicodec as the tag and documents the header as
provisional. See [wire-format.md](wire-format.md#varsig-headers).

### 8. `no_std` core, `std` at the edges

Everything that parses, encodes, signs, verifies and validates is
`no_std` with `alloc`. The `std` feature adds a system clock and OS
randomness. ML-DSA is behind its own feature because its backend needs a
C toolchain.

## Module map

| Module       | Holds                                                              |
|--------------|--------------------------------------------------------------------|
| `codec`      | Strict DAG-CBOR encode, decode and scan; unsigned varints          |
| `cid`        | CIDv1 over DAG-CBOR and SHA-256; base58btc text form               |
| `did`        | The `Did` value, `did:key` encoding, the `Resolver` trait          |
| `crypto`     | `Algorithm`, `PublicKey`, `Signature`, `Signer`, the backends      |
| `varsig`     | The varsig v1 header                                               |
| `command`    | The `Command` path and its attenuation order                       |
| `time`       | `Timestamp` with the 53-bit bound; `Clock`                         |
| `nonce`      | `Nonce`                                                            |
| `envelope`   | The signed envelope shared by every token type                     |
| `delegation` | `Delegation`, its payload and builder                              |
| `invocation` | `Invocation`, its payload and builder                              |
| `policy`     | Statements, selectors, evaluation                                  |
| `validate`   | `Validator`, `ProofStore`, `ReplayGuard`                           |

Dependencies point downward in that table; nothing above `envelope` knows
about tokens.

## Relation to rs-ucan

[rs-ucan](https://github.com/ucan-wg/rs-ucan) by Brooklyn Zelenka,
Christopher Joel and the UCAN working group is the reference Rust
implementation and the place this crate learned the format from. Its test
fixtures are the interoperability vectors here.

The two differ where it matters for the goals above:

| Concern                     | rs-ucan                                    | pq-ucan                                          |
|-----------------------------|--------------------------------------------|--------------------------------------------------|
| Principal type              | One `Did` type per token, chosen statically | Any DID in any position; algorithm from the data |
| Signature verification      | Re-encodes the payload                     | Verifies the received bytes                      |
| Canonical form on decode    | Not enforced                               | Enforced; non-canonical input is rejected        |
| Proof chain validation      | Not implemented                            | Full pipeline with positioned errors             |
| Spec version                | `1.0.0-rc.1` tags                          | `1.0.0` tags; rc.1 accepted on request           |
| Post-quantum                | Only on an unmerged branch                 | ML-DSA 44/65/87 in the algorithm registry        |
| Codec                       | serde over `serde_ipld_dagcbor`            | Own strict codec                                 |

The code here is written from the specifications, not from rs-ucan.

## Security posture

- `#![forbid(unsafe_code)]`; `unwrap`, `expect`, indexing and `panic!` are
  denied by lint in library code. Untrusted bytes reach the crate from the
  network and must produce an `Error`, never a panic.
- Every cryptographic primitive is delegated: `ed25519-dalek`, `p256`,
  `k256`, and `aws-lc-rs` for ML-DSA.
- The crate has not had an external audit. The ML-DSA varsig header is
  provisional.
