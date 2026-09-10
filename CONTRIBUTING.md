# Contributing

## Development

```console
cargo test --all-features
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo check --no-default-features
cargo doc --no-deps
```

`ml-dsa` builds `aws-lc-rs`, which needs a C compiler and CMake.

## Rules of the road

- **The specification decides.** When the code and the UCAN, Delegation,
  Invocation or Varsig specification disagree, the code is wrong. Cite the
  section in the pull request.
- **Bytes are the truth.** Signatures and CIDs are computed over received
  bytes. Nothing re-encodes a token to verify it.
- **Strict in, canonical out.** The decoder refuses non-canonical DAG-CBOR
  and unknown payload fields. Loosening either needs a written reason in
  `docs/wire-format.md`.
- **Untrusted input never panics.** `unwrap`, `expect`, indexing and
  `panic!` are denied in library code by lint. Return an error.
- **Every rejection says where.** Validation errors name the hop and the
  rule. A new check gets a new variant, not a reused one.
- **Interoperability has tests.** A change to what is emitted or accepted
  comes with a fixture from another implementation, or with the reason no
  fixture can exist yet.
- **No `unsafe`, every public item documented.** The crate enforces both.

## Commit messages

Short, capitalized, imperative subject with no trailing period: `Add the
policy evaluator`, `Reject unsorted map keys`. Use a `ci:`, `docs:`,
`deps:`, or `chore:` prefix only for mechanical changes. Explain why in the
body when the diff does not make it obvious.
