# Security Policy

## Reporting security problems

**DO NOT CREATE A GITHUB ISSUE** to report a security problem.

Please use the
[Report a Vulnerability](https://github.com/ekayana-labs/pq-ucan/security/advisories/new)
link with a helpful title and a detailed description of the problem.
Expect a response typically within 72 hours.

If you receive no response in the advisory, email <suraj410401@gmail.com>
with the advisory URL. Do not put exploit details in the email; keep them
in the advisory.

## Scope

Anything that lets an invocation pass validation without the authority it
claims, or lets a token verify under a key that did not sign it.
Concretely:

- a proof chain that validates with a broken link: a hop whose audience is
  not the next issuer, a subject that changes, a command that widens, a
  policy that is not applied, a window that is not enforced;
- two byte strings that decode to the same token, or a token that decodes
  to something other than what was signed;
- a signature that verifies under the wrong algorithm or the wrong key;
- a replay that a `ReplayGuard` fails to catch;
- a panic on untrusted input. Tokens, DIDs, policies and arguments all
  arrive from the network.

Weaknesses in the underlying primitives belong upstream: report Ed25519
issues to `ed25519-dalek`, P-256 and secp256k1 issues to the RustCrypto
project, and ML-DSA issues to `aws-lc-rs`. Reports here are still welcome
if this crate uses them wrongly.

## Status

This crate has **not received an external audit**. The ML-DSA varsig
headers it emits are provisional pending registration, so tokens signed
with them today may not verify against a future registry assignment.
