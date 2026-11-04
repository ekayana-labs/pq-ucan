# Validation

What the crate checks, in what order, and what it reports when a check
fails. The rules come from the UCAN, Delegation and Invocation
specifications; this document is the concrete pipeline.

## Two moments

A delegation is validated on receipt. An invocation is validated at
execution time, together with the chain of delegations it names. The
specification requires the second; the first is hygiene.

## Delegation on receipt

`Delegation::decode` guarantees structure: strict DAG-CBOR, the envelope
shape, a known tag, a well-formed payload, a parseable command, a
parseable policy.

`Delegation::verify(resolver)` checks the signature against the key the
issuer resolves to. `Delegation::check_time(now, skew)` checks the
validity window. Neither knows anything about a chain.

## Invocation at execution time

`Validator::validate(invocation)` runs these checks in this order and
stops at the first failure. Positions are `Hop(n)` for the n-th proof
(root is `Hop(0)`) or `Invocation`.

| # | Check                | Rule                                                                                                   | Failure                          |
|---|----------------------|--------------------------------------------------------------------------------------------------------|----------------------------------|
| 0 | Proof limit          | If the validator was given a maximum, `prf` has no more entries than that.                             | `TooManyProofs`                  |
| 1 | Proofs resolve       | Every CID in `prf` is in the store.                                                                    | `MissingProof(cid)`              |
| 2 | Non-empty chain      | `prf` has at least one entry. Public resources are the caller's choice, not the default.               | `EmptyChain`                     |
| 3 | Root authority       | `Hop(0).iss` equals the invocation `sub`.                                                              | `RootNotSubject`                 |
| 4 | Powerline placement  | `Hop(0).sub` is not `null`.                                                                            | `PowerlineAtRoot`                |
| 5 | Subject alignment    | Each `Hop(n).sub` equals the invocation `sub`, or is `null` and inherits the previous hop's subject.   | `SubjectMismatch(hop)`           |
| 6 | Principal alignment  | `Hop(n).aud` equals `Hop(n+1).iss`; the last hop's `aud` equals the invocation `iss`. Fragments ignored. | `PrincipalMismatch(hop)`       |
| 7 | Command attenuation  | `Hop(n).cmd` covers `Hop(n+1).cmd`; the last hop's `cmd` covers the invocation `cmd`.                  | `CommandNotCovered(hop)`         |
| 8 | Time bounds          | For every hop, `nbf - skew <= now <= exp + skew`. For the invocation, `now <= exp + skew`.             | `NotYetValid(hop)`, `Expired(hop)` |
| 9 | Signatures           | Every hop's signature and the invocation signature verify under their issuer's resolved key.           | `BadSignature(hop)`, `Unresolvable(hop)` |
| 9a | Revocation          | If a `RevocationStore` is attached, no hop's CID is revoked.                                           | `Revoked { hop, cid }`           |
| 10 | Policy              | The invocation `args` satisfy every statement of every hop's policy.                                   | `PolicyRejected { hop, statement }` |
| 11 | Executor            | If the validator was given its own DID: `aud` when present, else `sub`, equals it.                     | `WrongExecutor`                  |
| 12 | Replay              | If a `ReplayGuard` is attached, the invocation CID has not been seen. Recorded only after 1-11 pass.  | `Replay`                         |

Ordering rationale: the proof limit costs nothing and protects everything
after it, so it comes before any lookup; structural failures are cheap and
give the best diagnostics, so they go next; signatures are the expensive step and
are checked before revocation and policy so that neither is consulted for a
token nobody signed; the replay guard is last so that a rejected invocation
never consumes a nonce.

The result of a successful validation is a `Proof`: the resolved chain,
the effective subject, and the invocation. Callers execute from the
`Proof`, not from the bare invocation.

## Command coverage

A command is a `/`-separated path. `a` covers `b` when `a` is `/`, or `a`
equals `b`, or `b` begins with `a` followed by `/`. Coverage is on
segment boundaries: `/crypto` covers `/crypto/sign` and does not cover
`/cryptocurrency`.

Commands must be lowercase, begin with `/`, and carry no trailing `/`
except the root itself. The `/ucan` namespace is reserved by the
specification; the crate does not police it.

## Time

Timestamps are integer seconds. `nbf` absent means valid from the epoch.
`exp: null` means never. The validator takes a clock and a skew allowance;
60 seconds is the specification's recommendation and the default. Both
bounds are inclusive.

## Policy

A policy is a list of statements. The list is an implicit `and`. A
statement is one of:

| Form                              | Meaning                                                            |
|-----------------------------------|--------------------------------------------------------------------|
| `["==", sel, value]`              | Selected value deep-equals `value`                                 |
| `["!=", sel, value]`              | `not ["==", sel, value]`                                           |
| `["<", sel, n]` and `<=`, `>`, `>=` | Numeric comparison; integers and floats compare by value; non-numbers are false |
| `["like", sel, pattern]`          | Glob match on a string; non-strings are false                      |
| `["and", [stmts]]`                | All hold; empty is true                                            |
| `["or", [stmts]]`                 | Any holds; empty is true                                           |
| `["not", stmt]`                   | Negation                                                           |
| `["all", sel, stmt]`              | Selected value is a list or map; `stmt` holds for every element (map values); non-collection is false |
| `["any", sel, stmt]`              | As `all`, with at least one element                                |

A selector that fails to resolve makes its statement false. Inside `all`
and `any`, the inner statement's selectors are relative to each element.

### Selectors

```abnf
selector   = "." *segment
segment    = ( "." ident / "." index / index ) [ "?" ]
index      = "[" ( quoted / integer / slice / "" ) "]"
slice      = [ integer ] ":" [ integer ]
ident      = ( ALPHA / "_" ) *( ALPHA / DIGIT / "_" )
quoted     = DQUOTE *char DQUOTE          ; JSON string escapes
integer    = [ "-" ] 1*DIGIT
```

Two consecutive dots are a syntax error. Repeated `?` collapses to one.

Resolution, left to right:

- `.` is the whole `args` map.
- `.name` and `["name"]` select a map key. A missing key yields `null`.
  Applied to anything but a map, the segment fails.
- `[]` on a list is the list; on a map it is the list of values; on
  anything else it fails.
- `[n]` indexes a list or a byte string (yielding the byte as an integer).
  Negative indexes count from the end. Out of range fails.
- `[a:b]` slices a list or byte string with the same index rules; missing
  bounds mean the start or end.
- A failing segment marked `?` yields `null` and resolution stops there.
  A failing segment without `?` fails the whole selector, regardless of
  any `?` later in it.

### Glob patterns

`*` matches zero or more characters. `\*` is a literal `*`. Every other
character, whitespace included, matches itself. Matching is whole-string.

### Paths

A pattern compares text and knows nothing about paths. `/data/h1/*` matches
`/data/h1/../../../etc/passwd`, which names a file outside `/data/h1`. The
validator accepts that invocation, and an executor that opens the path has
left the scope the delegation meant to grant.

The crate cannot change this. The specification says the wildcard is zero or
more characters and that it is the only special character, so a `*` that
stopped at `..` would disagree with every other implementation about what a
signed policy means.

If an argument is a path, the executor should refuse it unless it is already in
normal form, before validating:

```rust
fn in_normal_form(path: &str) -> bool {
    path.split('/').all(|segment| segment != ".." && segment != ".")
}
```

Refuse it, and do not rewrite it. The arguments are signed, so a rewritten
invocation no longer verifies, and checking one spelling while opening another
is the same bug again. Run the check on the form the executor will use, after
any percent-decoding. It is a check on the text, so symlinks inside the scope
still need handling where the file is opened.

A delegator can also say this in the policy, where it binds every hop below and
needs nothing from the executor. A policy is an implicit `and`, so any hop can
add it:

```json
[
  ["like", ".path", "/data/h1/*"],
  ["not", ["like", ".path", "*/../*"]],
  ["not", ["like", ".path", "*/.."]]
]
```

These only know the spelling they name, so treat them as a second layer and not
as a replacement for the executor's check.

Keep the separator in the pattern as well. `/data/h1*` also matches
`/data/h1-private/key`.

### Numbers

`1`, `1.0` and `1.00` are equal. Comparisons between an integer and a
float are exact. A comparison against a non-number is false, never an
error.

## Chain length

The specifications set no limit on the length of a chain and no token
field for one. `Validator::max_proofs` is the executor's own limit: it counts
the entries in `prf` and applies to every chain alike. It cannot express "Bob
may delegate twice more", because that would have to travel in the token.

Check 0 runs first because the cost of validating grows with the chain, by
one signature verification per hop, and an ML-DSA verification takes over a
millisecond. Without a limit, the invoker decides how much work the executor
does.

## Replay

The specification requires replay prevention for invocations. The
`ReplayGuard` trait records invocation CIDs; the crate ships an in-memory
guard. Production deployments should back it with something durable and
prune by `exp`.

## Revocation

`Validator::revocations` takes a `RevocationStore`, which answers one question:
is this CID revoked? The crate ships an in-memory store. Production deployments
should back it with something durable, and the executor must hold the
revocations for which it is the subject.

The check uses the CID computed from each delegation's bytes, which is the
canonical CID the specification names, and not the link in `prf`. The
specification says a revoked delegation is ignored, which need not invalidate
every chain to the same authority. An invocation's `prf` is one line, so
ignoring a hop breaks it, and the invoker can try again with a chain that avoids
that delegation.

A store that cannot answer should say the delegation is revoked. Otherwise an
outage of the store switches revocation off.

### Taking a revocation in

The store takes the caller's word, and recording every revocation received would
let anyone cut off anyone else. `Validator::check_revocation(subject, invocation,
chain)` judges one first. `subject` is whose revocations are being kept. `chain`
is the delegation being revoked and the delegations above it, root first. If the
invocation has `path`, `Revocation::read(invocation)?.path()` names them.

```rust
let accepted = validator.check_revocation(&me, &invocation, &chain)?;
revoked.revoke(*accepted.target());
```

It runs these in order and stops at the first failure. Failures in `Invalid` and
`Grant` wrap a `ValidationError`, whose hop says which token.

| # | Check             | Rule                                                                                    | Failure                       |
|---|-------------------|-----------------------------------------------------------------------------------------|-------------------------------|
| 1 | Command           | `cmd` is `/ucan/revoke`.                                                                | `NotARevocation`              |
| 2 | Arguments         | `revoke` is a link, `path` if present is a list of links, and there is nothing else.    | `MissingTarget`, `MalformedArgument`, `UnknownArgument` |
| 3 | Proof limit       | If the validator has a maximum, the chain is no longer than that.                       | `Invalid(TooManyProofs)`      |
| 4 | Chain shape       | Checks 2 to 7 above, for `subject`, over the chain. The last hop has no next token.     | `Invalid(...)`                |
| 5 | Target            | `revoke` is the CID of the chain's last delegation, computed from its bytes.            | `WrongTarget`                 |
| 6 | Path              | `path`, if present, is the CIDs of the chain, root first.                               | `PathMismatch`                |
| 7 | No loops          | No principal issues twice in the chain.                                                 | `RepeatedIssuer`              |
| 8 | Revocation itself | It is signed by its `iss` and has not expired.                                          | `Invalid(BadSignature, Unresolvable, Expired)` with `Hop::Invocation` |
| 9 | Chain signatures  | Every hop verifies under its issuer's key.                                              | `Invalid(BadSignature, Unresolvable)` |
| 10 | Whose right      | The revocation's `sub` issued a delegation in the chain.                                | `SubjectNotInChain`           |
| 11 | Revoker          | `iss` issued a delegation in the chain, or `prf` is non-empty and passes the whole pipeline above as an invocation of `/ucan/revoke`, so it is rooted in `sub`. | `NotAuthorized`, `Grant(...)` |
| 12 | Standing         | The hops above the one whose right is used are in their time bounds and, if a store is attached, not revoked. | `Invalid(Expired, NotYetValid, Revoked)` |

The result is an `AcceptedRevocation`: the CID to record, who signed, which hop's
right was used, and whether it was delegated.

The time bounds in check 12 stop at the hop whose right is used. A delegation that
has expired or not yet begun can still be revoked, and someone whose grant was
revoked or has lapsed can no longer take others down with them. A delegated
right also needs its `/ucan/revoke` chain to be in time when the revocation
arrives. The executor and replay guard do not apply, because a revocation is
idempotent and may arrive by gossip.

`subject` is an argument and not read from the token because a powerline has no
subject. Without it Mallory could root a chain in herself above Bob's powerline
to Carol and revoke it for everyone. Keep one store per subject: a powerline can
be revoked under one subject and stay good under another, and a store shared by
subjects would lose that.

`/` and `/ucan` cover `/ucan/revoke`, as they do any other command. The UCAN
specification says the top command includes revoking delegations, so whoever
holds `/` over a subject can revoke any delegation of that subject, even one above
them. Grant it with that in mind.

### What a path can prove

The specification says an issuer above a delegation may revoke it. A UCAN 1.0
delegation has no ancestors of its own though: a chain exists only when someone
presents one, and anyone can sign a delegation to anyone without their consent.
So Mallory, if she really holds `/mcp/read_file` from Alice, can sign the same
command to Bob and present Alice → Mallory → Bob → Carol. She has a good path to
Bob's delegation to Carol. The check accepts it, and because the store is keyed by
CID that delegation is now revoked on Alice → Bob → Carol as well, a chain Mallory
is not in.

The check does narrow this. She must hold authority over the same subject and a
command that covers the target's, she cannot do it from downstream alone since
loops are refused, and she cannot do it once her own grant has lapsed. It does
not close it, and nothing can while the store is keyed only by CID. The Revocation
specification's own pseudocode scopes a revocation to chains that contain the
revoker, but its Store text, and the UCAN specification's section on memoized
validation, say a match on the CID is enough. The crate follows the latter for
now.

The case is reported: `AcceptedRevocation::rests_on_intermediate_issuer` is true
when the right comes from an issuer between the root and the target. Nothing else
can be manufactured this way. The root is the subject, and the target's issuer
issued the target. A caller for whom this matters can refuse those, at the cost of
intermediate issuers having to go to the subject or to the target's issuer.

### Reading the specification

The Revocation specification is v1.0.0-rc.1 and still partly uses older field
names. Upstream issues [#2] and [#3] ask about the same things and are unanswered,
so these are readings. No other implementation has `/ucan/revoke` yet, neither
rs-ucan nor ts-ucan, so there is no fixture to test them against.

| Point                | Revocation rc.1                                               | UCAN 1.0                                                     | Here |
|----------------------|---------------------------------------------------------------|--------------------------------------------------------------|------|
| Command              | `ucan/revoke`                                                 | Must begin with `/`. The UCAN specification lists `/ucan/revoke`. | `/ucan/revoke`. The older form does not parse. |
| Command field        | `do` in the table, `cmd` in the schema and diagrams           | `cmd`                                                        | `cmd` |
| Argument names       | `revoke`, `path` in the text and example. `rev`, `pth` in `revocation.ipldsch`. | Silent | `revoke`, `path`. The others are refused rather than half read. This is the least certain reading. |
| Nonce                | `""`. A MUST in the table, a SHOULD in the sentence after it. | Bytes, and SHOULD be empty for idempotent commands           | Not enforced. It gives a revoker nothing. Send it empty. |
| Grant                | `can` and `args: {"revoke": cid}`                             | A delegation has `cmd` and `pol`, and no `args`              | `cmd: "/ucan/revoke"` and `pol: [["==", ".revoke", {"/": cid}]]`. An empty policy allows any delegation. |
| What a grant names   | The table names the revoked delegation. A diagram names its parent. | `pol` compares arguments                                  | Exactly what the policy says. |
| `sub`                | The Store section reads it as the resource's subject. Unmerged [#4] reads it as the principal whose right is used. | The chain in `prf` is rooted in `sub`. | Either. It must have issued in the chain, and the root has. So Zelda can hold Bob's right in a chain rooted in Bob with `sub` Bob. |
| `prf` from an issuer | The example has both `path` and `prf`                         | Must run from `sub` to `iss`                                 | Not consulted. An issuer's right comes from the chain, and a chain from the subject often cannot cover `/ucan/revoke`. Such a token does not pass `Validator::validate`, and is not meant to. |
| `path` order         | Not stated                                                    | `prf` is root first                                          | Root first, including the target. |
| `exp`                | Silent, and revocations are irreversible                      | SHOULD time out. An attestation may set `null`.              | Enforced. A revocation meant to travel by gossip should set `exp: null`. |
| Canonical CID        | The examples use `bafkrei...`, a raw CID                      | DAG-CBOR, SHA-256                                            | `Delegation::cid`. A link spelling it another way is `WrongTarget`. |
| Envelope tag         | `ucan/i/1.0.0-rc.1` in the example                            | `ucan/inv@1.0.0`                                             | As for any invocation. See the wire format. |
| Early revocations    | RECOMMENDED to accept one before the delegation arrives       | Silent                                                       | Requires the chain, so the revoker sends it along. `MemoryRevocationStore::revoke` takes any CID for a caller who has decided. |

[#2]: https://github.com/ucan-wg/revocation/issues/2
[#3]: https://github.com/ucan-wg/revocation/issues/3
[#4]: https://github.com/ucan-wg/revocation/pull/4

## What is not checked

- That the subject actually controls the resource. The executor is the
  resource, or it asks the resource; the validator cannot know.
- Semantic conditions (day of week, quota). The specification places
  these in `args` and in execution, not in policy.
- Who issued a revocation. `Validator::validate` only asks the store, so a
  revocation has to go through `Validator::check_revocation` on its way in.
