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
| 1 | Proofs resolve       | Every CID in `prf` is in the store.                                                                    | `MissingProof(cid)`              |
| 2 | Non-empty chain      | `prf` has at least one entry. Public resources are the caller's choice, not the default.               | `EmptyChain`                     |
| 3 | Root authority       | `Hop(0).iss` equals the invocation `sub`.                                                              | `RootNotSubject`                 |
| 4 | Powerline placement  | `Hop(0).sub` is not `null`.                                                                            | `PowerlineAtRoot`                |
| 5 | Subject alignment    | Each `Hop(n).sub` equals the invocation `sub`, or is `null` and inherits the previous hop's subject.   | `SubjectMismatch(hop)`           |
| 6 | Principal alignment  | `Hop(n).aud` equals `Hop(n+1).iss`; the last hop's `aud` equals the invocation `iss`. Fragments ignored. | `PrincipalMismatch(hop)`       |
| 7 | Command attenuation  | `Hop(n).cmd` covers `Hop(n+1).cmd`; the last hop's `cmd` covers the invocation `cmd`.                  | `CommandNotCovered(hop)`         |
| 8 | Time bounds          | For every hop, `nbf - skew <= now <= exp + skew`. For the invocation, `now <= exp + skew`.             | `NotYetValid(hop)`, `Expired(hop)` |
| 9 | Signatures           | Every hop's signature and the invocation signature verify under their issuer's resolved key.           | `BadSignature(hop)`, `Unresolvable(hop)` |
| 10 | Policy              | The invocation `args` satisfy every statement of every hop's policy.                                   | `PolicyRejected { hop, statement }` |
| 11 | Executor            | If the validator was given its own DID: `aud` when present, else `sub`, equals it.                     | `WrongExecutor`                  |
| 12 | Replay              | If a `ReplayGuard` is attached, the invocation CID has not been seen. Recorded only after 1–11 pass.  | `Replay`                         |

Ordering rationale: structural failures are cheap and give the best
diagnostics, so they go first; signatures are the expensive step and
are checked before policy so that no policy is evaluated for a token
nobody signed; the replay guard is last so that a rejected invocation
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

### Numbers

`1`, `1.0` and `1.00` are equal. Comparisons between an integer and a
float are exact. A comparison against a non-number is false, never an
error.

## Replay

The specification requires replay prevention for invocations. The
`ReplayGuard` trait records invocation CIDs; the crate ships an in-memory
guard. Production deployments should back it with something durable and
prune by `exp`.

## What is not checked

- That the subject actually controls the resource. The executor is the
  resource, or it asks the resource; the validator cannot know.
- Semantic conditions (day of week, quota). The specification places
  these in `args` and in execution, not in policy.
- Revocation. Planned; see the roadmap.
