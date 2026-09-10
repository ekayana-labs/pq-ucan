# Wire format

Normative references: [UCAN 1.0.0](https://github.com/ucan-wg/spec),
[UCAN Delegation 1.0.0](https://github.com/ucan-wg/delegation),
[UCAN Invocation 1.0.0](https://github.com/ucan-wg/invocation),
[Varsig 1.0.0](https://github.com/ChainAgnostic/varsig),
[DAG-CBOR](https://ipld.io/specs/codecs/dag-cbor/spec/),
[did:key](https://w3c-ccg.github.io/did-key-spec/),
[multicodec](https://github.com/multiformats/multicodec/blob/master/table.csv).

Where this document and a specification disagree, the specification wins
and this document has a bug.

## Envelope

Every token is a DAG-CBOR array of two elements.

| Position | Type    | Content                                                  |
|----------|---------|----------------------------------------------------------|
| `.0`     | bytes   | Signature by the payload's `iss` over the bytes of `.1`  |
| `.1`     | map     | `SigPayload`: exactly two keys                           |
| `.1.h`   | bytes   | Varsig v1 header                                         |
| `.1.<tag>` | map   | The token payload; `<tag>` names the token type          |

The signature covers the DAG-CBOR bytes of the whole `SigPayload` map,
header included. This was checked against the working group's fixture:
the signature verifies over `.1` and does not verify over the payload map
alone.

Tags:

| Token      | Tag              |
|------------|------------------|
| Delegation | `ucan/dlg@1.0.0` |
| Invocation | `ucan/inv@1.0.0` |

The decoder also accepts `ucan/dlg@1.0.0-rc.1` and `ucan/inv@1.0.0-rc.1`
when asked to (`DecodeOptions::release_candidate_tags`). The encoder never
emits them.

Worked example, the delegation fixture from the working group (an rc.1
token; the structure is identical):

```
82                                  array(2)
  58 40 <64 bytes>                    .0  Ed25519 signature
  a2                                  .1  map(2)
    61 68                               "h"
    48 34 01 ed 01 ed 01 13 71            bytes(8): varsig header
    73 "ucan/dlg@1.0.0-rc.1"             tag
    a9                                    map(9): payload
      63 "aud" 78 38 "did:key:z6Mkf…"
      63 "cmd" 61 "/"
      63 "exp" f6                           null
      63 "iss" 78 38 "did:key:z6Mkr…"
      63 "nbf" 1a 69 24 f1 a7               1764028839
      63 "pol" 80                           []
      63 "sub" f6                           null (powerline)
      64 "meta" a0                          {}
      65 "nonce" 4c <12 bytes>
```

## Varsig headers

A header is `0x34 0x01` followed by unsigned varint segments: the
signature algorithm and its parameters, then the payload encoding. Every
token here uses DAG-CBOR (`0x71`) as the payload encoding.

| Algorithm  | Segments after `34 01`                              | Header bytes                |
|------------|-----------------------------------------------------|-----------------------------|
| Ed25519    | `eddsa` `0xed`, curve `ed25519-pub` `0xed`, hash `sha2-512` `0x13` | `34 01 ed 01 ed 01 13 71` |
| ES256      | `ecdsa` `0xec`, curve `p256-pub` `0x1200`, hash `sha2-256` `0x12`  | `34 01 ec 01 80 24 12 71` |
| ES256K     | `ecdsa` `0xec`, curve `secp256k1-pub` `0xe7`, hash `sha2-256` `0x12` | `34 01 ec 01 e7 01 12 71` |
| ML-DSA-44  | `mldsa-44-pub` `0x1210`                             | `34 01 90 24 71`            |
| ML-DSA-65  | `mldsa-65-pub` `0x1211`                             | `34 01 91 24 71`            |
| ML-DSA-87  | `mldsa-87-pub` `0x1212`                             | `34 01 92 24 71`            |

Varints: `0xed` encodes as `ed 01`, `0xec` as `ec 01`, `0xe7` as `e7 01`,
`0x1200` as `80 24`, `0x1210` as `90 24`. Values below `0x80` are one byte.

The ML-DSA headers are an extension. The varsig registry has no entry for
ML-DSA; the crate uses the registered public key multicodec as the tag
and adds no hash segment, since FIPS 204 hashes internally. Tokens signed
with these headers are self-describing but may not verify against a
future registry assignment. The UCAN specification calls such algorithms
"off spec"; they are intended for deployments that control both ends.

Signature bytes:

| Algorithm | Length | Form                     |
|-----------|--------|--------------------------|
| Ed25519   | 64     | RFC 8032                 |
| ES256     | 64     | `r ‖ s`, fixed width     |
| ES256K    | 64     | `r ‖ s`, fixed width     |
| ML-DSA-44 | 2420   | FIPS 204                 |
| ML-DSA-65 | 3309   | FIPS 204                 |
| ML-DSA-87 | 4627   | FIPS 204                 |

## Delegation payload

| Key     | Type                    | Presence          |
|---------|-------------------------|-------------------|
| `iss`   | DID string              | required          |
| `aud`   | DID string              | required          |
| `sub`   | DID string or `null`    | required          |
| `cmd`   | string                  | required          |
| `pol`   | list of statements      | required          |
| `nonce` | bytes                   | required          |
| `meta`  | map                     | omitted when empty |
| `nbf`   | integer                 | omitted when unset |
| `exp`   | integer or `null`       | required          |

Canonical key order, which is what the encoder writes:
`aud, cmd, exp, iss, nbf, pol, sub, meta, nonce`.

`sub: null` is a powerline delegation. `exp: null` never expires.

## Invocation payload

| Key     | Type                    | Presence                          |
|---------|-------------------------|-----------------------------------|
| `iss`   | DID string              | required                          |
| `sub`   | DID string              | required                          |
| `aud`   | DID string              | omitted when equal to `sub`       |
| `cmd`   | string                  | required                          |
| `args`  | map                     | required                          |
| `prf`   | list of CIDs            | required; root first              |
| `meta`  | map                     | omitted when empty                |
| `nonce` | bytes                   | required; may be empty            |
| `exp`   | integer or `null`       | required                          |
| `iat`   | integer                 | omitted when unset                |
| `cause` | CID                     | omitted when unset                |

Canonical key order:
`aud, cmd, exp, iat, iss, prf, sub, args, meta, cause, nonce`.

The decoder rejects an `aud` equal to `sub` and an empty `meta`, since
the specification forbids both on the wire.

## Timestamps

Seconds since the Unix epoch, as integers. Values outside
`[-(2^53 - 1), 2^53 - 1]` are rejected on decode and cannot be constructed.

## Encoding rules

The codec is strict DAG-CBOR in both directions.

Emitted:

- Definite lengths only.
- Integers in their shortest encoding; 64-bit range.
- Floats as 64-bit; NaN and infinities are refused.
- Map keys are strings, sorted by byte length then bytewise.
- CIDs as tag 42 over bytes with a leading `0x00` identity prefix.

Rejected on decode, in addition to the inverse of each rule above:

- Duplicate map keys, non-string map keys, keys out of order.
- Tags other than 42; simple values other than `false`, `true`, `null`.
- Trailing bytes after the top-level item.
- Unknown keys in a token payload.

Unknown payload keys are an error rather than ignored: a field this
validator does not understand may carry meaning another validator would
enforce, and silently dropping it would let the two disagree about what
was signed.

## CIDs

CIDv1, codec `dag-cbor` (`0x71`), multihash `sha2-256` (`0x12`), computed
over the complete envelope bytes. The text form is multibase `base58btc`
and begins with `zdpu`. The decoder also accepts the base32 (`b…`) form.

## `did:key`

`did:key:z` followed by base58btc of the public key multicodec as an
unsigned varint and the raw key.

| Algorithm | Multicodec              | Prefix bytes | Key length | Text prefix |
|-----------|-------------------------|--------------|------------|-------------|
| Ed25519   | `ed25519-pub` `0xed`    | `ed 01`      | 32         | `z6Mk`      |
| P-256     | `p256-pub` `0x1200`     | `80 24`      | 33, compressed SEC1 | `zDn` |
| secp256k1 | `secp256k1-pub` `0xe7`  | `e7 01`      | 33, compressed SEC1 | `zQ3s` |
| ML-DSA-44 | `mldsa-44-pub` `0x1210` | `90 24`      | 1312       |             |
| ML-DSA-65 | `mldsa-65-pub` `0x1211` | `91 24`      | 1952       |             |
| ML-DSA-87 | `mldsa-87-pub` `0x1212` | `92 24`      | 2592       |             |

Other DID methods are carried as opaque strings and resolved through the
`Resolver` trait. DID URL parts (path, query, fragment) are preserved in
the string and ignored when principals are compared.

## Compatibility notes

- rs-ucan and the current JavaScript implementation emit `-rc.1` tags and
  always write `meta`, even when empty. Both decode here with
  `release_candidate_tags` enabled. Tokens emitted here use the released
  tags and omit an empty `meta`, so their CIDs differ from what those
  implementations would compute for the same content. This is a
  consequence of following the released specification.
- The multicodec table also registers `eddsa` as `0xd0ed` and `es256` as
  `0xd01200`. Varsig 1.0.0 uses `0xed` and `0xec`, and so do the fixtures
  in circulation. The crate uses the varsig values.
