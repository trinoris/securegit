# 04. Envelope Format

## Overview

The on-disk representation of an encrypted blob: what `clean` writes, what
`smudge` reads, and the rules that keep a repository written by version 1
readable by version 9.

**Status: IMPLEMENTED.** `src/envelope.ts` — `seal`/`unseal`/`parseEnvelope`/
`looksLikeEnvelope` — matches this document exactly; format-breaking
deviations found while building it were corrected here, not there (there is
no declared-length field, for one — see the edge-case table below).
`tests/fixtures/envelopes/v1-basic.bin` and `v1-bindpath.bin` are two
envelopes sealed once and committed, asserted in `src/vectors.test.ts` to
still decrypt to their frozen plaintext under their frozen key — the "must
decrypt forever" promise, checked rather than assumed. The tampered-envelope
fixtures this file's own 00-test-plan.md fixture catalogue lists
(`v1-truncated.bin`, `v1-flipped.bin`, and the rest) were deliberately not
built as separate committed files: every one of those rows is already
covered in `src/envelope.test.ts` by tampering a freshly-sealed envelope
in memory, which is a test about today's parser rejecting corruption, not
about compatibility with something committed in the past — a static fixture
would add a file without adding signal.

## Core Principle

> The format is the compatibility surface. Once a byte of it has been committed
> to somebody's repository, it is permanent — so version it explicitly, refuse
> what you do not recognise, and never repurpose a field.

## Layout

Binary, fixed header, no length-prefixed sections to get wrong.

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 11 | `magic` | `\0SECUREGIT\0` |
| 11 | 1 | `format` | `0x01` |
| 12 | 1 | `algorithm` | see table below |
| 13 | 1 | `flags` | bit 0 = `bindPath`; bit 1 = `padded` ([14](14-metadata-leakage.md), see below); bits 2–7 reserved, must be 0 |
| 14 | 1 | `keyIdLen` | `n`, 1–64 |
| 15 | n | `keyId` | ASCII, `<generation>.<fingerprint>` |
| 15+n | 32 | `tag` | content tag ([03](03-determinism.md)) |
| 47+n | 16 | `authTag` | AES-GCM authentication tag |
| 63+n | — | `ciphertext` | same length as the plaintext, or the padded content when `padded` is set |

Overhead is `63 + n` bytes — 81 for a typical 18-character `keyId`.

```
\0SECUREGIT\0 01 01 00 12 "3.a1b2c3d4e5f60718" ┃ tag(32) ┃ authTag(16) ┃ ct…
└──────────────── AAD ─────────────────────────┘
```

**AAD** is the header from offset 0 through the end of `keyId` inclusive, plus
`0x00 ‖ path` when `bindPath` is set. Every field that changes the meaning of
the ciphertext is therefore authenticated: an adversary cannot flip `flags`,
renumber the generation, or downgrade `algorithm` without the tag check failing.

### Padding (bit 1 of `flags`)

When `padded` is set, the *plaintext of the ciphertext* — what `aeadEncrypt`
actually sees, before this header's own AAD — is not the caller's original
content directly, but:

```
[4-byte BE length][original content][zero padding to the next multiple of padTo]
```

`unseal` reads the 4-byte length first and returns exactly that many bytes
after it, discarding the rest — never "trim trailing zero bytes," which
would silently corrupt content that legitimately ends in NUL bytes of its
own. `padTo` itself is **not** part of the envelope; it lives in
`.securegit/config.json` ([14](14-metadata-leakage.md)) and is needed only
to *produce* a padded envelope, never to read one back — the length prefix
already says everything `unseal` needs, which is what makes the format
self-describing regardless of what `padTo` a repository is configured with
now, or was configured with when a given blob was sealed.

The content tag, the file key, and the AEAD encryption itself all operate on
the padded buffer as a whole, not the original content — padding is applied
before every other step in `seal`, unwound after every other step in
`unseal`. This costs nothing for determinism ([03](03-determinism.md)):
padding a given plaintext to a given `padTo` is itself a pure function, so
the composition (pad, then seal) is exactly as deterministic as `seal` alone.

### Why binary rather than the JSON envelope in the sketch

JSON with base64 costs 33% on every protected file, and protected files are
often the ones committed most often. It also invites Git's text conversions to
take an interest in a file that must not be touched
([02](02-git-integration.md)). The format is machine-read by exactly one program;
legibility buys nothing that `securegit inspect` cannot provide.

### Why the magic starts with NUL

Git's automatic binary detection classifies content containing a NUL in the
first 8000 bytes as binary, and skips CRLF conversion for it. The leading NUL is
a second line of defence behind the mandatory `-text` attribute. It also means
`grep`, editors and diff tools treat the blob as binary rather than offering to
"fix" its line endings.

## Algorithms

| Id | Scheme | Status |
|---|---|---|
| `0x01` | AES-256-GCM, HKDF-SHA256, keyed-convergent nonce | current |
| `0x02` | reserved — AES-256-GCM-SIV, if it reaches `node:crypto` | not allocated |
| `0x03` | reserved — XChaCha20-Poly1305 | not allocated |

An id is never redefined. A change to any HKDF label, to the tag construction,
or to the AAD composition is a **new id**, because the old one must keep
decrypting blobs already in somebody's history.

## Version handling

- `format` unknown → **error**, both directions, with the observed value in the
  message. Never guess, never fall back to passthrough: passthrough on `clean`
  writes plaintext.
- `algorithm` unknown → error on `smudge`, error on `clean`.
- `flags` with a reserved bit set → error. Reserved bits are how a future
  version signals something we would be wrong to ignore.
- `keyId` naming a generation not in the keyring → not a format error; see
  [07](07-unlock-session.md) for the locked/missing-key path.

## Detection and passthrough

`clean` and `smudge` both accept arbitrary bytes and must never corrupt input
they do not understand.

### `clean`

```
input begins with magic, parses as a valid envelope,
names a keyId in this repository's keyring,
and authenticates under that key
        → emit input unchanged        (idempotent)

otherwise
        → encrypt under the current generation
```

The authentication step matters. Detecting "looks like an envelope" on the
header alone would let a crafted plaintext — a file that happens to begin with
the magic — pass through `clean` **unencrypted**, which is the one failure this
tool exists to prevent. `clean` always has the key ([07](07-unlock-session.md)
makes that a hard requirement), so it can always afford the check.

Idempotence is not hypothetical: it is what happens when a clone without
`install` checks out ciphertext, the user runs `git add`, and the filter is
configured only later.

### `smudge`

```
input begins with magic and parses
        → decrypt, or fall back to emitting the input unchanged when the key
          is unavailable ([07](07-unlock-session.md))

otherwise
        → emit input unchanged        (predates securegit, or was committed
                                       without the filter installed)
```

## Edge cases, decided

| Case | Behaviour | Why |
|---|---|---|
| Empty file | encrypted; result is `63+n` bytes | passthrough would leak that the file is empty, and would make `clean` non-injective |
| File larger than `maxFileBytes` (default 512 MiB) | error | GCM must buffer for the auth tag; failing loudly beats an out-of-memory kill mid-`add` |
| Envelope truncated below the header minimum | parse error, naming actual and required lengths | a truncated blob is corruption, not plaintext |
| Envelope with a truncated *ciphertext* | authentication failure | the format carries no length field, so the parser cannot see it — only the AEAD tag can, which is why `smudge` must never emit unauthenticated bytes |
| Envelope whose `authTag` fails | error naming the path | tampering or a wrong key; never emit the raw bytes as if they were plaintext |
| Plaintext that begins with the magic | encrypted normally | the authentication check in `clean` distinguishes it |
| `keyIdLen` of 0, or beyond the buffer | error | |

## Inspection

`securegit inspect <file>` prints the header without needing a key:

```
format      1
algorithm   1  AES-256-GCM / HKDF-SHA256 / convergent
flags       bindPath=false
keyId       3.a1b2c3d4e5f60718
tag         9f2c…  (32 bytes)
ciphertext  1184 bytes
```

Useful in a keyless clone to answer "which generation is this, and do I have
it?" without a decryption attempt. It reveals nothing an observer with the blob
did not already have.

## Test Cases

| Test | Test File | Fixture | Status |
|------|-----------|---------|--------|
| Encode/decode round-trips for 0, 1, 15, 4095, 4096, 4097, 64 KiB inputs | `src/envelope.test.ts` | — | ✅ |
| Committed v1 envelopes still decrypt | `src/vectors.test.ts` | `envelopes/v1-*.bin` | ✅ |
| Unknown `format` errors rather than passing through | `src/envelope.test.ts` | — | ✅ |
| Unknown `algorithm` errors on parse, guarding both directions | `src/envelope.test.ts` | — | ✅ |
| A set reserved flag bit errors | `src/envelope.test.ts` | — | ✅ |
| Flipping any header byte fails authentication | `src/envelope.test.ts` | — | ✅ |
| Flipping any ciphertext byte fails authentication | `src/envelope.test.ts` | — | ✅ |
| Truncation below the header minimum errors, naming both lengths | `src/envelope.test.ts` | — | ✅ |
| Ciphertext truncation is caught by authentication, not the parser | `src/envelope.test.ts` | — | ✅ |
| `clean` of a valid envelope is a passthrough | `src/filter.test.ts` | `envelopes/` | ✅ |
| `clean` of plaintext that begins with the magic encrypts it | `src/filter.test.ts` | `blobs/magic-prefixed` | ✅ |
| `clean` of an envelope from an unknown keyId encrypts rather than passes through | `src/filter.test.ts` | — | ✅ |
| Empty input produces a `63+n` byte envelope | `src/envelope.test.ts` | — | ✅ |
| Oversized input errors before allocating | `src/envelope.test.ts` | — | ✅ |
| `bindPath` envelope fails to decrypt under a different path | `src/envelope.test.ts` | — | ✅ |
| `inspect` works with no key present | `src/envelope.test.ts` | `envelopes/` | ✅ |
| `padded` envelope round-trips exactly, flag set on seal, cleared on parse of an unpadded one | `src/envelope.test.ts` | — | ✅ |
| Padding rounds to a multiple of `padTo`; a file above it rounds to the next multiple | `src/envelope.test.ts` | — | ✅ |

## Relationship to Other Specs

- [03](03-determinism.md) — where `tag` comes from
- [05](05-key-hierarchy.md) — `keyId`, generations and fingerprints
- [07](07-unlock-session.md) — the locked-key path through `smudge`
- [16](16-adversarial-integrity.md) — what the AAD does and does not bind
