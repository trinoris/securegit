# 05. Key Hierarchy

## Overview

Every key in the system, where it comes from, and what it is allowed to touch.

**Status: IMPLEMENTED.** The master key, per-file derivation and generations
are all in `src/crypto.ts` and `src/keyring.ts`. `bindPath` works; hardware
providers behind [06](06-key-provider-port.md) do not exist yet — this
document describes them, `passphrase-file` is what ships. The
`securegit/tag/v1` and `securegit/dek/v1` HKDF labels are pinned directly in
`src/vectors.test.ts`, independent of the envelope round-trip in
[03](03-determinism.md) and [04](04-envelope-format.md): `deriveTagKey`,
`contentTag` and `deriveFileKey` are each called against a fixed key and
plaintext in `tests/fixtures/vectors/v1.json`'s `hkdf` block and compared to
frozen hex, so a rename of either label is caught here even though the
envelope-level vectors would also — indirectly — notice the same change.

## Core Principle

> One secret per repository is the root. Everything below it is *derived*, never
> stored — because a stored per-file key would have to be wrapped, and wrapping
> is randomised, and randomised is the one thing [03](03-determinism.md) forbids.

## The tree

```
   passphrase / TPM / PIV / recovery code        ← key provider ([06])
             │
             │  wrap / unwrap  (randomised: fine, never enters a blob)
             ▼
   ┌───────────────────────────────────────┐
   │  RMK — repository master key          │   32 bytes, one per generation
   │  generation 1, 2, 3 …                 │   never leaves the workstation
   └──────┬────────────────────────┬───────┘
          │                        │
     HKDF │ "securegit/tag/v1"     │ HKDF  "securegit/dek/v1"
          ▼                        │       salt = tag
   ┌─────────────┐                 ▼
   │   K_tag     │          ┌─────────────┐
   │  (secret)   │          │  DEK        │   32 bytes, per distinct content
   └──────┬──────┘          │  (derived)  │
          │                 └──────┬──────┘
   HMAC over plaintext             │
          │                        │  AES-256-GCM
          ▼                        ▼
   ┌─────────────┐          ┌─────────────┐
   │  tag (32B)  │─────────▶│ ciphertext  │
   │  stored     │  salt    │             │
   └─────────────┘          └─────────────┘
```

## Derivations

All HKDF-SHA256. Labels are byte-exact and version-suffixed; changing one is a
new `algorithm` id ([04](04-envelope-format.md)), never an edit.

| Output | IKM | Salt | Info | Length |
|---|---|---|---|---|
| `K_tag` | RMK | — | `securegit/tag/v1` | 32 |
| `DEK` | RMK | `tag` | `securegit/dek/v1` `‖ 0x00 ‖ path` when `bindPath` | 32 |
| `KEK` (passphrase provider) | scrypt output | — | `securegit/kek/v1` | 32 |
| recipient wrap key | X25519 shared secret | `ephPub ‖ recipientPub` | `securegit/recipient/v1` | 32 |
| recovery wrap key | recovery code bytes | — | `securegit/recovery/v1` | 32 |

`tag = HMAC-SHA256(K_tag, [path ‖ 0x00 ‖] plaintext)`.

## Why DEKs are derived, not wrapped

The sketch this package started from proposed a random per-file DEK, wrapped by
the master key and stored in the envelope. That cannot work here, and the reason
is worth stating because it is the kind of thing a reviewer will propose again:

- A random DEK makes the envelope non-deterministic, which breaks Git
  ([03](03-determinism.md)).
- Wrapping the DEK deterministically requires a deterministic wrap nonce, which
  must be derived from something — and the only material available is the
  content. At which point the DEK is a function of the content and the master
  key, which is what derivation already gives us, minus 48 bytes per file and
  minus a second AEAD invocation.

Derivation keeps the security property the per-file DEK was there to provide:
**compromise of one file's key reveals nothing about any other file**, because
HKDF is not invertible and the DEKs share no material beyond an RMK the attacker
would need anyway.

## Generations

Rotation adds a generation; it does not replace one. The keyring holds every
RMK it has ever had, because history encrypted under generation 1 must stay
readable after the move to generation 4.

```
keyring
├── generation 1   (2026-01-14)   ← decrypt only
├── generation 2   (2026-04-02)   ← decrypt only
└── generation 3   (2026-09-01)   ← current: encrypt + decrypt
```

- `clean` always uses `current`.
- `smudge` uses the generation named in the envelope's `keyId`.
- Old generations are never deleted. Losing one makes part of the history
  permanently unreadable, and Git history is not something a user can be
  expected to rewrite on request.

## The fingerprint is checked again after unwrap, not just trusted

`gen.fingerprint` is recorded once, at creation, computed from the real key.
After every successful `unwrap`, `unlockKeyring` (`src/keyring.ts`) recomputes
the fingerprint of whatever came back and compares it — constant-time —
against that recorded value. A mismatch is not the generic "authentication
failed" a bad passphrase produces (the provider already ruled that out by
succeeding); it means the keyring *file itself* disagrees with what a correct
unwrap produced, which is a keyring-integrity problem, not a credentials
problem. It is reported through the caller's `warn` callback, distinctly, and
the generation is treated as still locked rather than trusted.

## `keyId` and fingerprints

```
keyId = "<generation>.<fingerprint>"
fingerprint = SHA-256("securegit/keyid/v1" ‖ RMK)[0..8]  →  16 lowercase hex
```

The generation alone would be enough to select a key. The fingerprint is there
so that a mismatch is *diagnosable*: "this blob wants generation 3 fingerprint
`a1b2…`, your keyring's generation 3 is `9f0c…`" is an actionable message, where
a failed GCM tag is not. Publishing it costs nothing — it is a one-way function
of a 256-bit secret, truncated.

## `bindPath`

Whether the file's path enters the tag and DEK derivations, and the AAD.

| | `bindPath = false` (default) | `bindPath = true` |
|---|---|---|
| Identical content at two paths | identical blobs | different blobs |
| Rename detection (`git log --follow`, `-M`) | works | broken — a move rewrites the blob |
| Moving a file | no new blob | new blob every move |
| Adversary relocates a ciphertext blob to another path ([16](16-adversarial-integrity.md), A7) | decrypts successfully | fails authentication |

The default is `false`, matching established tooling, because rename stability
is a daily cost and blob relocation is an attack that presupposes push access —
which signed commits and protected branches already address, and which
`bindPath` addresses only for protected files.

Set in `.securegit/config.json` at `init`. **It cannot be changed afterwards
without re-encrypting**, because it changes every derivation; `securegit key
rotate --bind-path` is the supported path ([09](09-rotation-recovery.md)) and
leaves old generations readable under the old setting. The flag is recorded in
each envelope's `flags` byte so a blob always states which rule produced it.

## The tracked half: `.securegit/config.json`

Everything above this line lives outside the repository. One small file lives
*inside* it, tracked and committed, because a clone with no key yet still needs
to know which keyring to ask for:

```json
{ "version": 1, "repoId": "4f9a1c22b3e05617...", "bindPath": false }
```

`src/config.ts` creates it once, at `init`, and refuses to run a second time —
`repoId` is generated then and never changes. It refuses outside a Git
checkout (accepting either a `.git` directory or a worktree's `.git` *file*),
and it is written with ordinary file permissions: unlike the keyring or the
session cache, this file is supposed to be world-readable, because it carries
nothing an observer with the repository doesn't already have. `bindPath` is set
here once and, per above, cannot be changed without a rotation.

## Key material at rest

| Key | Where | Protection |
|---|---|---|
| RMK (all generations) | `~/.securegit/repos/<repoId>/keyring.json` | wrapped by the key provider |
| RMK (unlocked) | session cache ([07](07-unlock-session.md)) | file mode `0600`, TTL, `tmpfs` where available |
| Identity private key | `~/.securegit/identity.json` | wrapped by the key provider |
| `K_tag`, DEK | process memory only | never written |
| RMK wrapped to a recipient | `.securegit/recipients/*.json` **in the repo** | X25519 public-key encryption ([08](08-multi-recipient.md)) |
| RMK wrapped to a recovery code | an exported file, wherever the user puts it | high-entropy code, held offline ([09](09-rotation-recovery.md)) |

Nothing in this table places unwrapped key material inside the repository.
`initConfig()` (`src/config.ts`) now refuses this mistake at the source: an
optional `home` option, always passed by `cli.ts`'s `cmdInit`, checks
whether `home`'s own `.securegit` root would resolve inside the repository
being initialised (nested under it, or the repository itself) and throws
before anything is written. Optional so every existing caller that never
passed `home` at all keeps working — this is `init`-time defense in depth
on top of, not instead of, `verify`'s own equivalent check.

## Test Cases

| Test | Test File | Fixture | Status |
|------|-----------|---------|--------|
| HKDF labels match the committed vectors | `src/vectors.test.ts` | `vectors/` | ✅ |
| Two different plaintexts yield unrelated DEKs | `src/crypto.test.ts` | — | ✅ |
| Fingerprint is stable and 16 hex characters | `src/crypto.test.ts` | — | ✅ |
| `rotate` preserves every earlier generation | `src/keyring.test.ts` | — | ✅ |
| `clean` uses `current`, `smudge` uses the envelope's generation | `src/filter.test.ts` | — | ✅ |
| Blob from generation 1 decrypts after two rotations | `src/git.integration.test.ts` | `repo-protected/` | ✅ |
| Mismatched fingerprint produces a diagnostic, not a tag failure | `src/keyring.test.ts` | — | ✅ |
| `bindPath=true` envelope fails under a different path | `src/envelope.test.ts` | — | ✅ |
| `bindPath` is recorded in `flags` and honoured on decrypt | `src/envelope.test.ts` | — | ✅ |
| Changing `bindPath` in config does not silently break old blobs | `src/filter.test.ts` | — | ✅ (`unseal()` has no `bindPath` parameter at all — decrypt always uses each envelope's own recorded flag, structurally, never a caller's "current config" value; `keyring.ts` has no bindPath concept to test in the first place) |
| Keyring inside a working tree is refused at `init` | `src/config.test.ts` | — | ✅ |
| Keyring file is created with mode `0600` | `src/keyring.test.ts` | — | ✅ |

## Relationship to Other Specs

- [03](03-determinism.md) — the constraint that forced derivation over wrapping
- [04](04-envelope-format.md) — where `keyId` and `flags` are carried
- [06](06-key-provider-port.md) — what wraps the RMK
- [08](08-multi-recipient.md) — the second wrapping path
- [09](09-rotation-recovery.md) — how generations are added
