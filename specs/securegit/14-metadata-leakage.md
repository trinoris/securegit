# 14. Metadata Leakage

## Overview

Everything an observer holding the encrypted repository can still learn. This is
the residue [01](01-threat-model.md) declared out of scope, enumerated, because
"out of scope" is only an acceptable answer if the reader knows what it covers.

**Status: INHERENT.** Most of this cannot be fixed within Git's object model.
The parts that can be are marked.

## Core Principle

> The contents are encrypted. The *shape* of the repository is not, and cannot
> be, because Git needs the shape to be a Git repository.

## What is visible

| | Observable | Why | Mitigable |
|---|---|---|---|
| M1 | Every file path and directory name | tree objects are not filtered | no |
| M2 | File sizes, ± 63 bytes of envelope | ciphertext preserves length | partially (padding) |
| M3 | Which commits touched which paths | tree diffs | no |
| M4 | Commit messages | commit objects are not filtered | no |
| M5 | Author name, email, timestamps | commit objects | no |
| M6 | Branch and tag names | refs | no |
| M7 | The commit graph — merges, rate, contributors | commit objects | no |
| M8 | Blob equality across paths, commits and branches | convergent encryption ([03](03-determinism.md)) | partially (`bindPath`) |
| M9 | Whether a change reverted to an earlier state | M8 over time | partially |
| M10 | Which files are protected at all | `.gitattributes` is plaintext | no |
| M11 | Recipient count, labels, fingerprints, join dates | `.securegit/recipients/` | no |
| M12 | Key generation in use per blob | envelope `keyId` | no |

## M1 is usually the biggest one

```
secrets/
├── prod-db-password.json
├── stripe-live-key.secret
└── customer-export-signing.pem
```

Every content byte is encrypted and the repository has still disclosed its
entire inventory: that production database credentials exist, that the Stripe
account is live, that customer exports are signed and by what. For an adversary
choosing where to spend effort, the inventory is often more useful than any one
file.

There are three honest responses, in the order they are worth trying:

1. **Do not encode the secret in the filename.** `config/production.json`
   discloses far less than `secrets/prod-db-password.json`, at no cost.
2. **If the existence of the thing is itself sensitive, it does not belong in
   this repository.** A secrets manager, an out-of-band file, a separate
   repository with a different audience. This is the correct answer and the one
   people resist.
3. Encrypt the paths too — rejected, below.

## Why paths are not encrypted

Encrypting paths means every tree object is rewritten, and the consequences
cascade until the result is not Git:

- `.gitattributes` matches on paths. A repository whose paths are ciphertext
  cannot express "encrypt `*.secret`", because there is no `.secret` to match.
- Every path-taking command — `git log <path>`, `git add`, `git checkout
  <path>`, every pathspec, every `.gitignore` — needs translation through a map
  that must itself be committed and encrypted, and consulted before Git parses
  its own arguments. There is no extension point for that.
- Merges of directory renames, `git mv`, submodules and sparse checkout each
  need bespoke handling.
- The path map becomes a single point of failure: lose it and the repository is
  an unnavigable set of blobs.

Tools that do this — Keybase's encrypted repositories, `git-remote-gcrypt` —
encrypt the *whole repository* and push an opaque blob, giving up server-side
Git entirely: no pull requests, no web review, no partial clone, no CodeCommit
integration. That is a coherent design and a different product. It is worth
noting as the escape hatch for anyone whose requirement is genuinely M1:
`git-remote-gcrypt` over the same S3 bucket, at the cost of every server-side
feature.

## M2: size, and padding

Ciphertext length equals plaintext length, so sizes leak. It matters more than
it sounds: a 32-byte protected file is a key, a 2 KB one is a config, and a
change from 1184 to 1201 bytes across a commit whose message says "rotate
staging password" is informative.

`padTo` in `.securegit/config.json`, off by default:

```json
{ "padTo": 4096 }
```

Pads plaintext to a multiple of `padTo` with a length-prefixed scheme before
encryption, so all small files look 4 KiB. The cost is real — every protected
file occupies the padded size in every commit that touches it, and delta
compression already does nothing for ciphertext ([12](12-diff-merge.md)).

Padding is deliberately **not** the default. It buys a coarse bucket, not
anonymity, and a user who enables it should have decided that sizes are part of
their threat model rather than inheriting it from a default.

## M8: equality, and what it costs

The one leak introduced by a *choice* in this design rather than by Git's
structure. [03](03-determinism.md) explains why there was no alternative and
what the keyed HMAC preserves (an adversary who guesses a plaintext still cannot
confirm the guess).

`bindPath = true` ([05](05-key-hierarchy.md)) removes cross-path equality — two
identical files at different paths get different blobs — while leaving
same-path-over-time equality intact, which is the part M9 depends on. It costs
rename detection. Neither setting removes M9.

## What an observer builds from all of this

```
   repo has 3 protected files, one added 2026-03-02
   the 32-byte one changes every ~90 days      → a rotated key
   the 4 KB one changed once, in a commit
     titled "point at new RDS instance"        → a database config
   4 contributors, 3 recipients, one removed
     2026-06-01                                → someone left in June
   commit rate drops to zero for 3 weeks
     in August                                 → a release freeze, or a holiday
```

None of that required breaking any cryptography. If that profile is itself
unacceptable, the requirement is not "encrypt the files" — it is "do not put
this in a repository the adversary can read", and no filter can deliver it.

## Test Cases

| Test | Test File | Fixture | Status |
|------|-----------|---------|--------|
| Ciphertext length equals plaintext length plus `63 + keyIdLen` | `src/envelope.test.ts` | — | ✅ |
| Padding rounds to a multiple of `padTo` | `src/envelope.test.ts` | — | 🔲 |
| Padded content round-trips exactly, including trailing NULs in the original | `src/envelope.test.ts` | — | 🔲 |
| Padding is deterministic ([03](03-determinism.md)) | `src/crypto.test.ts` | — | 🔲 |
| Files under `padTo` all yield the same ciphertext length | `src/envelope.test.ts` | — | 🔲 |
| A file above `padTo` rounds to the next multiple | `src/envelope.test.ts` | — | 🔲 |
| `padTo` change is refused without a rotation | `src/config.test.ts` | — | 🔲 |
| Padding disabled by default | `src/config.test.ts` | — | 🔲 |
| `status` reports which of M1–M12 apply to this repository | `src/cli.test.ts` | — | 🔲 |

## Relationship to Other Specs

- [01](01-threat-model.md) — where this was scoped out
- [03](03-determinism.md) — the source of M8 and M9
- [05](05-key-hierarchy.md) — `bindPath`, which narrows M8
- [12](12-diff-merge.md) — delta compression, which padding makes worse
