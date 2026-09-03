# 14. Metadata Leakage

## Overview

Everything an observer holding the encrypted repository can still learn. This is
the residue [01](01-threat-model.md) declared out of scope, enumerated, because
"out of scope" is only an acceptable answer if the reader knows what it covers.

**Status: INHERENT, except M2, which is IMPLEMENTED — and `status` now
reports which of M1–M12 apply.** Most of this cannot be fixed within Git's
object model. The parts that can be are marked. `padTo` (M2's mitigation) is
built: `src/envelope.ts`'s `seal`/`unseal` (a length-prefixed pad/unpad
scheme behind a new `flags` bit), `src/config.ts`'s `RepoConfig.padTo` (set
only at `init`, like `bindPath`), and every place that calls `seal` —
`clean`, `reencrypt`, `merge`, `filter-process`, `encrypt` — now threads it
through. `src/verify.ts`'s new `metadataReport()` — a static catalogue of
all twelve observables, not a live audit — is wired into `securegit status
--json`'s `metadata` field; the human-readable form gets a one-line pointer
to it rather than twelve lines repeated on every call. See "What this pass
actually built" below.

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

As built, `padTo` is set at `securegit init --pad-to <n>`, and — unlike
`bindPath` ([05](05-key-hierarchy.md), which now has its own dedicated
update path, `key rotate --bind-path`, since padding and path-binding are
not the same kind of change — there is deliberately no equivalent command
for `padTo`. Padding never enters key derivation, so changing it doesn't
need a rotation or a new generation at all: hand-edit `padTo` in
`.securegit/config.json`, then run `reencrypt` (already built,
[09](09-rotation-recovery.md)) — every protected file still tracked gets
re-sealed under the new value, since `reencrypt` compares against a
freshly-computed `clean()` output and stages whatever differs. Building a
`--pad-to <n>` flag on `key rotate` to match `--bind-path`'s shape was
considered and deliberately rejected: it would imply padding needs a new
generation the way `bindPath` genuinely does, which isn't true, and would
just be a second way to do what hand-edit-then-`reencrypt` already does.

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

## What this pass actually built

`src/envelope.ts`: `FLAG_PADDED` (`0x02`, the second flag bit — `bindPath`
already used bit 0), `padContent`/`unpadContent`, and `padTo?: number` on
`SealOptions`. `src/config.ts`: `RepoConfig.padTo` (always present, `0`
meaning disabled — same shape as `bindPath: boolean`, never optional) and
validated in `initConfig` (a non-negative integer, or refused). Every
caller that seals content — `clean` (`filter.ts`), `merge` (`merge.ts`),
`FilterProcessServer` (`process.ts`), and `encrypt`/`reencrypt`
(`cli.ts`) — now threads `padTo` through from `RepoConfig`.
`unseal`/`smudge`/`decrypt` need no such threading: the padded/unpadded
state travels with the envelope itself, in the flag bit.

- **Padding is applied to the *whole* pad-then-seal pipeline, not
  layered on top of an already-complete `seal()`.** The content tag, the
  file key, and the AEAD ciphertext are all derived from the padded buffer,
  not the original content — `seal(plaintext, {padTo})` is exactly
  `seal(padContent(plaintext, padTo), {…, flags: FLAG_PADDED})` internally.
  This keeps convergent encryption's guarantee intact: identical plaintext
  and `padTo` still produce identical ciphertext, since padding is a pure
  function of both.
- **The length prefix, not a "trim trailing zero bytes" heuristic, is what
  makes the round-trip exact.** Real content that itself ends in NUL bytes
  — not contrived, e.g. a fixed-width binary record format — would be
  silently truncated by the latter; the spec's own test case calls this out
  explicitly, and the length-prefixed design was chosen for exactly this
  reason rather than discovered as a bug afterward.
- **`padTo` is set only via `securegit init --pad-to <n>`, and deliberately
  gets no dedicated update command — not the same constraint `bindPath`
  has, even though it looked that way at the time this was first written.**
  `bindPath` later gained `key rotate --bind-path` ([05](05-key-hierarchy.md),
  [09](09-rotation-recovery.md)) precisely because it enters key
  derivation and genuinely needs a rotation boundary. Padding never enters
  derivation, so it never needed the equivalent primitive in the first
  place: `reencrypt` after a hand-edited `padTo` in `config.json` already
  covers changing it, for every currently-tracked protected file, with no
  rotation and no refusal required.
- **Proven against a real commit, not just `envelope.ts`'s own injected
  buffers.** A new `git.integration.test.ts` block runs `init --pad-to 256`,
  commits a 3-byte file, and checks the committed blob is well over 256
  bytes (padding actually inflated the ciphertext, not just set a flag) while
  the checked-out worktree file is still the exact original 3 bytes.
- **`metadataReport()` is a static catalogue, not a live audit.** Unlike
  `verify()`/`historyReport()`, which scan actual committed content, this
  just reports what the spec's own table already says is true, crossed with
  local config — it reads `RepoConfig.padTo`/`bindPath` and whether any
  `.securegit/recipients/*.json` files exist, nothing else. Nine of the
  twelve observables (M1, M3–M7, M9, M10, M12) are unconditional — inherent
  to committing to a Git repository at all, per the spec's own "Mitigable:
  no" — so `applies` is always `true` for them and the note always says so;
  only M2 (`padTo`) and M8 (`bindPath`) have a real mitigation state to
  report, and only M11 (recipient metadata) can genuinely not apply, when
  there are no recipients to have metadata about.
- **Wired into `status --json`'s `metadata` field, not the default
  human-readable output.** Printing twelve mostly-static lines on every
  plain `securegit status` would bury the four lines that actually vary
  (repository, repoId, session state, and now `padTo`) under boilerplate
  that never changes for a given repository. The human form instead gets
  one line pointing at `securegit status --json` for the full list — the
  two configurable ones (M2, M8) are already implied by the `padTo`/
  `bindPath` lines already printed just above it.

## Test Cases

| Test | Test File | Fixture | Status |
|------|-----------|---------|--------|
| Ciphertext length equals plaintext length plus `63 + keyIdLen` | `src/envelope.test.ts` | — | ✅ |
| Padding rounds to a multiple of `padTo` | `src/envelope.test.ts` | — | ✅ |
| Padded content round-trips exactly, including trailing NULs in the original | `src/envelope.test.ts` | — | ✅ |
| Padding is deterministic ([03](03-determinism.md)) | `src/envelope.test.ts` | — | ✅ |
| Files under `padTo` all yield the same ciphertext length | `src/envelope.test.ts` | — | ✅ |
| A file above `padTo` rounds to the next multiple | `src/envelope.test.ts` | — | ✅ |
| Padding disabled by default (envelope, and `RepoConfig.padTo`) | `src/envelope.test.ts`, `src/config.test.ts` | — | ✅ |
| `init --pad-to` round-trips through a real commit, larger blob, exact checkout | `src/git.integration.test.ts` | — | ✅ |
| `clean`/`smudge`/`merge`/`filter-process` all apply the repository's `padTo` | `src/filter.test.ts`, `src/merge.test.ts`, `src/process.test.ts`, `src/cli.test.ts` | — | ✅ |
| `padTo` change is refused without a rotation | `src/config.test.ts` | — | N/A — superseded by the design decided earlier in this document ("As built, `padTo` is set only via..." above): padding never enters key derivation, so unlike `bindPath` ([05](05-key-hierarchy.md)), changing it needs no rotation and no refusal — the documented path is hand-edit `config.json`, then `reencrypt`, which this file's own prose already settles. This row predates that decision; left standing as 🔲 would misleadingly suggest a refusal is still owed |
| `metadataReport()` lists all 12 observables, each with a code and a note | `src/verify.test.ts` | — | ✅ |
| Every inherent (non-configurable) observable always applies | `src/verify.test.ts` | — | ✅ |
| M2 reflects `padTo`: unmitigated at 0, partially mitigated once set | `src/verify.test.ts` | — | ✅ |
| M8 reflects `bindPath`: unmitigated off, partially mitigated once on | `src/verify.test.ts` | — | ✅ |
| M11 does not apply with no recipients, and does once one exists | `src/verify.test.ts` | — | ✅ |
| `status --json` includes the M1–M12 metadata report | `src/cli.test.ts` | — | ✅ |
| The human-readable form points at `status --json` for the M1–M12 detail | `src/cli.test.ts` | — | ✅ |

## Relationship to Other Specs

- [01](01-threat-model.md) — where this was scoped out
- [03](03-determinism.md) — the source of M8 and M9
- [05](05-key-hierarchy.md) — `bindPath`, which narrows M8
- [12](12-diff-merge.md) — delta compression, which padding makes worse
