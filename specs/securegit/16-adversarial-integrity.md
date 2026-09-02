# 16. Adversarial Integrity

## Overview

The threat model in [01](01-threat-model.md) names the adversaries. This spec
works through what they actually do, in order of how likely it is to happen to
somebody using this tool in 2026.

**Status: MOSTLY IMPLEMENTED for the v1-marked mitigations.** T3, T10, T12
and T13 are done and tested; T1's `verify` detector and T7/T8's key-material
hardening were already built as part of earlier specs and are cross-checked
here. What's still open needs specs 08/09 (T5) or spec 11 (part of T13) —
see the Test Cases table.

## The thesis

> Confidentiality of blob contents is the easy half and it is finished at
> [04](04-envelope-format.md). Everything left is about an adversary who does
> not attack the cipher — they attack the *configuration*, the *workflow*, or
> the files the cipher was never pointed at.

## Attack catalogue

| | Attack | Requires | Effect | Detected / prevented by |
|---|---|---|---|---|
| T1 | Attribute downgrade | push access | next commit of a path lands in plaintext | `verify` ([13](13-verify.md)) — **v1** |
| T2 | Local filter substitution | local account access | `clean` becomes `cat` | nothing; local access is game over |
| T3 | Blob relocation | push access | ciphertext moved to a path where its plaintext is dangerous | `bindPath`, signed commits |
| T4 | Blob rollback | push access | a path silently reverts to an older secret | signed commits, branch protection |
| T5 | Hostile recipient | push access + a merged commit | attacker receives every future generation | `verify --access`, review — **v1** |
| T6 | Recovery theft | both halves of an export | full, permanent, invisible read access | split storage, export log — **v1** |
| T7 | Session theft | code execution as the user | the master key | `0600`, tmpfs, TTL — **v1** |
| T8 | Offline passphrase attack | the keyring file | the master key | scrypt cost, length floor — **v1** |
| T9 | Equality and size analysis | the ciphertext repository | which files changed, when, and back to what | `bindPath`, `padTo` ([14](14-metadata-leakage.md)) |
| T10 | Hostile `.git` directory | delivering a repository as a directory | arbitrary code execution | never `install` into an untrusted `.git` — **v1** |
| T11 | Supply chain | compromising this package or a dependency | everything | zero runtime dependencies — **v1** |
| T12 | Plaintext residue | ordinary editor and merge behaviour | plaintext committed or left on disk | `.gitignore` defaults, `verify` — **v1** |
| T13 | Envelope denial of service | push access | out-of-memory on every colleague's checkout | `maxFileBytes` — **v1** |

## T1 — attribute downgrade

`.gitattributes` is an ordinary tracked file. Delete one line and the next
commit of the matching path is stored in plaintext. Nothing errors, nothing
warns, and the person who commits it is not the person who removed the line.

It is also the *accident* case: a merge resolution that drops a line, a
`.gitattributes` rewritten by a tool, a directory rename that leaves a pattern
matching nothing ([13](13-verify.md), L4). Accident and attack have the same
signature and the same detection.

Mitigations, all cheap, all v1:

- `verify` compares tracked paths against `git check-attr` and reads the first
  bytes of every protected blob. Run it in `pre-push` and in CI.
- `install --hooks` writes the `pre-push` hook.
- `verify --history` finds a downgrade that already landed.

There is no cryptographic fix. The repository cannot contain a value that proves
`.gitattributes` was not edited, because whoever edits it can edit that too.
This is a code-review problem with a detector attached.

## T3 and T4 — relocation and rollback

The AAD ([04](04-envelope-format.md)) binds the envelope's own header, and the
path when `bindPath` is set. It does not and cannot bind *where in history* a
blob sits, because the blob is created before the commit that contains it.

So an adversary with push access can:

- **T3:** copy the blob at `config/staging.json` over `config/production.json`.
  With `bindPath = false` it decrypts perfectly, and a deployment reads staging
  credentials — or, in the other direction, production credentials are written
  to a path a wider audience can read. `bindPath = true` makes this fail
  authentication.
- **T4:** restore an earlier ciphertext of a path. It decrypts perfectly,
  because it is genuinely that path's earlier content. `bindPath` does not help,
  and nothing in the envelope can.

Both are ordinary Git tampering, and Git's own answer applies: signed commits
and protected branches. `securegit` states the limit rather than implying the
authentication tag covers more than it does — a per-blob GCM tag proves *this
ciphertext was produced by a key holder*, not *this ciphertext belongs here*.

## T5 — hostile recipient

`.securegit/recipients/` is committed, so adding a recipient is a commit. A
commit that adds `attacker.json` alongside a plausible refactor is a
supply-chain attack with an unusually clear diff — and one that gains the
attacker nothing until the next `key rotate` wraps the new generation for them.

- `verify --access` lists every recipient with the commit that added it.
- `key rotate` prints the recipient list and requires confirmation of the count.
- `addedBy` records the identity that performed the addition.
- Signed commits make the addition attributable.

## T6 — recovery theft

The one path that is total, permanent and invisible ([09](09-rotation-recovery.md)).
The two halves must not share a storage medium, a backup, or a password manager.
The committed export log makes the *existence* of an export visible even when the
holder is not.

## T7 and T8 — key material at rest

- **T7 (session):** mode `0600`, `$XDG_RUNTIME_DIR` when available so it is
  `tmpfs`, 8-hour default TTL, `securegit lock`. Code execution as the user
  defeats all of it; the goal is bounding the window, not closing it.
- **T8 (keyring):** scrypt `N = 2^16`, a 12-character floor, parameters raised
  over time and re-wrapped on unlock. An adversary with the keyring file and a
  weak passphrase wins, which is why `key init` shows an estimate and why the
  hardware providers in [06](06-key-provider-port.md) exist.

## T10 — hostile `.git`

`.git/config` names executables that Git runs. A repository delivered as a
directory or tarball — not a `git clone`, which does not copy config — can
therefore ship a `filter.securegit.clean` pointing anywhere.

`securegit install` refuses to run against a repository whose `.git/config`
already contains filter, diff or merge entries it did not write, and prints
them, rather than silently overwriting. The check (`src/install.ts`) compares
the existing value of each identity key against every command line securegit
itself would produce, for either supported form — so switching between
`clean`/`smudge` and `--process` is never mistaken for tampering — and refuses
anything else without an explicit `force: true`, which has no CLI flag on
purpose. `securegit status` shows the configured command lines in full, so
"what will actually run" is one command away.

## T11 — supply chain

**Zero runtime dependencies.** Everything comes from `node:crypto`, `node:fs`
and `node:child_process`. This is not minimalism for its own sake: an
`npm install` of a package that holds encryption keys is an unusually attractive
place to put a postinstall script, and a dependency tree is a set of parties who
can be compelled or compromised.

Development dependencies are `typescript`, `vitest` and its coverage plugin, and
they never ship. `package.json` declares `files` so the published tarball is
`dist/`, `src/`, the licence and the README.

## T12 — plaintext residue

The attack that requires no attacker. `.gitattributes` protects the paths it
names, and ordinary tooling produces neighbours it does not:

```
.env            protected
.env~           editor backup       — plaintext, unprotected
.env.swp        vim swap            — plaintext, unprotected
.env.save       editor              — plaintext, unprotected
config/production.json.orig         — left by a conflicted merge, PLAINTEXT
config/production.json.rej          — left by a failed patch, PLAINTEXT
config/production.json.bak          — left by anything
```

`*.orig` is the sharp one: a conflicted merge writes the *plaintext* pre-merge
content there, and it is a file the user did not create and does not think
about. `git add -A` picks it up.

Mitigations, all v1:

- `securegit protect <pattern>` also writes matching `.gitignore` entries for
  `<pattern>~`, `<pattern>.orig`, `<pattern>.rej`, `<pattern>.bak`,
  `<pattern>.save` and `.<basename>.sw?`.
- `verify` reports any *untracked* file matching those shapes next to a
  protected path, so the residue is visible even when `.gitignore` catches it.
  Implemented as a third `Finding` kind, `'residue'` — checked against the
  real filesystem (not `git status`), since the point is catching a file
  `.gitignore` would otherwise hide from view entirely. The plain suffixes
  (`~`, `.orig`, `.rej`, `.bak`, `.save`) are a direct existence check;
  vim's actual swap filename varies (`.swp`, then `.swo`, `.swn`, …) so that
  one scans the directory for anything sharing the `.<basename>.sw` prefix
  instead of checking one fixed name. `RESIDUE_SUFFIXES` is exported from
  `install.ts` so both places share one list rather than two that could
  drift. Contributes to `EXIT_VERIFY_MISCONFIGURED` (2), not the leak exit
  (5) — real plaintext exposure, but not yet a committed one.
- The merge driver ([12](12-diff-merge.md)) writes no temporary files outside a
  `0700` directory and removes them on every exit path.
- `reencrypt` never writes an intermediate plaintext file.

## T13 — envelope denial of service

A 4 GiB envelope committed by an adversary is decrypted by everyone who checks
out that branch, and AES-GCM must buffer the whole thing to authenticate it. The
`maxFileBytes` limit ([04](04-envelope-format.md)) is checked against the
buffer length *before* any derivation or allocation — the format carries no
declared length to trust — and the
`filter-process` implementation bounds in-flight bytes across concurrent
requests ([11](11-filter-process.md)).

## Non-goals, restated

- **T2 is out of scope.** An adversary running code as the user has the
  plaintext worktree and the session cache. No filter helps.
- **Repository integrity is Git's job.** Signed commits, protected branches,
  push rules. This tool authenticates blobs, not history.
- **Side channels.** Node's AES-GCM is OpenSSL's, and tag comparison happens
  there. Our own comparisons — fingerprints, checksums, recovery codes — use
  `timingSafeEqual`; it costs nothing and removes the question.

## Test Cases

| Test | Test File | Fixture | Status |
|------|-----------|---------|--------|
| T1: removed attribute is found by `verify` | `src/verify.test.ts` | `attributes/` | ✅ |
| T1: downgrade already in history is found by `verify --history` | `src/verify.test.ts` | — | ✅ |
| T3: relocated blob fails under `bindPath = true` | `src/envelope.test.ts` | — | ✅ |
| T3: relocated blob decrypts under `bindPath = false`, as documented | `src/envelope.test.ts` | — | ✅ |
| T5: `verify --access` names the commit that added each recipient | `src/verify.test.ts` | `identities/` | 🔲 |
| T5: `rotate` requires confirmation of the recipient count | `src/cli.test.ts` | — | 🔲 |
| T6: the recovery file alone does not decrypt without the code | `src/recovery.test.ts` | — | ✅ |
| T6: an export appends to the committed recovery log, not the code or file | `src/recovery.test.ts` | — | ✅ |
| T7: session file with loose permissions is deleted, not used | `src/session.test.ts` | — | ✅ |
| T8: scrypt parameters meet the floor | `src/provider.test.ts` | — | ✅ |
| T10: `install` refuses over foreign filter config | `src/install.test.ts` | — | ✅ |
| T11: the published package has zero runtime dependencies | `src/package.test.ts` | — | ✅ |
| T11: no `src/` file imports outside `node:` builtins | `src/package.test.ts` | — | ✅ |
| T12: `protect` writes the residue `.gitignore` entries | `src/install.test.ts` | — | ✅ |
| T12: `verify` reports an untracked `.orig` beside a protected path | `src/verify.test.ts` | `legacy-plaintext/` | ✅ |
| T12: `verify` reports an untracked vim swap file beside a protected path | `src/verify.test.ts` | — | ✅ |
| T12: `verify` does not flag a residue-shaped file that is itself tracked | `src/verify.test.ts` | — | ✅ |
| T12: merge driver leaves no temporary file behind, including on error | `src/merge.test.ts` | — | ✅ |
| T13: oversized envelope is refused before allocation | `src/envelope.test.ts` | — | ✅ |
| T13: `filter-process` bounds in-flight bytes | `src/process.test.ts` | — | 🔲 |
| All non-AEAD comparisons use `timingSafeEqual` | `src/package.test.ts` | — | ✅ |

## Relationship to Other Specs

- [01](01-threat-model.md) — the adversaries these attacks belong to
- [04](04-envelope-format.md) — what the AAD binds, and what it does not
- [05](05-key-hierarchy.md) — `bindPath`, the T3 mitigation
- [09](09-rotation-recovery.md) — the recovery file/code split behind T6
- [12](12-diff-merge.md) — the merge driver, source of the `.orig` residue
- [13](13-verify.md) — the detector for T1, T5 and T12
