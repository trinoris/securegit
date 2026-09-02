# Client-Side Git Encryption

Design for `@trinoris/securegit` — a Git clean/smudge filter that encrypts
selected files on the workstation, so the repository is ciphertext everywhere it
goes afterwards.

> **The boundary is the process, not the network.** Plaintext exists in the
> working tree on a machine that holds a key. `.git/objects`, the remote, the
> mirror, the backup and the bundle hold ciphertext, and no cloud provider ever
> holds anything that can decrypt it.

The lifecycle, which is the whole architecture:

```
   worktree                          object database              remote
   ────────                          ───────────────              ──────
   plaintext  ──── clean ─────────▶  ciphertext  ──── push ────▶  ciphertext
   plaintext  ◀─── smudge ────────   ciphertext  ◀─── fetch ───   ciphertext
                   textconv ──────▶  plaintext, for display only
```

Three properties make it work rather than merely encrypt:

1. `clean` is a **pure function of its input**, so Git's change detection still
   works ([03](03-determinism.md)).
2. `filter.securegit.required = true`, so a missing key **fails the commit**
   instead of storing plaintext ([02](02-git-integration.md)).
3. The master key is wrapped by something the cloud provider does not hold — and
   a provider that could be compelled is marked as such, in the tool's own
   output ([06](06-key-provider-port.md)).

## Documents

### Foundations (01–03)
| # | Document | Description |
|---|----------|-------------|
| 01 | [Threat Model & Trust Boundary](01-threat-model.md) | Who the adversaries are, and the four things this does not do |
| 02 | [Git Integration Model](02-git-integration.md) | Filters not hooks, and the attributes that must be set |
| 03 | [Determinism](03-determinism.md) | **The load-bearing constraint** — why a random nonce breaks Git |

### Cryptography (04–06)
| # | Document | Description |
|---|----------|-------------|
| 04 | [Envelope Format](04-envelope-format.md) | The bytes, the AAD, and the passthrough rules |
| 05 | [Key Hierarchy](05-key-hierarchy.md) | Master key, derived per-file keys, generations |
| 06 | [Key Provider Port](06-key-provider-port.md) | Passphrase, TPM, PIV, KMS behind one interface |

### Key lifecycle (07–09)
| # | Document | Description |
|---|----------|-------------|
| 07 | [Unlock & Session](07-unlock-session.md) | **The asymmetry** — `clean` fails closed, `smudge` fails open |
| 08 | [Multi-Recipient Sharing](08-multi-recipient.md) | X25519 in the repository, no key server |
| 09 | [Rotation & Recovery](09-rotation-recovery.md) | Generations, re-encryption, and the offline way back in |

### Surface (10–13)
| # | Document | Description |
|---|----------|-------------|
| 10 | [CLI Contract](10-cli-contract.md) | Commands, exit codes, and the stdout rule |
| 11 | [Long-Running Filter Process](11-filter-process.md) | pkt-line protocol, one process per checkout |
| 12 | [Diff, Merge & What Stays Broken](12-diff-merge.md) | textconv, a three-way merge driver, an honest list |
| 13 | [Verify & Leak Detection](13-verify.md) | **The highest-value component** — finding the silent failures |

### Residue & Integrity (14–16)
| # | Document | Description |
|---|----------|-------------|
| 14 | [Metadata Leakage](14-metadata-leakage.md) | Everything still visible, and why paths are not encrypted |
| 15 | [Failure Modes](15-failure-modes.md) | F1–F20, what Git does, and what to tell the user |
| 16 | [Adversarial Integrity](16-adversarial-integrity.md) | **Threat catalogue** — the configuration and workflow attacks |

Fixtures, test layout and build order: [00-test-plan.md](00-test-plan.md).

## Current status

**Phase 1 is complete and proven end to end.** `src/crypto.ts` (the derivations in
[05](05-key-hierarchy.md), the determinism property in
[03](03-determinism.md)), `src/envelope.ts` (the wire format in
[04](04-envelope-format.md)) and `src/filter.ts` (`clean`/`smudge`/`textconv`
and the asymmetry in [07](07-unlock-session.md)) and `src/provider.ts` (`passphrase-file`, [06](06-key-provider-port.md)) are
implemented and green, plus `src/keyring.ts` — generations, atomic disk
persistence, and `unlockKeyring`, which is the real `KeySource` the filter now
plugs into instead of a test stub, and `src/install.ts` — `install`/`protect`,
writing real `.git/config` filter entries and `.gitattributes`/`.gitignore`
against a real `git` binary — plus `src/session.ts`, `src/config.ts`, and `src/cli.ts` — the full command
surface in [10](10-cli-contract.md) except key rotation, recipients and
recovery, backed by the real `dist/bin/securegit.js` binary
(`src/bin/securegit.ts`). 314 unit tests, all green.

The phase 1 acceptance criterion is now proven against real `git`, not just
injected `CliIO`: `src/git.integration.test.ts` drives the actual compiled
binary as a real filter through `init`/`install`/`protect`/`unlock`, a
commit, a push to a bare remote, and a clone — `git status` clean throughout,
ciphertext in `.git/objects`, plaintext in the worktree, `git diff` showing a
real plaintext hunk via `textconv`, `stash`/`stash pop` and branch switches
leaving a clean tree, and a keyless clone's ciphertext repaired once
`install` + `unlock` run there (see [07](07-unlock-session.md) — the working
recovery turned out not to be `git checkout --force .`, which Git's
stat-cache silently no-ops on an already-checked-out path). 9 tests, all
green, plus one further subprocess smoke test
(`src/bin.integration.test.ts`) proving the CLI wiring itself.

**Phase 2 has started:** `src/verify.ts` ([13](13-verify.md)) implements the
always-on configuration and index checks — missing filter config, `required`
turned off, a removed attribute, a conflicting `text`/`ident` attribute, key
material inside the worktree, a custodial-only provider set — plus the
leak/advice content scan (19 module tests). `src/merge.ts`
([12](12-diff-merge.md)) implements the three-way merge driver: real
`git merge-file` over the three decrypted plaintexts, fails closed (unlike
`smudge`) rather than guessing when a side can't be decrypted, cleans up its
temp directory on every exit path (10 module tests). Both are now wired into
`src/cli.ts` as `securegit verify` and `securegit merge`, with CLI-level
tests proving the wiring (7 more tests). Still open: `verify
--history`/`--access`, and a real `git merge`/`git diff` proof of the merge
driver driven through actual `.gitattributes` routing rather than a direct
`securegit merge` call.

Failure-message discipline ([15](15-failure-modes.md)) went from designed to
mostly verified: `src/failure.test.ts` checks that every message this
package controls names what happened, where, and what to do; `unlockKeyring`
now rejects a keyring written for a different repository, naming both ids,
before ever attempting to unwrap anything (F19); a simulated write failure
is proven to leave the previous keyring file untouched (F11). Along the way,
a real bug in this very document surfaced: F16 ("a keyless clone can commit
an unmodified protected file") was attributed to `clean`'s passthrough rule —
but `clean` has no such case; it always fails closed when locked, proven in
`src/filter.test.ts`. What actually makes F16 true is Git's own stat-cache
short-circuit skipping `add` entirely for a path whose worktree content
already matches the index — the same mechanism, from the opposite side, as
why the F2/F4/F8 recovery isn't `checkout --force`. 361 unit tests total,
all green; 11 integration tests, all green. What remains: multi-recipient
sharing, rotation/recovery, `--history`, `--access`, the residue/untracked-residue
check, and the long-running filter process. TypeScript, `src/` → `dist/`,
unit tests beside the source, matching `@trinoris/decision-core`.

| | Implemented | Designed only |
|---|---|---|
| Cryptography | derivations, envelope | known-answer vectors |
| Git integration | clean/smudge/textconv, attributes, real-`git` round trip | process protocol |
| Keys | keyring, passphrase provider, session | recipients, rotation, recovery |
| Tooling | CLI (`init`/`install`/`protect`/`unlock`/`lock`/`status`/`verify`/`clean`/`smudge`/`textconv`/`merge`/`encrypt`/`decrypt`/`inspect`) | `verify --history`/`--access`, `filter-process` |

Ten things worth knowing before reading any spec here. The first three are the
load-bearing ones; the last two are about scope.

1. **A random nonce breaks Git, and this is not a small problem.**
   `clean` runs on `git add`, `git diff`, `git stash` and every branch switch.
   If it returns different bytes for the same input, every protected file is
   permanently modified, no commit is ever clean, and the user cannot get back
   to a clean tree — so nothing that depends on a clean tree works.
   [03](03-determinism.md) solves it with a keyed convergent nonce, and pays for
   it in a documented leak. Build and test this first.

2. **The clean/smudge asymmetry is deliberate and easy to get backwards.**
   `clean` without a key **fails**, always, with no exception for a file that
   is already a valid envelope — it cannot verify a passthrough is even safe
   without the key. `smudge` without a key **passes the ciphertext through**,
   because the alternative is a repository nobody without a key can clone.
   The recovery once a key is available is *not* `git checkout --force .` —
   Git's stat-cache treats an already-checked-out path that matches the index
   as up to date and never reruns `smudge` on it, `--force` or not, confirmed
   against a real clone. It is `git rm --cached -r -q . && git checkout HEAD
   -- .`. The same stat-cache behaviour also explains why a locked, keyless
   clone can silently `commit` an unmodified protected file: Git never calls
   `clean` at all for a path whose content hasn't changed, so "locked" never
   gets a chance to block it. [07](07-unlock-session.md),
   [15](15-failure-modes.md).

3. **`verify` is what makes the rest trustworthy.** Every interesting failure of
   this design is silent: an attribute removed in a merge, a directory renamed
   out from under a pattern, a fresh clone that never ran `install`. Nothing
   errors; the file just goes to the remote in plaintext. [13](13-verify.md) is
   the detector, and it belongs in `pre-push` and in CI.

4. **`-text` on every protected path is a correctness requirement.** Git's
   check-in order is filter → `ident` → `text`, so CRLF conversion operates on
   the *ciphertext*. Under `core.autocrlf` or an inherited `* text`, the blob is
   mangled and fails to decrypt later, on another machine. [02](02-git-integration.md).

5. **`diff.securegit.cachetextconv` must be `false`.** Set to `true`, Git caches
   textconv output in a notes ref — which means writing the decrypted plaintext
   into `.git/objects` as an ordinary blob, undoing the design as a performance
   optimisation. [12](12-diff-merge.md).

6. **Per-file keys are derived, not wrapped.** The obvious design — a random DEK
   per file, wrapped by the master key — is non-deterministic and therefore
   fails (1). Deriving the DEK from the master key and a keyed hash of the
   content keeps the isolation property, costs 48 bytes less per file, and is
   the only version that works. [05](05-key-hierarchy.md).

7. **Removing a recipient does not un-share anything.** They have the
   repository, they had the key, and every blob committed under that generation
   stays readable to them forever. Removal, rotation and re-encryption are three
   separate steps and only the first two are about the future.
   [09](09-rotation-recovery.md).

8. **The dominant risk is losing the key, not breaking the cipher.** For a tool
   whose premise is that the cloud provider cannot help you, the most likely bad
   outcome is that nobody can. `init`, `status` and `verify` all push toward two
   independent recovery paths, because a user who has not lost a key yet does
   not feel the need. [15](15-failure-modes.md), F14.

9. **Paths, sizes, commit messages and blob equality are all visible**, and
   encrypting paths would stop this being Git. `secrets/prod-db-password.json`
   discloses its own inventory no matter what the file contains. If the
   *existence* of a secret is sensitive, it does not belong in this repository.
   [14](14-metadata-leakage.md).

10. **This tool authenticates blobs, not history.** A GCM tag proves a ciphertext
    was produced by a key holder — not that it belongs at that path, in that
    commit, at that point in the branch. An adversary with push access can
    relocate or roll back a blob and it will decrypt perfectly. Signed commits
    and protected branches remain necessary and are not in scope here.
    [16](16-adversarial-integrity.md), T3 and T4.
