# 15. Failure Modes

## Overview

Every way this breaks, what Git does about it, what the user sees, and what they
should do. A filter that fails in the middle of `git clone` produces a message
from Git, not from us — so the design job is to make sure our part of that
message is the useful part.

**Status: MOSTLY VERIFIED.** Every message this package controls (F1/F9, F5,
F6, F18) is checked in `src/failure.test.ts` for the what/where/action
discipline below; F11/F19 in `src/keyring.test.ts`; F2/F4/F8/F16/F21 in
`src/git.integration.test.ts` (real `git`, since they're about what Git does,
not about a message — F21 reuses F1's exact message, discovered while
building spec 08's real-clone join-flow proof). F21's own test was itself
flaky for the same reason F16 exists — see "F21 is the same optimization
again" below — fixed once diagnosed, not by changing what `pull` guarantees.
What's not covered: F3/F17 are Git's own message, not ours; F10 (`filter-process`
crashes mid-run) has no test yet, though `filter-process` itself is now built
([11](11-filter-process.md)) — this row predates that and is stale in saying
the feature doesn't exist, only the test for this specific crash-mid-run
case; F20 needs a Node-version floor check, not built; F12/F14/F15 have no
code path to test; F13 needs a real concurrent-process race (`key rotate`
itself is wired now — see [09](09-rotation-recovery.md)).

## Core Principle

> Fail towards ciphertext, never towards plaintext. When there is a choice
> between "the user cannot proceed" and "the file is stored unencrypted", the
> user cannot proceed.

## The table

| # | Failure | Git's behaviour | What the user sees | Recovery |
|---|---|---|---|---|
| F1 | Locked keyring, `git add` | `clean` exits 1, `required` aborts the add | "repository is locked; run `securegit unlock`" | `securegit unlock` |
| F2 | Locked keyring, `git clone` | `smudge` passes ciphertext through | clone succeeds, protected files are ciphertext | `securegit unlock; git rm --cached -r -q . && git checkout HEAD -- .` |
| F3 | `securegit` not on `PATH` | `required` aborts every filtered operation | Git's "external filter … failed" | install the package, or `git config --unset` to work unprotected |
| F4 | Fresh clone, `install` never run | no filter runs at all | ciphertext in the worktree, no error | `securegit install && securegit unlock; git rm --cached -r -q . && git checkout HEAD -- .` |
| F5 | Wrong key — envelope names a generation not in the keyring | `smudge` passes through | "blob wants generation 4 (`9f0c…`); keyring has 1–3" | `git pull` for new recipient files, then `securegit unlock` |
| F6 | Corrupted blob, authentication fails | `smudge` exits 3 | "authentication failed for `config/x.json` — the blob was modified or truncated" | `git fsck`; restore from a known-good commit |
| F7 | Attribute removed, plaintext committed | nothing fails | nothing, until `verify` runs | `verify`, then rotate the exposed secret ([13](13-verify.md)) |
| F8 | Session expires mid-checkout | `smudge` passes through from that point | a partially decrypted worktree | `securegit unlock; git rm --cached -r -q . && git checkout HEAD -- .` |
| F9 | Session expires mid-`add` | `clean` exits 1 | the add aborts, index unchanged | `securegit unlock`, redo |
| F10 | `filter-process` crashes mid-run | Git fails the operation | Git's "filter process died" plus our stderr | rerun; report if reproducible |
| F11 | Disk full while writing the keyring | keyring write is atomic (temp + rename) | "could not write keyring" | free space; the old keyring is intact |
| F12 | Two `git` processes filtering at once | both read the session | fine — the session is read-only to the filter | — |
| F13 | Concurrent `key rotate` and `git add` | rotate invalidates the session | the add fails F9-style | rerun after rotation |
| F14 | Keyring lost, no recipients, no recovery export | — | every protected blob is permanently unreadable | none. This is the failure the design cannot soften. |
| F15 | Recovery file present, code lost | — | as F14 | none |
| F16 | Clone by someone with no key, who commits without ever touching the protected file | Git's own stat-cache skips `add`/`commit` staging a path whose worktree content already matches the index — `clean` is never invoked at all | works; the file is unmodified ciphertext | — (Git never calls the filter; see below, not `clean`'s passthrough) |
| F17 | Merge driver absent, protected file conflicts | Git reports a binary conflict | "Cannot merge binary files" | `securegit install`; take one side and re-merge |
| F18 | `core.autocrlf=true`, `-text` missing | ciphertext is CRLF-mangled on the way in or out | F6 on the next checkout | add `-text` ([02](02-git-integration.md)), re-commit the file from a good copy |
| F19 | Repository moved, `repoId` mismatch | wrapped keys fail their AAD check | "this keyring belongs to repository `4f9a…`, this repository is `7c02…`" | use the right keyring, or `import-recovery` |
| F20 | Node version below the floor | crypto primitives missing | a startup error naming the required version | upgrade Node |
| F21 | Locked keyring, `git pull` | `git pull`'s merge can run `clean` on a tracked path even one the incoming change never touches, *when Git's own stat-cache doesn't skip it* (see "F21 is the same optimization again" below) — `required` then aborts the pull | "repository is locked; run `securegit unlock`", but the pull that would have delivered the thing needed to unlock (e.g. a new recipient file) never lands | `securegit unlock` if a keyring already exists; if not (a brand-new recipient's first pull), `install` must not have run yet — see [02](02-git-integration.md) and [08](08-multi-recipient.md) |

## Why the F2/F4/F8 recovery is not `checkout --force`

Confirmed against a real clone in [02](02-git-integration.md)'s integration
suite: `git checkout --force .` does not rerun `smudge` on a path whose
worktree content already matches what the index expects, `--force` or not.
This is Git's stat-cache optimization, not a securegit bug, and it holds even
for the plumbing-level `git checkout-index --force --all` — both skip the
rewrite entirely ("Updated 0 paths from the index") whenever the file that's
already sitting in the worktree looks, to Git, like the file the index already
records. Since a keyless clone's ciphertext blob is exactly the content Git
expects to see there, `--force` alone never gets `smudge` to run a second time
after the fact.

The working recovery empties the index first so Git has nothing left to treat
as "already matching", then restores from `HEAD`:

```
git rm --cached -r -q . && git checkout HEAD -- .
```

`git rm --cached` only touches the index, not the worktree — nothing is
deleted from disk. This is the same technique documented for git-crypt and
git-lfs for the identical class of problem.

## F16 is the same optimization, seen from `add` instead of `checkout`

F16 as originally written here credited `clean`'s passthrough rule
([04](04-envelope-format.md)) for why a locked, keyless clone can still
`commit` an unmodified protected file. That's not what happens — confirmed
in `src/filter.test.ts` (`clean(envelope3, ctx({ keys: locked() }))` throws
`LockedError`) and in `src/git.integration.test.ts`'s F16 test: **`clean`
always fails closed when locked, with no exception for a file that is
already a valid envelope.** The comment in `filter.ts` says why: "a locked
filter cannot verify the passthrough precondition" — proving an envelope
authentic still requires the key.

What actually makes F16 true is the same Git stat-cache short-circuit behind
the F2/F4/F8 recovery above, from the opposite side: `git add`/`commit` never
invoke `clean` at all on a path whose worktree content already matches the
index. A fresh, unmodified clone is exactly that case, so the filter never
runs and there is nothing for "locked" to block. The moment the file's
content or mtime actually changes — even rewritten with identical bytes —
Git re-evaluates the path, calls `clean`, and it fails closed exactly like
F1. This is provable and is exactly what the F16 integration test does:
locked, re-add of a byte-identical worktree file succeeds silently; locked,
re-add after touching the same file fails with the F1 message.

## F21 is the same optimization again, seen from `merge`

F21's own integration test — proving a locked `git pull` fails closed — was
flaky, found by repeated runs rather than by reading the spec: roughly half
the time, `git pull` (a trivial fast-forward whose only actual change is a
*new*, unrelated file) silently succeeded instead of hitting the lock check
at all, with no test-visible cause. `GIT_TRACE=1` on a failing run showed
why: `git merge -q FETCH_HEAD` never invoked our filter for the protected
path in the first place. This is F16's exact mechanism (a stat-cache/
tree-diff short-circuit that skips a path Git doesn't believe changed),
manifesting inside `merge`'s fast-forward path instead of `add`'s — and
whether Git trusts the cached entry for `PROTECTED_PATH` depends on how much
real wall-clock time separates the prior test's `checkout` (which sets a
fresh index stat entry) from this test's own `pull`, not on anything this
package controls.

The claim in the table above — "even ones the incoming change never
touches" — is therefore not an unconditional guarantee; it is what happens
*when Git actually re-verifies the path*, which a sufficiently fast pull
right after a checkout is not guaranteed to do. The fix is F16's own
technique, applied to `merge`: force a future mtime on `PROTECTED_PATH`
(`utimes`) before locking and pulling, so Git can no longer trust the cached
entry and must re-read the file — which is what makes the filter, and
therefore the lock check, actually run. Six consecutive clean runs (versus
roughly 50% failures beforehand) confirm the fix; the underlying git
mechanism itself is unaffected — it's the test's setup that now reliably
reaches the code path it means to exercise, not a change to what `pull`
guarantees on its own.

## F14 is the real risk

Not cryptanalysis. Not a compromised cloud provider. **Losing the key.**

For a tool whose entire premise is that the cloud provider cannot help you, the
dominant failure mode is that nobody can. The design's answers are all preventive
and all have to be pushed at the user, because a user who has not lost a key yet
does not feel the need:

- `init` prints a warning and offers `key export-recovery` immediately.
- `status` reports "no recovery export, one recipient" as a warning, every time,
  until there are two independent paths.
- `verify` treats a single-recipient, no-export repository as a finding.
- The recovery file is safe to commit ([09](09-rotation-recovery.md)), so the
  cheapest possible mitigation — commit the file, write the code on a card — is
  one command.

Two independent paths means two of: a second recipient on a different machine, a
recovery export whose code is stored offline, a second provider on different
hardware. Two copies of the same passphrase in the same password manager is one
path.

## Message discipline

Every failure message names three things: **what**, **where**, **what to do**.

```
securegit: repository is locked
  file:   config/production.json
  action: run `securegit unlock`, then retry

securegit: cannot decrypt config/production.json
  reason: blob wants generation 4.9f0c1a2b3c4d5e6f; this keyring has 1.a1b2…, 2.b30f…, 3.c7e0…
  action: `git pull` for new recipient files, then `securegit unlock`

securegit: authentication failed for config/production.json
  reason: the blob was modified or truncated (...)
  action: `git fsck`; restore from a known-good commit

securegit: this keyring belongs to repository 4f9a1c2b3d4e5f60
  this repository is 7c02918a4b3c2d1e
  action: use the keyring for 7c02918a4b3c2d1e, or `securegit key import-recovery`
```

Never "decryption failed". Never a stack trace as the primary output. Never a
message that mentions a key fingerprint the user has no way to look up — every
fingerprint printed is one `securegit key list` will show.

Messages go to stderr in every case ([10](10-cli-contract.md)), including
`filter-process`, where stdout is protocol.

## Test Cases

| Test | Test File | Fixture | Status |
|------|-----------|---------|--------|
| Each F-code this package controls the message for follows discipline (F1/F9, F5, F6, F18) | `src/failure.test.ts` | — | ✅ |
| Each message named above starts `securegit:`, names the path, and ends in an `action:` line | `src/failure.test.ts` | — | ✅ |
| F1: `git add` aborts and the index is unchanged | `src/git.integration.test.ts` | `repo-protected/` | 🔲 |
| F2: clone succeeds with no key | `src/git.integration.test.ts` | `repo-protected/` | ✅ |
| F4: the documented `install`+`unlock`+recovery sequence works | `src/git.integration.test.ts` | `repo-protected/` | ✅ |
| F5: message names both generations and fingerprints | `src/failure.test.ts` | — | ✅ |
| F6: a flipped ciphertext byte reports the path | `src/failure.test.ts` | — | ✅ |
| F8: a keyless-clone worktree is repaired by `rm --cached`+`checkout HEAD` | `src/git.integration.test.ts` | `repo-protected/` | ✅ |
| F11: keyring write is atomic; a simulated failure leaves the old file | `src/keyring.test.ts` | — | ✅ |
| F13: rotation during an add fails the add rather than mixing generations | `src/git.integration.test.ts` | `repo-protected/` | 🔲 (`key rotate` is wired now — this needs a real concurrent-process race, not built) |
| F16: keyless commit of an unmodified protected file is a no-op, and the mechanism is Git's stat-cache, not `clean`'s passthrough | `src/git.integration.test.ts` | `repo-protected/` | ✅ |
| F18: CRLF-mangled envelope reports corruption, not a wrong key | `src/failure.test.ts` | — | ✅ |
| F19: foreign keyring is rejected by `repoId`, with both ids named | `src/keyring.test.ts` | — | ✅ |
| F21: a locked repository with the filter attached cannot `git pull` | `src/git.integration.test.ts` | — | ✅ |
| `status` warns while there is only one recovery path | `src/cli.test.ts` | — | 🔲 (blocked: recovery export is spec 09, not built) |
| `verify` reports single-recipient, no-export as a finding | `src/verify.test.ts` | — | 🔲 (blocked: recovery export is spec 09, not built — recipients themselves are spec 08, now built) |
| No failure path writes plaintext to the object database | `src/git.integration.test.ts` | `repo-protected/` | 🔲 |

## Relationship to Other Specs

- [02](02-git-integration.md) — the general statement of the mechanism behind F21
- [04](04-envelope-format.md) — passthrough, behind F16
- [07](07-unlock-session.md) — the asymmetry, behind F1, F2 and F21
- [08](08-multi-recipient.md) — the join flow F21 was found while proving
- [09](09-rotation-recovery.md) — the recovery path that prevents F14
- [13](13-verify.md) — how F7 is found at all
