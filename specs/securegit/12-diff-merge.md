# 12. Diff, Merge & The Tools That Stay Broken

## Overview

Git's content-aware features assume they can read the content. This document
restores the two that matter — diff and merge — and is explicit about the ones
that cannot be restored, because a user who discovers those on their own
concludes the tool is broken.

**Status: MOSTLY IMPLEMENTED.** Diff (`textconv`) has been implemented since
[filter.ts](02-git-integration.md) landed. `src/merge.ts` implements the
merge driver itself, and it is wired into `src/cli.ts` as
`securegit merge -- <base> <ours> <theirs> <markerSize> <path>`
([10](10-cli-contract.md)). What's still open: the real-`git` end-to-end
proof — a genuine conflicted merge driven through `git merge` itself, with
`.gitattributes`' `merge=securegit` actually routing to the driver, not just
`cli.test.ts` calling `securegit merge` directly. See "What this pass
actually built" below.

## Core Principle

> Decrypt for **display** and for **merge**, never for storage. Every mechanism
> here has to be checked against one question: does this write plaintext
> anywhere under `.git/`?

## Diff

```ini
[diff "securegit"]
	textconv      = securegit textconv --
	cachetextconv = false
```

```gitattributes
config/production.*  filter=securegit diff=securegit -text
```

`textconv` receives a *path to a temporary file* holding the blob and prints the
text Git should diff. It runs for `git diff`, `git log -p`, `git show` and
`git difftool`, and never for anything that writes to the object database.

```
$ git diff config/production.json
-  "timeout": 30
+  "timeout": 60
```

### `cachetextconv = false` is a security setting

Setting it to `true` makes Git cache textconv output in a notes ref, which means
**writing the decrypted plaintext into `.git/objects` as an ordinary blob** —
undoing the entire design, quietly, as a performance optimisation. The plaintext
then sits in the object database, survives `git gc`, and travels with any push
of `refs/notes/*`.

`install` writes `false` explicitly rather than relying on it being the default,
and `verify` ([13](13-verify.md)) reports `true` as an error. If someone has
already enabled it, the remediation is to delete the notes ref and `gc`; `verify
--history` looks for it.

### `textconv` and the locked case

Locked, `textconv` prints a single line to stdout:

```
<securegit: encrypted, 1184 bytes, keyId 3.a1b2c3d4e5f60718>
```

A diff between two such lines shows the sizes changing, which is honest and
occasionally useful. It never prints a partial decryption, and it exits 0 so
`git log -p` over a large history does not stop at the first protected file.

## Merge

Without help, merging a protected file is a binary conflict — "warning: Cannot
merge binary files" — with no option but to take one side whole.

```ini
[merge "securegit"]
	name   = securegit encrypted three-way merge
	driver = securegit merge -- %O %A %B %L %P
```

```gitattributes
config/production.*  filter=securegit diff=securegit merge=securegit -text
```

The driver:

1. Decrypt `%O` (ancestor), `%A` (ours) and `%B` (theirs) into memory.
2. `git merge-file --marker-size=%L` over the three plaintexts.
3. Encrypt the result — **conflict markers included** — and write it to `%A`.
4. Exit 0 on a clean merge, 1 on conflict, mirroring `merge-file`.

Step 3 is the part that looks wrong and is right. `%A` is a blob-shaped file
that Git will put in the index, so it must be ciphertext; the user then sees
plaintext with conflict markers in the worktree because `smudge` decrypts it.
Resolving is an ordinary edit.

Any of the three inputs may be plaintext — a side that predates protection, or
one committed without the filter installed. The driver handles each input
independently ([04](04-envelope-format.md) passthrough rules) rather than
assuming all three are envelopes.

Temporary files, if the implementation needs any, go in a `0700` directory and
are removed on every exit path including a thrown error.

## What stays broken

Honest list. Each of these is a place where Git wants to read content and has no
hook that lets us decrypt first.

| Feature | Behaviour | Workaround |
|---|---|---|
| `git log -S` / `-G` (pickaxe) | Searches raw blobs; never matches plaintext. Silently returns nothing. | none |
| `git blame` | No textconv support. Attributes lines of ciphertext. | `securegit decrypt` an older revision and diff by hand |
| `git grep <rev>` | Searches ciphertext. Worktree `git grep` is fine. | grep the worktree |
| `git add -p` | Interactive hunks come from the raw diff, not textconv. Offers a binary blob. | stage whole files |
| Web review (GitHub, CodeCommit) | Shows ciphertext, or "binary file". | review locally; **this is also the feature** |
| `git diff --stat` | Byte counts of ciphertext, off by the envelope overhead. | cosmetic |
| `git archive` | Emits ciphertext — `archive` does not run smudge. | `git checkout` then archive the worktree |
| Delta compression | Random bytes do not delta; each version stores whole. | keep protected files small |
| Editor and IDE Git integrations | Most use plumbing directly and see ciphertext. | varies |

The last row is worth planning for: an IDE's built-in diff view will show
ciphertext even when `git diff` on the command line shows plaintext, because the
IDE calls `git diff --no-textconv` or reads blobs itself. That is not a bug in
`securegit`, but it is the first thing a new user reports.

**`git archive` is the one with teeth.** It is how release tarballs and some
deployment pipelines are built, and it produces an archive of ciphertext without
warning. `verify` reports the presence of protected paths as a note when an
`export-subst`-style archive workflow is detected in the repository.

## What this pass actually built

`src/merge.ts` exports `merge(opts): Promise<{ clean: boolean; output: Buffer }>`.
It takes `%O`/`%A`/`%B` as already-read `Buffer`s and a `KeySource` rather than
touching `process.argv` or a real Git invocation directly — `cli.ts`'s
`cmdMerge` is the thin layer that reads the three files Git actually hands the
driver, calls `merge()`, writes `output` back to `%A` unconditionally (clean or
not — that's how Git knows what to show in the worktree), and maps `clean` to
exit 0/1.

- **Real `git merge-file`, not a hand-rolled three-way merge.** The spec calls
  for exactly this ("`git merge-file --marker-size=%L` over the three
  plaintexts"), and it is the correct call for a second reason found while
  building it: **two edits on adjacent lines conflict under `git merge-file`
  even when they touch different lines**, because diff3 needs at least one
  unchanged line of context between two hunks to treat them as independent.
  Reimplementing the merge ourselves would either miss this — silently
  auto-resolving something Git's own merge would flag as a conflict, a correctness
  bug at exactly the layer this tool has to be trustworthy — or would have to
  rediscover the same rule from scratch. Using the real binary means securegit's
  merge behaviour matches ordinary Git merge behaviour by construction.
- **Fails closed on an undecryptable side, unlike `smudge`.** [07](07-unlock-session.md)'s
  asymmetry is `clean` fails closed, `smudge` fails open — but a merge is
  neither read nor write in that sense. It cannot pass ciphertext through the
  way `smudge` does (there is nothing sensible to *diff3* against ciphertext),
  and it cannot proceed by guessing. So every one of `%O`/`%A`/`%B` that looks
  like an envelope must actually decrypt, or the whole merge throws before any
  temporary file is even written — one `MergeError` for "wrong or missing
  generation" or "authentication failed", reusing `filter.ts`'s `LockedError`
  (re-exported from `merge.ts`) specifically for "no *current* generation to
  encrypt the result under", so a caller can dispatch on error type exactly
  like it already does for `clean`.
- **Exit 1 has two meanings for `securegit merge`, deliberately unresolved.**
  `cmdMerge` maps `clean: false` to exit 1 and a caught `LockedError` to
  `EXIT_LOCKED`, which is also 1 — Git's merge-driver protocol only
  distinguishes zero from nonzero, so nothing forwarding the exit code to Git
  loses information. A caller that needs to tell "conflict" from "locked"
  apart still can: a locked failure always writes a stderr diagnostic; a
  conflict, not being a failure, writes nothing. See [10](10-cli-contract.md).
- **Temp directory is `mkdtemp`'s default, not a bespoke `chmod`.** `mkdtemp`
  always creates its directory with mode `0700`; the spec's "0700 directory"
  requirement needs no extra step. Cleanup is a single `finally` around every
  temp-file-scoped operation, so any failure after the directory is created —
  not only the ones anticipated here — still removes it.

## Test Cases

| Test | Test File | Fixture | Status |
|------|-----------|---------|--------|
| `textconv` decrypts a blob for display | `src/filter.test.ts` | `blobs/` | ✅ |
| `git diff` shows a plaintext hunk | `src/git.integration.test.ts` | `repo-protected/` | ✅ |
| `git log -p` shows plaintext across commits | `src/git.integration.test.ts` | `repo-protected/` | 🔲 |
| `textconv` while locked prints the placeholder and exits 0 | `src/filter.test.ts` | — | ✅ |
| `textconv` never writes to the object database | `src/git.integration.test.ts` | `repo-protected/` | 🔲 |
| `install` sets `cachetextconv = false` | `src/install.test.ts` | — | ✅ |
| `verify` reports `cachetextconv = true` as an error | `src/verify.test.ts` | — | ✅ |
| `verify --history` finds a textconv notes ref | `src/verify.test.ts` | `legacy-plaintext/` | 🔲 |
| Merge driver resolves a non-overlapping three-way merge cleanly | `src/merge.test.ts` | — | ✅ |
| Merge driver writes ciphertext to `%A` | `src/merge.test.ts` | — | ✅ |
| Conflicted merge exits 1 and the worktree shows plaintext markers | `src/git.integration.test.ts` | `repo-protected/` | 🔲 |
| Merge driver handles a plaintext ancestor | `src/merge.test.ts` | — | ✅ |
| Merge driver handles a plaintext side | `src/merge.test.ts` | — | ✅ |
| Merge driver removes its temporary files on the error path | `src/merge.test.ts` | — | ✅ |
| Merge driver fails closed rather than writing plaintext to `%A` | `src/merge.test.ts` | — | ✅ |
| Merged result decrypts to the expected plaintext | `src/git.integration.test.ts` | `repo-protected/` | 🔲 |

## Relationship to Other Specs

- [02](02-git-integration.md) — the attributes that route to these drivers
- [04](04-envelope-format.md) — passthrough, used by the merge driver
- [07](07-unlock-session.md) — locked behaviour, here as elsewhere: never fail a read
- [13](13-verify.md) — auditing `cachetextconv` and the notes ref
- [14](14-metadata-leakage.md) — `--stat` and delta behaviour as observables
