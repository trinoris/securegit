# 02. Git Integration Model

## Overview

How `securegit` attaches to Git: which extension point, which attributes, and
which of Git's own conversions have to be switched off for the scheme to be
correct rather than merely usually-correct.

**Status: IMPLEMENTED.** `src/filter.ts` (`clean`/`smudge`/`textconv`) and
`src/install.ts` (`install`/`protect`/`unprotect`, writing the real
`.git/config` and `.gitattributes` entries described below) are both built
and tested against a real `git` binary. `unprotect` removes only the
`.gitattributes` line — never `.gitignore`'s residue entries, which stay
harmless once a pattern is unprotected and could unhide files a user still
wants ignored for unrelated reasons — and, like key rotation
([09](09-rotation-recovery.md)), is forward-only: a blob already committed
as ciphertext stays ciphertext, in history and in the current index, until
something actually re-stages the file.

## Core Principle

> Git already has a documented place to transform content on its way into and
> out of the object database. Use it, mark it `required`, and let Git — not a
> hook we wrote — decide when it runs.

## Why not a hook

| | `pre-commit` hook | clean/smudge filter |
|---|---|---|
| Runs on `git add` | no | yes |
| Runs on `git stash`, `git diff`, `git checkout` | no | yes |
| Transforms content without touching the worktree | no | yes |
| Reverses automatically on checkout | no | yes (`smudge`) |
| Can force Git to *fail* rather than store plaintext | no | yes (`required`) |
| Installed by cloning | no | no — both need a local step |

A `pre-commit` hook would have to encrypt the file in place, commit, then
decrypt it again: a window in which a crash leaves ciphertext in the worktree
and, worse, a window in which `git add` has already staged the plaintext. It is
the wrong extension point. The filter is the right one, and its `required` flag
is the property no hook can offer — with `filter.securegit.required = true`, a
filter that is missing or exits non-zero makes the Git operation **fail** rather
than fall back to storing the file verbatim.

## The two directions

```
   worktree                          object database
   ────────                          ───────────────
   plaintext  ──── clean ─────────▶  ciphertext          (git add, diff, stash)
   plaintext  ◀─── smudge ────────   ciphertext          (git checkout, merge)
                   textconv ──────▶  plaintext (display) (git diff, log -p)
```

`clean` and `smudge` must be exact inverses over all byte strings, including
empty input and input that is already ciphertext ([04](04-envelope-format.md)
defines the passthrough rules). `textconv` is display-only and never writes to
the object database.

**`clean` runs on more than the obvious triggers, but not unconditionally.**
Confirmed against a real clone in `src/git.integration.test.ts`: `git pull`
*can* run `clean` as a pre-merge safety check on a tracked path the incoming
change never touches — not only the ones in the diff — to confirm the
worktree hasn't been locally modified before touching anything. Whether it
actually does is Git's own call: the same stat-cache/tree-diff short-circuit
behind F16 ([15](15-failure-modes.md), "the same optimization, seen from
`add` instead of `checkout`") can skip a path Git doesn't believe changed,
in which case the filter never runs for it at all. Combined with the
fail-closed asymmetry ([07](07-unlock-session.md)), this means **a locked
repository is not reliably able to `git pull` once the filter is attached
and Git decides the safety check is needed** — which, in practice, a fresh
checkout followed immediately by a pull may not trigger, and a repository
that's had time to settle usually will (`src/git.integration.test.ts`'s own
F21 test needed a forced stat-cache miss, F16's own technique, to exercise
this reliably — see [15](15-failure-modes.md)'s "F21 is the same
optimization again"). Nothing about this is a plaintext-exposure risk in
either direction: skipping the check just means Git didn't bother
re-verifying a file that genuinely didn't change; running it fails closed
exactly as designed. This is exactly why the join flow in
[08](08-multi-recipient.md) has a new machine's very first `git pull`
happen *before* `securegit install`, not after — identical in shape to why a
keyless clone that never runs `install` still works ([15](15-failure-modes.md), F4).

## Configuration

Written by `securegit install` into `.git/config` — **local, never committed**,
because it names an absolute path to an executable and because a repository that
could configure its own filters would be a remote code execution vector.

```ini
[filter "securegit"]
	clean    = securegit clean -- %f
	smudge   = securegit smudge -- %f
	required = true

[diff "securegit"]
	textconv      = securegit textconv --
	cachetextconv = false
```

Or, with the long-running variant ([11](11-filter-process.md)), which replaces
`clean`/`smudge` rather than supplementing them:

```ini
[filter "securegit"]
	process  = securegit filter-process
	required = true
```

`%f` is the path of the file being filtered, relative to the repository root.
It is supplied for key-derivation context and diagnostics only. **The filter
must never read that path from disk** — Git supplies the content on stdin, and
during a merge or a `git show` the worktree file either does not exist or holds
different content. The `--` separator is not decoration; paths beginning with
`-` are legal in Git.

## Attributes

```gitattributes
# Protected paths
.env                    filter=securegit diff=securegit merge=securegit -text
*.secret                filter=securegit diff=securegit merge=securegit -text
config/production.*     filter=securegit diff=securegit merge=securegit -text

# securegit's own metadata is public and must never be filtered
.securegit/**           -filter -diff -text
```

### `-text` is mandatory, not stylistic

Git's check-in conversion order is **filter → `ident` → `text`**, and check-out
runs the reverse. `text` therefore operates on our *ciphertext*: after `clean`
produced it, and before `smudge` gets to see it. If `text` is in effect, Git
rewrites LF↔CRLF inside a byte string of uniformly random bytes, producing a
blob that no longer decrypts — discovered later, by someone else, on another
machine.

Git's automatic binary detection normally saves us, which is one reason the
envelope magic begins with a NUL byte ([04](04-envelope-format.md)). But the
heuristic only applies under `text=auto`; an explicit `* text` line in a parent
`.gitattributes` forces conversion regardless of content. `-text` on every
protected path removes the question. `install` writes it and
[13](13-verify.md) treats its absence as an error.

The same reasoning rules out `ident` and `working-tree-encoding` on protected
paths. Both mutate content outside the filter, and both are checked by `verify`.

### The `.securegit/**` exclusion

Recipient files, the repository config and the format version live in the
repository as plaintext by design — they hold public keys and key identifiers,
and a clone that has no key yet must still be able to read them to find out
which key it needs. A broad pattern such as `config/**` that accidentally
captured them would make the repository unrecoverable: the file needed to locate
your key would itself be encrypted under that key.

The exclusion is written last so it wins under `.gitattributes` last-match-wins
precedence, and `verify` treats its absence as an error rather than a warning.

## Ordering and precedence

- `filter.<name>.process` takes precedence over `clean`/`smudge` when both are
  set. `install` writes one form or the other, never both.
- Attributes resolve per path with the usual last-matching-pattern-wins rule,
  which is why the exclusion goes at the end.
- `git check-attr filter -- <path>` is the authority on what is protected.
  [13](13-verify.md) calls it rather than re-implementing pattern matching, so
  the tool and Git cannot disagree about which files are covered.

## Detecting a foreign configuration

`install()` (`src/install.ts`) reads the four "identity" keys before writing
anything — `filter.securegit.clean`, `.smudge`, `.process`,
`diff.securegit.textconv` — because those are the ones that name an
executable; `required` and `cachetextconv` are plain booleans and carry no
signal about who set them. A key is judged **foreign** if it is set to
something other than one of the four command lines securegit itself would
produce for *either* supported form, computed for the `bin` this call is
using:

```
<bin> clean -- %f
<bin> smudge -- %f
<bin> filter-process
<bin> textconv --
```

This is why switching a repository from `clean`/`smudge` to `--process` is not
treated as foreign — it is recognisably this tool's own alternate form — while
a value naming an unrelated command is refused and printed in full, along with
the key it belongs to. `force: true` overwrites it anyway; there is no CLI flag
for this in [10](10-cli-contract.md) by design, since a foreign value is the
one case where a person should look at what is there before choosing to
replace it. Unrelated git config (`user.name`, anything outside the
`filter.securegit.*` / `diff.securegit.*` namespace) is never read or touched.

## Installation is a local step

Cloning a repository does not configure its filters, and must not. Until a fresh
clone runs `securegit install`, protected files check out as ciphertext. That is
Git behaving correctly; [15](15-failure-modes.md) covers making it legible
rather than mysterious.

## Test Cases

| Test | Test File | Fixture | Status |
|------|-----------|---------|--------|
| `clean` then `smudge` is the identity over random binary input | `src/filter.test.ts` | — | ✅ |
| `clean` of empty input round-trips | `src/filter.test.ts` | — | ✅ |
| `clean` of already-ciphertext is a passthrough | `src/filter.test.ts` | `envelopes/` | ✅ |
| `install` writes `required = true` | `src/install.test.ts` | — | ✅ |
| Filter exiting non-zero aborts `git add` rather than storing plaintext | `src/git.integration.test.ts` | `repo-protected/` | ✅ |
| `install` writes `-text` on every protected pattern | `src/install.test.ts` | — | ✅ |
| Round-trip survives `core.autocrlf=true` | `src/git.integration.test.ts` | `repo-protected/` | 🔲 |
| Round-trip survives an inherited `* text` attribute | `src/git.integration.test.ts` | `attributes/` | 🔲 |
| `.securegit/**` exclusion is present and last | `src/install.test.ts` | — | ✅ |
| `clean` runs during `git pull` as a pre-merge safety check, and fails closed when locked (F21) | `src/git.integration.test.ts` | — | ✅ |
| Filter never opens the path given by `%f` | `src/filter.test.ts` | — | ✅ |
| A path beginning with `-` is filtered correctly | `src/filter.test.ts` | — | ✅ |
| `install` writes `cachetextconv = false` | `src/install.test.ts` | — | ✅ |
| `install` run twice changes nothing the second time | `src/install.test.ts` | — | ✅ |
| `install` refuses to write filter config into a committed file | `src/install.test.ts` | — | 🔲 |

## Relationship to Other Specs

- [03](03-determinism.md) — why `clean` must be a pure function of its input
- [04](04-envelope-format.md) — what `clean` emits
- [11](11-filter-process.md) — the long-running form of the same contract
- [12](12-diff-merge.md) — `textconv`, and why `cachetextconv` is dangerous
- [13](13-verify.md) — auditing this configuration
- [15](15-failure-modes.md) — what a clone without `install` looks like
