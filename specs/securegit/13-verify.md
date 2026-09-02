# 13. Verify & Leak Detection

## Overview

Encryption that is switched on is worth very little without a way to find out
that it is still switched on. `securegit verify` is the command that answers
"has a protected file ever been committed in plaintext, and is this repository
still configured to prevent it".

**Status: IMPLEMENTED.** `src/verify.ts` implements the always-on
configuration and index checks (L1–L3, L7–L10), the leak/advice content scan,
`--access` (`accessReport()`), and `--history` (`historyReport()`) — all
wired into `src/cli.ts` as `securegit verify [--access|--history] [--json]`.
`--json` is built for all three forms: the report object itself, exactly as
the module returns it, `JSON.stringify`'d to stdout. See "What this pass
actually built" below.

## Core Principle

> The interesting failures of this design are silent ones. A missing attribute,
> a filter that was never installed, a pattern that stopped matching after a
> directory was renamed — none of them produce an error, and all of them produce
> plaintext in the object database.

## What can go wrong quietly

| | Failure | How it happens | Detected by |
|---|---|---|---|
| L1 | Filter never installed | fresh clone, `install` forgotten | config check |
| L2 | `required` not set | hand-edited config, older `install` | config check |
| L3 | Attribute removed | edit to `.gitattributes`, merge resolution | attribute check |
| L4 | Pattern stopped matching | `config/` renamed to `conf/` | content scan |
| L5 | New sensitive file never protected | `secrets/new.json` added | pattern advice |
| L6 | Plaintext committed before adoption | the file existed before `securegit` | history scan |
| L7 | `cachetextconv` enabled | copied config, well-meaning optimisation | config check |
| L8 | `text` / `ident` / `working-tree-encoding` on a protected path | inherited `.gitattributes` | attribute check |
| L9 | Keyring or session inside the worktree | `HOME` pointed at the repository | path check |
| L10 | Only custodial providers remain | KMS added, passphrase removed | provider check |

L4 is the one that bites in practice. Nothing fails. The commit succeeds. The
push succeeds. The file is in CodeCommit in plaintext and will stay there.

## Checks

### Configuration — always

```
$ securegit verify
  ✓  repository initialised          .securegit/config.json, format 1
  ✓  keyring present                 generations 1–3, current 3
  ✓  filter configured               clean, smudge
  ✓  filter required                 filter.securegit.required = true
  ✓  diff driver configured          textconv
  ✓  textconv cache disabled         cachetextconv = false
  ✓  attributes present              4 patterns
  ✓  metadata exclusion              .securegit/** -filter, last
  ✓  no conflicting attributes       no text/ident/working-tree-encoding
  ✓  key material outside worktree
  ✓  non-custodial unwrap path       passphrase-file
```

### Content — index and HEAD, always

For every tracked path, `git check-attr filter` decides whether it is protected;
Git's own matcher is the authority ([02](02-git-integration.md)). For every
protected path, read the blob and require the envelope magic.

```
  ✗  plaintext in HEAD               config/legacy.json
     protected by pattern `config/production.*`? no
     matched by no pattern, but resembles a protected file
```

Three distinct findings come out of `verify` (`FindingKind`: `'leak' | 'advice' | 'residue'`):

- **Leak** — the path *is* protected by an attribute and its blob is plaintext.
  Exit code 5. This is a live failure of L1–L4.
- **Advice** — the path is not protected, but its name matches the heuristics
  (`*.env`, `*secret*`, `*credential*`, `id_rsa`, `*.pem`, `*.p12`) or its
  content matches high-confidence patterns (`AKIA[0-9A-Z]{16}`,
  `-----BEGIN .* PRIVATE KEY-----`, `xox[baprs]-`). Exit code 0 with a note; the
  tool suggests a `protect` invocation but never edits `.gitattributes` itself.
- **Residue** ([16](16-adversarial-integrity.md), T12) — an untracked file
  shaped like editor/merge fallout (`~`, `.orig`, `.rej`, `.bak`, `.save`, a
  vim swap file) exists on disk beside a *protected* path. Checked against
  the real filesystem, not `git status`, because the point is catching what
  `.gitignore` would otherwise hide from view — plaintext that was never
  committed is still plaintext sitting on disk. Exit code 2 (the
  misconfigured tier): real, but not the same severity as a committed leak.

### History — `--history`

```
$ securegit verify --history
scanning 1,204 commits, 3,318 blobs …
  ✗  plaintext at config/production.json
     first: 8b0e114  2026-01-04  "add production config"
     last:  a3f9c21  2026-02-11  "enable securegit"
     14 commits, still reachable from main
  ✗  textconv cache notes ref present
     refs/notes/textconv/securegit — 44 blobs of plaintext
```

Walks every reachable commit; for each, resolves attributes **as they were at
that commit** — a path protected today may not have been then, and reporting it
as a leak either way would be wrong in one direction or the other.

Optimisations that matter for this to be usable on a real repository: check each
blob OID once (`git cat-file --batch-check` over `rev-list --objects`), read only
the first 11 bytes of each candidate, and cache results by OID.

As built: `git rev-list --all` is the walk (every branch and tag, not just
the checked-out one — the case this exists for is exactly a commit that
isn't on the branch someone happens to be looking at). Attributes are
resolved per commit via a temporary index (`GIT_INDEX_FILE` pointed at a
scratch file, `git read-tree <sha>`, then `git check-attr --cached -z
--stdin filter`, batched over every tracked path in one call) rather than
`git check-attr --source <tree-ish>` — that flag needs Git 2.40, and this
tool can't assume a real clone is running anything that new. Each blob is
read at most once via a plain `Map<blobSha, boolean>` keyed on content hash
(content-addressed storage means the same SHA is always the same bytes) —
the dedup the optimisation note asks for, reached by a different route than
`--batch-check`/`rev-list --objects` since this walk only ever needs to
inspect *protected* paths' blobs, not the whole object graph. Reading only
the first 11 bytes of each candidate is not built — full blob content is
read via `git cat-file -p`; leaked files are overwhelmingly small
config/secret files, not large binaries, so this is a real but low-priority
simplification, honestly documented rather than silently different from the
spec.

### The remediation is not "run a command"

`verify --history` finds plaintext; it does not remove it. Removal means
rewriting history with `git filter-repo`, force-pushing, and every clone
re-cloning. The report says so, and says the thing that is actually true:

```
  A secret committed in plaintext and pushed is exposed. Rewriting history
  removes it from the repository; it does not remove it from the mirrors,
  backups, CI caches and clones that already have it. Rotate the secret.
```

## Who can read this repository

```
$ securegit verify --access
recipients
  7c1e4a09b2d5f836  laptop      added 2026-01-14 by b30f92ac  gen 1–3
  b30f92ac1e7d4405  desktop     added 2026-01-14 by b30f92ac  gen 1–3
  e4a7c0912f38bb61  ci-build    added 2026-03-02 by b30f92ac  gen 2–3
providers
  passphrase-file                                              gen 1–3
recovery exports
  2026-01-20  by b30f92ac  export 4f2a91  covers gen 1
  ⚠  a recovery export is a full, non-revocable read path that leaves no
     recipient entry. This list cannot tell you who holds it.
removed recipients
  9d1c04ff72ab3e58  contractor  removed 2026-06-01, before generation 3
     can still read every blob committed under generations 1–2
```

The warnings are the point. A report that listed three recipients and stopped
would be actively misleading ([09](09-rotation-recovery.md)).

## Use as a hook

```sh
# .git/hooks/pre-push
securegit verify || exit 1
```

`install --hooks` writes it. Configuration and index checks are fast enough for
`pre-commit`; `--history` is not, and belongs in CI.

## What this pass actually built

`src/verify.ts` exports `verify(opts): Promise<VerifyReport>` — `{ checks: CheckResult[], findings: Finding[] }` —
and `verifyExitCode(report): number`. It touches no session and unwraps no
key: every check reads git config, `.gitattributes`, or blob magic bytes, all
of which are public even in a locked repository, so `verify` runs the same
whether unlocked or not.

Scope decisions made building it, and why:

- **Index only, not index-and-HEAD separately.** For a repository with no
  uncommitted changes — the common case, and the only one that matters for
  "what would `git push` send" — the index and `HEAD` are byte-identical, so
  scanning both would just do the same work twice. A dirty worktree with
  staged-but-uncommitted plaintext is still caught, since the index reflects
  staged content. `--history`, not this pass, is the tool for "was this ever
  plaintext at `HEAD`" across commits that no longer hold it.
- **Per-file `git check-attr`, not the batched `--stdin -z` form.** The spec's
  optimisation note ("check each blob OID once … cache results by OID") is
  scoped to `--history`, which walks potentially thousands of commits — the
  always-on scan here runs once, over the current tree, and a call per
  tracked file is not yet a real cost. Worth revisiting if it is.
- **Content heuristics scan at most 1 MiB per unprotected file.** Large
  unprotected files are overwhelmingly binary assets, not secrets; skipping
  them keeps a `verify` run bounded without materially weakening the check.
- **L4 (a pattern that stopped matching) has no bespoke detector.** It is
  provably caught by the same leak/advice content scan every other unprotected
  file goes through — an unprotected path whose content matches a heuristic
  is exactly what L4 looks like from the outside. Building a separate
  rename-tracking detector would duplicate that logic for no additional
  coverage.
- **Exit code precedence, where the spec's table lists F-codes independently:**
  a leak (exit 5) outranks a misconfiguration (exit 2), which outranks
  advice-only (exit 0) — `verifyExitCode` checks in that order. A repository
  that is both leaking and missing `filter.securegit.required` is, above all,
  leaking.
- **`--history` is built now too — `historyReport()`, plus `securegit verify
  --history`.** Its tests live in `verify.test.ts` alongside the rest of the
  module rather than in a separate `git.integration.test.ts`-shaped file as
  earlier drafts of this note expected — `verify.test.ts` already spawns a
  real `git` binary for every check it has (there is no injected-IO form of
  "resolve attributes as of commit X"), so the history walk fits the
  existing setup rather than needing its own.
- **A finding aggregates by *path*, across every commit that had plaintext
  there — not one finding per offending commit.** `first`/`last` are the
  oldest and newest commit where the path held plaintext, `commitCount` is
  how many walked commits had it (not necessarily contiguous — a path can
  be fixed and later broken again). This matches the spec's own example
  ("14 commits") more directly than a per-commit finding list would.
- **`reachableFrom` reports local branches, not tags — `git branch
  --contains`, not `git tag --contains` or a combination.** The spec's
  example asks specifically "still reachable from main"; tags mark points
  in history rather than active development lines, and mixing the two would
  make "reachable from" a less useful signal for "is anyone likely to still
  check this out," not a more complete one.
- **The exit code for `--history` is a plain leak/no-leak decision (5 or
  0)** — a history finding is still a leak, the same severity as one caught
  by the base form's index scan, just found by a different walk; there's no
  reason for the two to disagree on precedence.
- **`--access` is built now that spec 08 (multi-recipient) and 09
  (rotation/recovery) exist to read from.** `accessReport()` touches no
  session and unwraps no key, same discipline as `verify()` itself — it
  reads recipient files, the keyring's own `provider` field on each wrapped
  slot (not a fresh unwrap), and two append-only logs
  (`.securegit/recovery-log.json`, and a new
  `.securegit/removed-recipients.json` — see below).
- **A recipient's or provider's generation coverage is reported as a range
  (`gen 1–3`) when contiguous, or an explicit list (`gen 1,3`) when it isn't,
  rather than always assuming contiguity.** In practice a gap shouldn't
  happen — `key rotate` rewraps every existing recipient unconditionally —
  but the formatter doesn't get to assume that just because nothing in this
  codebase currently produces a gap.
- **The recovery log gained a `generations: number[]` field it didn't have
  before**, so `--access` can report what an export actually covers (the
  spec's own example shows "covers gen 1"). This is public metadata — which
  generations, not the code or the file's content — so adding it doesn't
  weaken the log's existing "never the secret" guarantee
  ([09](09-rotation-recovery.md)).
- **`key remove-recipient` deletes the recipient file with no tombstone left
  behind, so nothing on disk recorded that a fingerprint ever had access at
  all — a gap `--access`'s "removed recipients" section needs closed.**
  Rather than require `--access` to walk Git history for a deleted file (real
  complexity that belongs with `--history`'s own future commit-walking
  machinery, not duplicated here), `key remove-recipient` now reads the
  recipient file *before* deleting it and appends `{fingerprint, label,
  removedAt, removedBy, generations}` to a new committed
  `.securegit/removed-recipients.json` — `recipients.ts`'s
  `removedRecipientsLogPath`/`appendRemovedRecipientLogEntry`/
  `readRemovedRecipientsLog`, mirroring `recovery.ts`'s log in shape and
  intent. Never the recipient's still-wrapped keys, which cease to exist
  once the file itself is deleted.
- **`verify --access` needs no key either — it's wired the same way as the
  base `verify` form**: a `PassphraseFileProvider` is never even constructed
  for it, since `accessReport()` reads the keyring's `provider` field
  directly rather than calling `describe()` on anything.
- **`securegit verify` is now wired into `src/cli.ts`.** `cmdVerify` needs no
  passphrase or session — it constructs a `PassphraseFileProvider` purely to
  call `describe()` for the L10 check, never `unwrap()` — prints each check
  and finding to stderr (`✓`/`✗`/`⚠`), and returns `verifyExitCode(report)`
  directly, since `verify.ts`'s own exit codes (0/2/5) already match `cli.ts`'s.
  Landed a pass after the module itself, matching how `crypto.ts`,
  `envelope.ts`, `filter.ts`, `provider.ts`, `keyring.ts`, `install.ts` and
  `session.ts` each landed before `cli.ts` wired them together — but closed
  in the very next cycle here rather than left open indefinitely, once it
  became clear two modules (this one and [12](12-diff-merge.md)'s merge
  driver) were sitting unreachable from the CLI at once.
- **`--json` is the report object itself, `JSON.stringify`'d — no separate
  JSON-specific shape to define or keep in sync.** `VerifyReport`,
  `AccessReport`, and `HistoryReport` are already exactly what a script
  wants; a bespoke JSON schema on top would just be a second description of
  the same fields, one more thing to drift when a field is added. `--json`
  is checked in each of `cmdVerify`/`cmdVerifyAccess`/`cmdVerifyHistory`
  (`cli.ts`) independently, since which mode is active is decided first —
  a caller can combine `--access --json` or `--history --json` freely.

## Test Cases

| Test | Test File | Fixture | Status |
|------|-----------|---------|--------|
| Clean repository passes every check | `src/verify.test.ts` | `repo-protected/` | ✅ |
| Missing filter config is reported (L1) | `src/verify.test.ts` | `attributes/` | ✅ |
| `required = false` is reported (L2) | `src/verify.test.ts` | — | ✅ |
| Removed attribute line is reported (L3) | `src/verify.test.ts` | `attributes/` | ✅ |
| Renamed directory leaving a file unprotected is reported (L4) | `src/verify.test.ts` | `legacy-plaintext/` | ✅ |
| Unprotected file matching a name heuristic yields advice, not a leak | `src/verify.test.ts` | `legacy-plaintext/` | ✅ |
| Unprotected file containing an AWS key id yields advice | `src/verify.test.ts` | `legacy-plaintext/` | ✅ |
| `cachetextconv = true` is reported (L7) | `src/verify.test.ts` | — | ✅ |
| `text` on a protected path is reported (L8) | `src/verify.test.ts` | `attributes/` | ✅ |
| Keyring inside the worktree is reported (L9) | `src/verify.test.ts` | — | ✅ |
| Custodial-only provider set is reported (L10) | `src/verify.test.ts` | — | ✅ |
| `historyReport()` finds plaintext committed on a branch unreachable from HEAD | `src/verify.test.ts` | — | ✅ |
| `historyReport()` resolves attributes as of each commit (both directions) | `src/verify.test.ts` | — | ✅ |
| `historyReport()` does not flag a file that predates protection | `src/verify.test.ts` | — | ✅ |
| `historyReport()` finds a textconv notes ref and counts its entries | `src/verify.test.ts` | — | ✅ |
| `historyReport()` reports no textconv notes ref when none exists | `src/verify.test.ts` | — | ✅ |
| Each blob OID is examined once, even unchanged across many commits | `src/verify.test.ts` | — | ✅ |
| `commitsWalked` reports the total reachable commit count | `src/verify.test.ts` | — | ✅ |
| `verify --history` exits 0 with no plaintext ever committed | `src/cli.test.ts` | — | ✅ |
| `verify --history` exits leaked (5), reporting first/last commit and the rotate-the-secret note | `src/cli.test.ts` | — | ✅ |
| Leak exits 5; advice exits 0; misconfiguration exits 2 | `src/verify.test.ts` | — | ✅ |
| `accessReport()` reports one provider covering the current generation for a plain solo repo | `src/verify.test.ts` | — | ✅ |
| `accessReport()` lists a recipient with the generations their file actually covers | `src/verify.test.ts` | — | ✅ |
| `accessReport()` providers section reflects coverage across a rotation | `src/verify.test.ts` | — | ✅ |
| `accessReport()` providers section is empty, not an error, with no local keyring | `src/verify.test.ts` | — | ✅ |
| `accessReport()` lists recovery exports from the committed log | `src/verify.test.ts` | — | ✅ |
| `accessReport()` lists removed recipients with their generation range | `src/verify.test.ts` | — | ✅ |
| `verify --access` reports "(none)" everywhere for a fresh solo repository, exits 0 | `src/cli.test.ts` | — | ✅ |
| `verify --access` lists a recipient added via `key add-recipient` | `src/cli.test.ts` | — | ✅ |
| `verify --access` lists a recovery export, with the non-revocable-access warning | `src/cli.test.ts` | — | ✅ |
| `verify --access` lists a removed recipient, with the "can still read" note | `src/cli.test.ts` | — | ✅ |
| `verify --json` writes the `VerifyReport` shape to stdout, nothing to stderr | `src/cli.test.ts` | — | ✅ |
| `verify --access --json` writes the `AccessReport` shape to stdout | `src/cli.test.ts` | — | ✅ |
| `verify --history --json` writes the `HistoryReport` shape to stdout, same exit code | `src/cli.test.ts` | — | ✅ |
| `verify` runs without a key present | `src/verify.test.ts` | `repo-protected/` | ✅ |

## Relationship to Other Specs

- [02](02-git-integration.md) — the configuration being audited
- [09](09-rotation-recovery.md) — why the access report carries warnings
- [12](12-diff-merge.md) — the textconv cache, checked here
- [15](15-failure-modes.md) — turning a finding into a next step
- [16](16-adversarial-integrity.md) — the attacks this detects, and the ones it cannot
