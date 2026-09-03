# 07. Unlock & Session

## Overview

Git runs filters non-interactively, thousands of times, with stdin and stdout
already committed to carrying file content. There is nowhere to prompt for a
passphrase. This spec is how the key gets to the filter anyway, and what the
filter does when it does not.

**Status: IMPLEMENTED**, all four non-interactive sources built.
`src/session.ts` (the cache, TTL and permission hardening) and the
clean/smudge asymmetry in `src/filter.ts` are both built and tested,
including end to end against real `git` in `src/git.integration.test.ts`.
Of the "Non-interactive unlock" table's four precedence-ordered sources
for the filter's key lookup: the session file (bottom) always worked.
`SECUREGIT_SESSION_KEY`
(top) is implemented — `src/session.ts`'s `keySourceFromSessionKey()`
decodes it, and `loadKeys()`/`runFilterProcess()` in `src/cli.ts` both check
it ahead of everything else. There is no separate command that *produces*
one — it is the exact bytes `writeSession()` already writes to a session
file, base64-encoded; any caller that already holds one (a parent process,
a wrapper script) can read and re-export its own file's content as-is,
without a new CLI surface.

`SECUREGIT_PASSPHRASE` (second) is now implemented as a filter-time source
too, alongside its existing role as the *interactive* `init`/`unlock`/
`identity init` prompt fallback — `keySourceFromPassphraseEnv()` in
`src/cli.ts` unwraps the local keyring file directly when it's set, so
`clean`/`smudge`/`status`/every command through `loadKeys()` work without
`unlock` ever running. **This is a deliberately accepted tradeoff, not an
oversight**: unlike `SECUREGIT_SESSION_KEY`, this source has no
`expiresAt` and `lock` cannot revoke it — there is no session file behind
it to remove — so for as long as the variable is set in a process's
environment, every command through `loadKeys()` gets standing,
non-time-bounded access, in tension with this spec's own core principle
("Unlocking is an explicit act with a lifetime"). Acceptable, even
intended, for the CI use case this row exists for (an ephemeral runner,
the secret coming from its own store, no persistence to worry about) — a
real risk for a long-lived developer shell that happens to have this set
persistently, silently, for any reason. Uncached for the one-shot
`clean`/`smudge` form (each invocation is a fresh process — scrypt's real
wall-clock cost, meant to be paid once per unlock, is paid again per
file); `runFilterProcess()` caches it for the lifetime of the long-running
`filter-process` server instead, which is the one context where "once" is
actually achievable without writing a session to disk.

`SECUREGIT_IDENTITY_FILE` (third) is implemented too, but not as a fourth
independent tier — it names *which* identity to join with, but carries no
secret of its own, so it needs `SECUREGIT_PASSPHRASE` to unlock it. When
both are set, `SECUREGIT_IDENTITY_FILE` changes what `SECUREGIT_PASSPHRASE`
is applied *to*: `keySourceFromIdentityFileEnv()` reads the named identity
file, unlocks its private key with the passphrase, then finds the matching
`.securegit/recipients/<fingerprint>.json` and derives a `KeySource` from
it — the same core steps `cmdUnlockViaRecipient` already takes for
`unlock`'s own no-local-keyring fallback, minus the session write, since
nothing here ever touches disk. Set alone, without `SECUREGIT_PASSPHRASE`,
it is never even looked at — `loadKeys()`'s branch on `SECUREGIT_PASSPHRASE`
is what decides whether `SECUREGIT_IDENTITY_FILE` gets consulted at all,
not the other way around. This resolved a real ambiguity in this
document's own precedence table, which lists the two as separate,
independently-ordered rows with no stated relationship — flagged and
confirmed rather than assumed, since guessing wrong here (checking each
env var in isolation) would have made `SECUREGIT_PASSPHRASE` always mean
"unwrap the local keyring," silently ignoring `SECUREGIT_IDENTITY_FILE`
whenever both happened to be set. Cached the same way as
`SECUREGIT_PASSPHRASE` in `runFilterProcess()`: once per server lifetime,
not once per blob.

## Core Principle

> Unlocking is an explicit act with a lifetime. A filter never prompts, never
> blocks, and never guesses — it either has the key or takes the documented path
> for not having it.

## Why the filter cannot prompt

During `git clone`, `git checkout` or `git merge`, the filter's stdin and stdout
are the content channel. Writing a prompt to stdout corrupts the file. Reading a
passphrase from stdin consumes the content. `/dev/tty` may not exist — a CI
runner, a GUI client, a hook invoked by an editor. And even where it does,
prompting once per file across a 400-file checkout is not a user experience.

So: **the key must already be available when the filter starts.**

## The session cache

`securegit unlock` performs the provider unwrap once, interactively, and caches
the unwrapped RMKs for a bounded time.

```
$XDG_RUNTIME_DIR/securegit/<repoId>.session      ← tmpfs, cleared on logout
~/.securegit/session/<repoId>.session            ← fallback, mode 0600
```

```json
{
  "version": 1,
  "repoId": "…",
  "expiresAt": "2026-09-01T18:22:04Z",
  "keys": { "1": "<hex>", "2": "<hex>", "3": "<hex>" }
}
```

The file contains **unwrapped** master keys. That is the trade, and it is the
same one `ssh-agent` and `gpg-agent` make: a bounded window in which a process
running as the user can read the key, in exchange for a tool that can be used.
The mitigations are ordinary and all of them are required:

- `0600`, and the directory `0700`, both verified on every read; a session file
  with wider permissions is deleted rather than used.
- `$XDG_RUNTIME_DIR` preferred, because it is `tmpfs` and disappears at logout —
  the key never reaches a disk that could be imaged.
- Default TTL **8 hours**, configurable, capped at 24. Expiry is checked on
  read, and an expired file is unlinked.
- `securegit lock` unlinks it immediately; so does `key rotate`.
- Never inside the repository. `verify` ([13](13-verify.md)) checks.

`unlock --ttl 0` unlocks for a single command via an inherited environment
variable rather than a file, for users who would rather not have one at all.

### Three ways a locked session ends, only two of which delete the file

`readSession` (`src/session.ts`) always returns a usable `KeySource` — never
`null`, never a throw — but the path it takes to a locked result differs by
cause, and only two of the three remove the file from disk:

| Cause | File removed? | Why |
|---|---|---|
| Missing entirely | n/a | the ordinary "never unlocked" case |
| Expired | yes | spec below — an expired session should not linger |
| Unsafe permissions (not `0600`) | yes | the file cannot be trusted, so keeping it around is pure risk |
| Wrong `repoId`, malformed JSON, unknown `version` | **no** | this might be a file written by a *newer* version of the tool, or simply the wrong path passed by a caller — deleting on a read failure that could be our own bug is the wrong default |

The last row's asymmetry is deliberate: unsafe permissions and expiry are
conditions this version of the tool is certain about and knows how to act on
safely. A parse failure or a version it doesn't recognise is a case where the
safest action is to do nothing to the file and simply report "locked" — the
same as if it had never been unlocked.

### A known gap: interactive prompting isn't wired yet

`src/bin/securegit.ts` reads real stdin to a `Buffer` for `init`/`unlock`'s
passphrase, with one guard: if stdin is a TTY, it reads nothing rather than
blocking indefinitely waiting for input the user hasn't typed yet. Combined
with `resolvePassphrase`'s fallback order (`SECUREGIT_PASSPHRASE` env var,
else stdin), that means **an interactive terminal user who does not set
`SECUREGIT_PASSPHRASE` currently gets an empty passphrase**, not a prompt.
Masked terminal input (readline with echo off, or piping through `/dev/tty`)
is real, necessary follow-up work, not a design decision — this is a
placeholder until it lands, called out here rather than left silently broken.

### Non-interactive unlock

For CI and scripted use, in precedence order:

| Source | Use | Status |
|---|---|---|
| `SECUREGIT_SESSION_KEY` | a session key handed directly to a child process — the exact bytes `writeSession()` writes to a session file, base64-encoded; nothing produces this but a caller re-exporting a file it already holds | implemented (`keySourceFromSessionKey()`, `src/session.ts`); time-bounded — carries its own `expiresAt` |
| `SECUREGIT_PASSPHRASE` | CI, where the passphrase comes from the runner's secret store — unwraps the local keyring file directly | implemented (`keySourceFromPassphraseEnv()`, `src/cli.ts`), both as this filter-time source and its pre-existing *interactive* `init`/`unlock`/`identity init` prompt-fallback role; **not time-bounded** — no `expiresAt`, and `lock` cannot revoke it, since there is no session file behind it. See below. |
| `SECUREGIT_IDENTITY_FILE` | a machine identity ([08](08-multi-recipient.md)) — needs `SECUREGIT_PASSPHRASE` alongside it to unlock; never consulted on its own | implemented (`keySourceFromIdentityFileEnv()`, `src/cli.ts`); same standing-access caveat as `SECUREGIT_PASSPHRASE` above, since it's unlocked by the same variable |
| session file | the normal interactive case | implemented; time-bounded (TTL) |

A CI runner given any of these **is a trusted machine** by
[01](01-threat-model.md)'s definition, and should hold a dedicated recipient key
that can be revoked without touching anyone else's ([09](09-rotation-recovery.md)).

**None of the three authenticate anything beyond the single `runCli()`
invocation that reads them — they must never cascade into a subprocess a
command merely spawns.** Found the hard way: `key rotate`'s dirty-check
spawns a real `git status`, which spawns `clean` itself as a nested
subprocess to compare the worktree against the index — before that spawn
was corrected to strip these three first, whatever was in the parent
invocation's environment reached the nested filter too, making it
re-authenticate via a fresh scrypt derivation instead of reading the
session that invocation's own `unlock` had already written. See
[09](09-rotation-recovery.md)'s "What this pass actually built" for the
fix and how a real CI failure, not a design review, is what surfaced it.

**`SECUREGIT_PASSPHRASE` is the one source that breaks this document's core
principle** ("Unlocking is an explicit act with a lifetime") **by design,
not by oversight.** A session — file or `SECUREGIT_SESSION_KEY` — always
carries an `expiresAt` and can be revoked early by `lock`. This source has
neither: it unwraps the local keyring fresh from whatever's in the
environment, for as long as the variable is set, with nothing on disk for
`lock` to remove. That is exactly what CI wants (an ephemeral runner, no
state to leak, no session file worth writing) and exactly what a
long-lived developer shell does not: `SECUREGIT_PASSPHRASE` left set for
any reason — a forgotten export, an inherited parent-process environment —
grants every command through `loadKeys()` standing access with no
time bound and no way to end it short of unsetting the variable. Also
uncached for the one-shot `clean`/`smudge` form: scrypt's cost, meant to
be paid once per unlock, is paid again on every single invocation, since
each is a fresh process with nothing to remember the last one's work.
`runFilterProcess()` caches the unwrap for its own server's lifetime
instead — the one context where "once" is achievable without a session
file — so pairing this source with `filter.securegit.process`
([11](11-filter-process.md)) is the way to actually get the "once per
unlock" cost this document otherwise promises.

## The `KeySource` seam

`clean`/`smudge`/`textconv` in `src/filter.ts` do not import the keyring
directly. They take a small injected interface instead:

```typescript
export interface KeySource {
  /** The generation `clean` encrypts under. `null` when locked. */
  current(): { keyId: string; rmk: Buffer } | null;
  /** The master key for one generation, or `null` if this keyring lacks it. */
  find(keyId: string): Buffer | null;
  /** Every keyId currently held, for diagnostics. */
  available(): string[];
}
```

This is what makes the asymmetry below testable without a real keyring,
session cache or key provider: the test suite hands `clean`/`smudge` a stub
that is "locked" (`current()` returns `null`) or "holds generations 2–3 but
not 4" (`find('4.…')` returns `null` while `available()` lists what it does
hold), and asserts the exact behaviour each case must produce. `keyring.ts`
([05](05-key-hierarchy.md)) and `session.ts` implement exactly this shape; the
filter never needs to know that a session file or a provider unlock sits
behind it.

## The asymmetry

This is the most important rule in the document, and it is not symmetric on
purpose.

```
   clean   without a key   →   HARD FAIL, exit non-zero, nothing written
   smudge  without a key   →   emit the ciphertext, warn on stderr, exit 0
```

**`clean` must fail.** The alternative is writing plaintext into the object
database, which is the one outcome the tool exists to prevent. With
`filter.securegit.required = true` ([02](02-git-integration.md)), a non-zero
exit aborts the `git add` or `git commit`. The user sees:

```
securegit: repository is locked; run `securegit unlock` before committing
           protected files (config/production.json)
error: external filter 'securegit clean -- %f' failed
```

`smudge` reads the same distinction: if the keyring is locked outright
(`current() === null`), the message is "locked", even for a blob whose
generation this keyring would hold once unlocked. A named-generation mismatch
([15](15-failure-modes.md), F5) is only reported once the keyring is unlocked
and still does not have that specific generation — otherwise every warning
during a keyless clone would misleadingly enumerate generations the user
cannot yet do anything about.

**`smudge` must not fail.** A hard failure here means `git clone` cannot
complete, so a colleague who does not yet have a key cannot obtain the
repository at all — and neither can a build that only needs the unprotected 95%
of it. Emitting the ciphertext leaves a checkout that is correct in every file
that is not protected, and visibly encrypted in the ones that are. The recovery
is two commands, not the `git checkout --force .` originally documented here:

```
securegit unlock
git rm --cached -r -q . && git checkout HEAD -- .
```

`git checkout --force .` (and even the plumbing-level
`git checkout-index --force --all`) is **not** sufficient, `--force` or no.
Confirmed against a real clone in [02](02-git-integration.md) and
[15](15-failure-modes.md): Git's stat-cache treats a worktree file whose
content already matches what the index expects as up to date and skips
rewriting it, so `smudge` never reruns — regardless of how the filter
configuration or unlock state changed in the meantime. `git rm --cached`
first empties the index entries so Git has no "already matches" shortcut left
to take; `checkout HEAD -- .` then re-materializes every path from the commit,
which is what actually invokes `smudge`. This is the same technique
git-crypt/git-lfs document for the identical problem, not a securegit-specific
workaround.

`--strict` inverts the smudge behaviour for anyone who prefers a failed clone to
a partially-encrypted worktree. It is not the default because the failure is
silent about *why* to most Git clients, and the partial checkout is not.

### The one thing that must never happen

A worktree file must never be *silently* left as ciphertext and then committed
back as ciphertext-of-ciphertext. `clean`'s passthrough rule
([04](04-envelope-format.md)) makes that impossible: a valid envelope that
authenticates is emitted unchanged, so re-committing an unsmudged file is a
no-op rather than a second layer.

## `securegit status`

The command that answers "why is this not working", without leaking anything:

```
repository   /home/u/proj              repoId 4f9a…
config       .securegit/config.json    format 1, bindPath false
keyring      ~/.securegit/repos/4f9a…  generations 1–3, current 3
providers    passphrase-file (available)   piv (not available)
session      unlocked, expires in 6h 12m
git config   filter ✓  required ✓  diff ✓  cachetextconv ✓
attributes   4 patterns, 12 files protected
```

Exit code 0 when usable, 1 when locked, 2 when misconfigured — so a shell prompt
or a pre-push hook can branch on it.

As built, this illustrative example is richer than the actual output:
`securegit status` prints `repository`/`repoId`/`bindPath`/`padTo`/`session`
plus a one-line pointer to `securegit status --json` for
[14](14-metadata-leakage.md)'s M1–M12 metadata-leakage report (the
`metadata` field of `--json`'s output). The keyring generation range,
per-provider availability, git-config check marks, and attribute/file counts
shown above are not built — `status` stays a cheap, session-only read
(`loadKeys`), not a scan of the keyring file or the working tree the way
`verify` is.

## Test Cases

| Test | Test File | Fixture | Status |
|------|-----------|---------|--------|
| `clean` without a key exits non-zero and writes nothing to stdout | `src/filter.test.ts` | — | ✅ |
| `git add` of a protected file fails when locked | `src/git.integration.test.ts` | `repo-protected/` | ✅ (F16's own test — touching then re-adding a locked, unmodified file — already exercises this exact assertion; also reconfirmed by 15-failure-modes.md's F1 test) |
| `smudge` without a key emits input unchanged and exits 0 | `src/filter.test.ts` | — | ✅ |
| `git clone` succeeds with no key present | `src/git.integration.test.ts` | `repo-protected/` | ✅ |
| `unlock` then `rm --cached`+`checkout HEAD` repairs a keyless clone | `src/git.integration.test.ts` | `repo-protected/` | ✅ |
| `--strict` makes `smudge` fail instead | `src/filter.test.ts` | — | ✅ |
| Session file is created `0600` in a `0700` directory | `src/session.test.ts` | — | ✅ |
| Session file with mode `0644` is deleted, not used | `src/session.test.ts` | — | ✅ |
| Expired session is unlinked and treated as locked | `src/session.test.ts` | — | ✅ |
| `lock` removes the session file | `src/session.test.ts` | — | ✅ |
| `rotate` invalidates the existing session | `src/cli.test.ts` | — | ✅ (`key rotate`'s own "adds a generation, keeps the old one, and invalidates the session" test — `status` exits locked (1) immediately after rotate, before a fresh `unlock`; `lockSession()`'s generic unlink behavior, which this literally calls, is separately proven in `src/session.test.ts`) |
| `$XDG_RUNTIME_DIR` is preferred when set and writable | `src/session.test.ts` | — | ✅ |
| TTL above the cap is clamped | `src/session.test.ts` | — | ✅ |
| `SECUREGIT_SESSION_KEY` decodes to a usable `KeySource`, matching the wrong-repoId/expired/malformed handling `readSession()` already has | `src/session.test.ts` | — | ✅ |
| `SECUREGIT_SESSION_KEY` takes precedence over an existing, valid session file — `loadKeys()` and `runFilterProcess()` both | `src/cli.test.ts` | — | ✅ |
| `SECUREGIT_PASSPHRASE` unwraps the local keyring directly, without `unlock`, for `clean`/`smudge`/`status`/every command through `loadKeys()` | `src/cli.test.ts` | — | ✅ |
| A wrong `SECUREGIT_PASSPHRASE` is locked, not a throw, and does not fall back to an existing valid session file | `src/cli.test.ts` | — | ✅ |
| `SECUREGIT_SESSION_KEY` still wins when both it and `SECUREGIT_PASSPHRASE` are set | `src/cli.test.ts` | — | ✅ |
| `runFilterProcess()` caches the `SECUREGIT_PASSPHRASE` unwrap for the server's lifetime — a second blob still decrypts after the local keyring file is deleted | `src/cli.test.ts` | — | ✅ |
| A removed recipient's own already-unlocked session keeps working across a real `key remove-recipient`/`rotate` on the repository — proof that no filter-time source can reach into a session and revoke it, same tradeoff this section documents in the other direction | `src/git.integration.test.ts` | `identities/` | ✅ (08-multi-recipient.md's "removed recipient can still read pre-rotation blobs") |
| `SECUREGIT_IDENTITY_FILE` + `SECUREGIT_PASSPHRASE` join via a named identity file's recipient entry, without `unlock` and without a local keyring | `src/cli.test.ts` | — | ✅ |
| A wrong passphrase, a missing identity file, or an identity with no matching recipient file are each locked, not a throw | `src/cli.test.ts` | — | ✅ |
| `SECUREGIT_IDENTITY_FILE` alone, without `SECUREGIT_PASSPHRASE`, is never consulted — falls through to the session file | `src/cli.test.ts` | — | ✅ |
| `SECUREGIT_IDENTITY_FILE` + `SECUREGIT_PASSPHRASE` takes precedence over an existing, valid session file | `src/cli.test.ts` | — | ✅ |
| `runFilterProcess()` caches the `SECUREGIT_IDENTITY_FILE` unwrap for the server's lifetime — a second blob still decrypts after the recipient file is deleted | `src/cli.test.ts` | — | ✅ |
| Env-var sources are honoured in the documented precedence, in full | `src/session.test.ts`, `src/cli.test.ts` | — | ✅ |
| No filter code path calls a provider with `interactive: true` | `src/filter.test.ts` | — | ✅ |
| Filter writes no diagnostics to stdout, only stderr | `src/cli.test.ts` | — | ✅ (`clean`'s locked-failure test now also asserts zero stdout writes; `filter.ts` itself has no stdout concept to test — it returns a `Buffer` or throws, never writes anywhere, which is what `src/filter.test.ts`'s "`clean` without a key exits non-zero and writes nothing to stdout" row above already covers at that layer) |
| `status` exit codes are 0 / 1 / 2 as specified | `src/cli.test.ts` | — | ✅ (three separate existing tests: "status exits 2 before init", "status exits 1 (locked) after init but before unlock", "unlock exits 0 with the right passphrase, status then exits 0") |
| Committing an unsmudged ciphertext file does not double-encrypt | `src/git.integration.test.ts` | `repo-protected/` | ✅ |

## Relationship to Other Specs

- [02](02-git-integration.md) — `required = true`, which makes the hard fail work
- [04](04-envelope-format.md) — the passthrough rule behind the no-double-encrypt guarantee
- [06](06-key-provider-port.md) — what `unlock` actually calls
- [11](11-filter-process.md) — the same rules inside the long-running protocol
- [15](15-failure-modes.md) — the full failure table
