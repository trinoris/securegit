# 00. Chaos Test Plan

## Overview

`specs/securegit/*.md` proves the design does what it says under normal
operation and under a small number of hand-picked adversarial scenarios
(T1-T13). This directory is different: it exists to break things that
weren't hand-picked — real process kills at random points, real disk
faults, real file corruption, more concurrent processes than any single
spec bothered to test, and a local process that behaves the way ransomware
or a crashing backup tool behaves (replacing or mangling files securegit
depends on while securegit is mid-operation).

The goal is not new features. Every chaos test targets code that already
exists and already claims to fail closed — `readSession()`'s
single-catch-treats-any-failure-as-locked property, the temp+rename atomic
write shared by `session.ts`/`keyring.ts`/`config.ts`, `required = true`
aborting Git on filter failure. Chaos testing is how those claims get
checked against something less polite than a unit test's hand-constructed
error.

**Status: C1 DONE, C2-C7 NOT STARTED.** C1 (killed mid-write) is built in
`src/chaos.test.ts`: three tests spawn a real `securegit init`/`unlock`/
`key rotate` subprocess and `SIGKILL` it, repeated across a delay sweep, and
found one real gap along the way — `initConfig()` was writing `config.json`
directly (`writeFile`, no temp+rename), unlike every other state file in
this codebase, so a kill mid-write could leave a torn file that then
blocked recovery too (`initConfig()`'s own already-exists guard refuses a
retry against a file it can't read back). Fixed to match `setBindPath()`'s
pattern. See "What C1 actually found" below for what the tests could and
couldn't empirically prove about it. See "Fault injection approach" for how
each category is actually exercised, since "real chaos" and "simulated
fault" are both used here and conflating them would be dishonest about what
each test proves.

## Core Principle

> The same principle as [01](../securegit/01-threat-model.md): fail towards
> ciphertext, never towards plaintext. Chaos testing adds a second half —
> fail towards a clear, recoverable error, never towards silent corruption
> or a half-written file left where a next operation could mistake it for
> good.

## Relationship to 01-sandbox.md

The categories below (C1-C7) are proven in isolation, one fault at a
time, deterministic enough to run in CI on every push. [01](01-sandbox.md)
is the sustained, multi-actor, Docker-orchestrated complement — several
real containers pushing/pulling/rotating against a shared remote for a
bounded stretch of real time while several kinds of chaos run
concurrently, surfacing interactions between categories that no single
Vitest case could construct. Not a replacement for what's below; slower
and opt-in on top of it.

## Relationship to `specs/securegit`

This is not a competing threat model. [01](../securegit/01-threat-model.md)'s
boundary and [16](../securegit/16-adversarial-integrity.md)'s attack
catalogue stand as written. Chaos tests exercise the same boundary under
fault injection instead of a clean simulated error, and extend
[15](../securegit/15-failure-modes.md)'s failure-mode table (F9, F11, F13)
past the two-process, hand-timed cases already proven there.

**T2 still applies and is restated, not reopened:** an adversary with
sustained code execution as the user has the plaintext working tree and the
session cache; nothing here changes that, and nothing here tries to. A
category below simulates a *hostile or crashing local process* touching
securegit's own files — not to detect or stop a live attacker (out of
scope, same as T2), but to prove securegit never trusts a file whose shape
it didn't expect, regardless of *why* that file is wrong. Resilience to
corruption is not the same claim as resistance to attack, and this
document only makes the first one.

## Categories

| | Category | What's injected | Proves |
|---|---|---|---|
| C1 | Killed mid-write | `SIGKILL` sent to a real securegit subprocess at a randomized delay during a keyring/session/config write | the temp+rename pattern never leaves a torn file live at the real path |
| C2 | Disk full (`ENOSPC`) | a write syscall fails partway through an atomic write | the write is refused cleanly, the temp file is removed, the original (if any) is untouched |
| C3 | Permission denied (`EACCES`) mid-operation | the session/keyring directory becomes unwritable between two operations | a clear, non-plaintext-leaking refusal, not a crash |
| C4 | Torn or corrupted state files | a byte flipped, truncated, or emptied in `session`/`keyring.json`/`config.json` | the file is treated as locked/misconfigured, never partially trusted |
| C5 | Concurrency beyond two processes | 8-10 real processes running `clean`/`smudge`/`unlock`/`rotate` against one repo simultaneously | no pairing beyond the `rotate`-vs-`add` case F13 already covers produces mixed or half-written state |
| C6 | Interrupted Git operations | `SIGKILL` to `git clone`/`push`/`pull`, and to the spawned filter subprocess mid-`clean`/`smudge` | Git's own abort leaves no plaintext committed and no half-written object |
| C7 | Hostile/crashing local process | a concurrent process deletes, truncates, or replaces `session`/`keyring.json`/`identity` while securegit is mid-read | same as C4 — the read fails closed, not "attacker defeated" |

## Fault injection approach

Two different techniques, and the test-case table below says which each
row uses:

- **Real chaos** — a real securegit (or `git`) subprocess is spawned and
  killed with `SIGKILL` at a delay drawn from a small random range,
  repeated many times (same shape as [15](../securegit/15-failure-modes.md)
  F13's real-race test), so the kill lands at genuinely different points
  in the write on different iterations rather than one hand-picked line.
  Used for C1 and C6.
- **Simulated fault** — `ENOSPC`/`EACCES` are awkward to trigger for real
  portably (a loop-mounted, size-limited filesystem works on Linux CI but
  not everywhere this package needs to run), so C2 and C3 inject the
  failure by making the specific `fs/promises` call inside the write path
  reject with that error code once, then verifying cleanup and the
  refusal message. This proves the *cleanup and error-handling code path*
  is correct; it does not prove the OS surfaces the error the same way
  everywhere, which real chaos would and simulated fault cannot.
- **Direct corruption** — C4 and C7 write bytes to the real file on disk
  (or delete it) directly, no subprocess involved, then run a normal
  operation against it. This is closer to a unit test than chaos in the
  literal sense, but is grouped here because it's the same underlying
  question ("does a file that isn't what we wrote get trusted anyway") as
  the rows that do use process-level chaos.
- **Real concurrency** — C5 spawns N real processes via `Promise.all`,
  same principle as F13, just more of them and more command variety.

## What C1 actually found

C1's delay sweep can't use a fixed millisecond list — cold Node/ESM startup
alone is ~250ms on the machine this was built on, and `init`/`unlock`/`key
rotate` each add real scrypt cost (`DEFAULT_SCRYPT_N`,
[06](../securegit/06-key-provider-port.md)) on top, so a delay chosen for
one machine either kills before a slower machine has even loaded its
modules or lands on an already-finished process on a faster one. Each C1
test now measures its own command's *unkilled* duration once, then sweeps
delays as fractions of that (5%-120%), which is what actually let the
sweep land inside the real write for the first time — the first version of
this test, with a hand-picked 0-150ms sweep, killed the process every
single iteration but never once caught it past the module-loading phase,
because a real `init` run takes 250-450ms end to end.

Even correctly calibrated, C1 as built could not force a kill during the
single `writeFile()` syscall itself — that window is apparently narrower
than a `setTimeout`'s own scheduling jitter from a separate controlling
process, and every iteration across many runs landed either clearly before
the write (file absent afterward) or clearly after (file fully valid).
What C1 *does* empirically prove, repeatedly and reliably, is the outcome
that matters operationally: killed at any point across a command's real
duration, the affected file is always either absent or fully valid, never
present-but-unreadable, and every command is cleanly re-runnable
afterward. The stronger claim — that the temp file itself could never be
torn, only ever the *rename* target, which is atomic by construction — is
a proof-by-construction argument, the same shape as
[15](../securegit/15-failure-modes.md)'s `readSession()` argument for F13,
not something C1's process-kill timing could independently verify at the
syscall level.

The one real gap this found: `initConfig()` (`src/config.ts`) wrote
`config.json` directly, the only one of the four state-file writers in
this codebase (`config.json` via `setBindPath()`, `keyring.json`,
`session`) not using the temp+rename pattern. Low practical severity — a
torn write is already reported as a clear `ConfigError` on the next read,
never trusted — but it had a real, separate consequence: a `config.json`
left torn by a killed `init` could never be recovered by re-running `init`,
because `initConfig()`'s own already-exists guard (`stat(path)`) sees the
torn file and refuses, permanently, without ever telling the operator why.
Fixed to match `setBindPath()`'s pattern; C1's `init` test would now find
`config.json` absent (not yet renamed) rather than present-but-torn for
any kill landing before the write completes, restoring exactly the
"nothing written yet, just retry" recovery path.

## Test Cases

| Test | Test File | Technique | Status |
|------|-----------|-----------|--------|
| C1: `init` killed at a random point never leaves `config.json` torn — absent or fully valid, never a fragment `readConfig()` can't cleanly classify | `src/chaos.test.ts` | real chaos | ✅ |
| C1: `unlock` killed at a random point never leaves the session torn — absent (still locked) or fully valid, never a fragment `readSession()` could half-parse | `src/chaos.test.ts` | real chaos | ✅ |
| C1: `key rotate` killed at a random point never leaves `keyring.json` torn — the old generation list or the fully-rotated one, never a fragment | `src/chaos.test.ts` | real chaos | ✅ |
| C2: `ENOSPC` during the keyring write is refused, the temp file is removed, the previous keyring still reads back unchanged | `src/keyring.test.ts` | simulated fault | 🔲 |
| C2: `ENOSPC` during the session write is refused, the temp file is removed, any previous session still reads back unchanged | `src/session.test.ts` | simulated fault | 🔲 |
| C2: `ENOSPC` during `setBindPath`'s config write is refused, the temp file is removed, the previous config still reads back unchanged | `src/config.test.ts` | simulated fault | 🔲 |
| C3: session directory becoming unwritable mid-run fails `unlock` with a clear, non-plaintext message, not a crash | `src/chaos.test.ts` | simulated fault | 🔲 |
| C3: keyring directory becoming unwritable mid-run fails `key rotate` with a clear, non-plaintext message before any rewrap is lost | `src/chaos.test.ts` | simulated fault | 🔲 |
| C4: a single bit-flipped byte in the session file is treated as locked, not partially read | `src/session.test.ts` | direct corruption | 🔲 |
| C4: a truncated `keyring.json` is refused with a clear "could not read keyring" message, never a partial generation list | `src/keyring.test.ts` | direct corruption | 🔲 |
| C4: an emptied (zero-byte) `config.json` is refused, not treated as "not yet initialised" | `src/config.test.ts` | direct corruption | 🔲 |
| C4: `config.json` with a wrong-typed field (`bindPath: "yes"`, `padTo: "large"`) is refused, not coerced | `src/config.test.ts` | direct corruption | 🔲 |
| C5: 8 concurrent real `clean`/`smudge` invocations against different paths in the same repo never cross-write each other's output | `src/chaos.integration.test.ts` | real concurrency | 🔲 |
| C5: a concurrent `unlock` and `key rotate` never leave the session referencing a generation the keyring no longer has | `src/chaos.integration.test.ts` | real concurrency | 🔲 |
| C6: `git clone` killed mid-transfer leaves no partial object claiming to be complete on the next `git fsck` | `src/chaos.integration.test.ts` | real chaos | 🔲 |
| C6: the filter subprocess killed mid-`clean` aborts the `git add` (`required = true`) with the index left exactly as before | `src/chaos.integration.test.ts` | real chaos | 🔲 |
| C6: the filter subprocess killed mid-`smudge` leaves the checkout failed, never a partially-decrypted file mistaken for complete | `src/chaos.integration.test.ts` | real chaos | 🔲 |
| C7: the session file deleted by a concurrent process between `unlock` and the next `clean` is treated as locked, exactly as an expired session already is | `src/chaos.test.ts` | direct corruption | 🔲 |
| C7: the keyring file replaced by a concurrent process with unrelated valid JSON (not a keyring) is refused, not partially trusted | `src/chaos.test.ts` | direct corruption | 🔲 |
| C7: the identity file replaced by a concurrent process mid-`key rotate` fails that specific operation without corrupting the keyring already on disk | `src/chaos.test.ts` | direct corruption | 🔲 |

## Explicitly not in scope

1. **Detecting or stopping a live local attacker.** Restated from T2: code
   execution as the user is game over. C7 proves file corruption is
   handled safely regardless of cause; it does not and cannot prove an
   active attacker gains nothing, because an active attacker with local
   code execution already has the plaintext.
2. **Filesystem-level guarantees below Node's `fs` API.** These tests
   trust that a completed `rename()` is atomic on the target filesystem,
   per POSIX and per Node's own documentation. Filesystems that violate
   that guarantee (some network filesystems, some misconfigured setups)
   are a documented assumption of every atomic-write pattern already in
   this codebase, not a new gap chaos testing introduces.
3. **Recovering encrypted-over ciphertext.** If a real ransomware process
   encrypts `.git/objects` itself (not securegit's key material, the
   *already-ciphertext* blobs), that is data loss like any other, backup
   and restore is the answer, and no design choice here changes that.
4. **Performance or resource exhaustion under chaos.** C5's process count
   is chosen to exercise more interleavings than F13, not to load-test.

## Open questions before implementation starts

- **Kill-delay ranges for C6.** Resolved for C1 (see "What C1 actually
  found"): a hardcoded millisecond range doesn't survive different machine
  speeds, so each test measures its own command's natural duration once and
  sweeps delays as fractions of it. C6 kills `git clone`/`push`/`pull`
  (much longer-running, network/disk-bound rather than CPU-bound like
  scrypt) and the filter subprocess specifically rather than the whole
  `git` invocation — the same fraction-of-measured-duration approach likely
  applies, but which duration to measure (the whole `git` command, or just
  the filter subprocess's own share of it) needs deciding once C6 is
  actually being built.
- **Where `src/chaos.test.ts` and `src/chaos.integration.test.ts` set up
  fixtures.** Likely reuses the `key rotate / reencrypt` describe block's
  `setUp()`/`gitEnv()`/`realGit()` helpers from `src/cli.test.ts` rather
  than duplicating them — to be confirmed once C1 is actually being
  written, not decided in the abstract here.
