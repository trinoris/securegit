# 01. Chaos Sandbox

## Overview

[00](00-test-plan.md)'s categories (C1-C7) are proven as isolated,
deterministic, one-thing-at-a-time Vitest cases — a single kill, a single
corrupted file, one `Promise.all` race. This spec extends that into a
live, sustained, multi-actor simulation: several independent
"workstations" (Docker containers) push, pull, rotate and unlock against
a shared remote for a bounded period of real wall-clock time, while
adversarial background processes tamper with files and the repository
concurrently — one shaped like commodity ransomware, one shaped like a
hostile collaborator with real push access, one shaped like ordinary
infrastructure failure. A verifier then audits every workstation and the
remote against three hard invariants that must hold regardless of what
chaos happened, no exceptions:

1. **No plaintext ever crossed the boundary**
   ([01](../securegit/01-threat-model.md)) — every protected file, in
   every commit that ever existed, everywhere in history.
2. **The codebase's integrity is guaranteed** — the repository's object
   graph itself stays structurally sound (`git fsck`), independent of
   confidentiality.
3. **Data loss is zero** — every commit this run itself confirmed as
   pushed is still reachable, and every protected blob in history still
   decrypts to its original, correctly-shaped content, using only the
   tools this package already ships (`unlock`, `key rotate`'s forward-only
   generations). "Recovered eventually after a retry" is fine; "gone" is
   not, for anything the run itself confirmed had landed.

See "Verifying the invariants" below for exactly how each is checked, and
the trust boundary the third one rests on.

**Status: FIRST IMPLEMENTATION BUILT, NOT DOCKER-VERIFIED.** Everything
described below exists under `chaos/` — the compose file, the shared
Dockerfile, and all seven scripts (three actor roles via one parameterized
driver, three chaos agents, the verifier). Docker itself was not available
in the environment this was built in (WSL, Docker Desktop's WSL
integration not enabled), so nothing here has been run end to end. What
*was* verified without Docker, directly against a real local git repo:
`chaos/lib/git-plumbing.mjs`'s T1/T3/T4/T5/remove commit-construction
logic (byte-identical relocation, correct rollback-to-older-blob, correct
content replacement — all confirmed against real commits on a real bare
repo), the binary-safety fix in `chaos/lib/proc.mjs`'s `runBinary()`
(confirmed byte-identical round-trip of non-UTF-8 content, after catching
and fixing a real corruption bug where the verifier's plaintext check
would have decoded ciphertext through UTF-8 and silently produced false
"plaintext leaked" findings), `chaos/lib/log.mjs` and
`chaos/lib/wait-for.mjs`, and that every `/app/dist/*.js` re-export in
`chaos/lib/paths.mjs`/`chaos/verifier/verify.mjs` actually exists in the
real build output. The zero-data-loss check specifically: built a real
two-commit history spanning an actual `key rotate` (generation 1 and
generation 2) against a real local build, then confirmed
`finalIntegritySelfCheck()`'s exact logic — `git log --all`, walking
`secrets/` blobs, `securegit smudge --strict` via the new binary-safe
`securegitBinaryIO()` — decrypts both generations' content correctly and
recovers the original `{role, counter}` shape, zero failures; also
confirmed `git fsck --full --no-dangling` exits clean against that same
repo. What's genuinely unverified: the Docker build itself,
compose networking/volume/PID-namespace sharing, `iptables` inside the
Alpine image, and the full bootstrap-through-verify sequence running
together. See `chaos/README.md`'s Troubleshooting section for the
specific things most likely to need a second pass.

**Later correction: since verified end-to-end on real infrastructure.**
The above is the original build-time note and is kept for its own record,
but it's stale — GitHub Actions' `chaos` job (`.github/workflows/node.js.yml`)
has since run this stack for real, more than once, on real Docker (not
WSL), including a full `docker compose up --build` and a real verifier
audit against a real fresh clone. The genuinely-unverified list above
turned out fine except for one real bug (nonzero exit from `docker compose
wait` aborting the "Extract" step under `bash -e`, losing that run's own
evidence — fixed, not a sandbox-logic bug). The T1 finding these runs
surfaced (plaintext leaking after chaos-5's attribute downgrade, nothing
local catching it) matches this spec's own T1 discussion and
[16](../securegit/16-adversarial-integrity.md)'s exactly — see that file's
T1 section for the operator-side recovery now built in response.

## Core Principle

> Same as [00](00-test-plan.md): fail towards a clear, recoverable error,
> never towards silent corruption. This sandbox adds one more axis — under
> *sustained, combined, concurrent* load, not just one fault at a time.

## Why Docker, not more Vitest processes

- **Real filesystem isolation per actor.** A chaos agent tampering with
  one actor's `~/.securegit` must not accidentally touch another's — two
  `mkdtemp`'d directories in one Node process already keep apart by
  construction, which is exactly the case that needs *not* to be assumed
  here, where an agent is deliberately trying to reach into things.
- **A real network hop for push/pull.** C6 (interrupted Git operations)
  becomes about an actual TCP connection dropping mid-transfer, not a
  killed local subprocess sharing the same filesystem as the thing it's
  pushing to.
- **Containers can be killed and restarted wholesale**, simulating a
  workstation crash mid-operation rather than just the `securegit`
  subprocess, and given independent resource limits (memory, disk quota)
  for C2 without special-casing one process among many sharing a CI
  runner's actual disk.
- **Genuinely separate identity per actor** — its own passphrase, its own
  identity keypair, its own clock — matching
  [08](../securegit/08-multi-recipient.md)'s multi-recipient model more
  faithfully than in-process fixtures sharing one Node heap ever could.

## Topology

```
                         ┌───────────────────┐
                         │   remote (bare     │
                         │   repo, git        │
                         │   daemon)          │
                         └─────────┬──────────┘
                    push/pull over a real network
              ┌─────────────────────┼─────────────────────┐
        ┌─────▼─────┐         ┌─────▼─────┐         ┌─────▼─────┐
        │  actor-1  │         │  actor-2  │         │  actor-3  │
        │collaborator│        │collaborator│        │ operator  │
        └─────┬─────┘         └─────┬─────┘         └─────┬─────┘
       shares filesystem      shares filesystem            │
              │                     │                       │
        ┌─────▼─────┐         ┌─────▼─────┐         ┌─────▼─────┐
        │  chaos-4  │         │  chaos-6  │         │  chaos-6  │
        │  "virus"  │         │  "infra"  │         │  "infra"  │
        └───────────┘         └───────────┘         └───────────┘

        ┌───────────┐
        │  chaos-5  │──── ordinary push access, its own clone ────▶ remote
        │"attacker" │
        └───────────┘
```

chaos-5 is deliberately drawn separately: it never touches an actor's
container. It only ever acts the way a real hostile collaborator with
legitimate write access would — through `git push` against `remote`,
nothing else. chaos-4 and chaos-6 share their target actor's filesystem
namespace (see "Sidecar vs. separate container" in Open Questions).

## Actors (legitimate)

| | Role | Behaviour |
|---|---|---|
| actor-1 | Collaborator A | Clones, protects a file set, periodically edits+commits+pushes, periodically pulls, unlocks as needed. Ordinary daily use. |
| actor-2 | Collaborator B | Same, with a file set overlapping actor-1's (real merge/conflict scenarios) and staggered timing, deliberately creating real push races beyond what F13/C5 construct with `Promise.all` in one process. |
| actor-3 | Operator | Never edits `secrets/` files. Periodically runs `key rotate --confirm-recipients <n>`, `verify --access`, `securegit status`, `key add-recipient` for actor-1/actor-2's identities — the maintenance role, run concurrently with actors 1/2's ordinary traffic over real wall-clock time and a real network, not one `Promise.all` batch. Also re-runs `protect` against the full protected-pattern list every round — a no-op when `.gitattributes` already matches, and the T1 recovery when chaos-5's attribute downgrade has landed since the last round (`reconcileAttributes()` in `chaos/actors/driver.mjs`; see [16](../securegit/16-adversarial-integrity.md)'s T1 section for why this lives in the ops role rather than the product). |

## Chaos agents (fault/attack simulation)

| | Role | Behaviour |
|---|---|---|
| chaos-4 | "virus" | Runs alongside actor-1, sharing its filesystem. At randomized intervals, tampers with actor-1's own `~/.securegit` (session/keyring/identity): truncates, bit-flips, deletes, or overwrites with unrelated-but-plausible bytes — the shape of commodity ransomware or a crashing backup tool indiscriminately touching files it doesn't recognize. Continuous and unattended over the whole run, unlike C4/C7's one-shot Vitest cases. |
| chaos-5 | "attacker" | Its own container, its own clone, ordinary push access to `remote` — matching threat model A6/A7 ([01](../securegit/01-threat-model.md)) exactly: a collaborator with legitimate write access, not code execution on someone else's machine. Periodically pushes commits attempting the [16](../securegit/16-adversarial-integrity.md) catalogue: an attribute downgrade (T1), a relocated blob (T3), a plausible hostile recipient file (T5), a rewound branch (T4). |
| chaos-6 | "infra" | Runs alongside an actor (one instance per actor needing it), scoped to that actor's own resources only: `SIGKILL`s its `securegit` subprocess mid-operation (C1), fills its disk quota (C2), revokes permissions on its `~/.securegit` (C3), drops its network link to `remote` mid-transfer (C6). Impersonal fault injection, not attacker-shaped — sustained and randomized instead of C1-C3/C6's deterministic single-shot sweeps. |

## Orchestration

- `chaos/docker-compose.yml`, kept under a top-level `chaos/` directory
  excluded from the published package (`.npmignore` / `package.json`'s
  `files` list) — mirrors T11's "the published tarball is
  `dist/`+`src/`+licence+README" invariant; this must never ship.
- `remote`: `git daemon --export-all` (or a minimal `sshd`) serving one
  bare repo from a named volume.
- `actor-*`: a shared base image (Node + git + this repo's *locally
  built* `dist/`, installed via `npm pack`/`npm link` rather than a
  published version, so the sandbox always exercises the current working
  tree) running a driver script parameterized by role.
- `chaos-*`: driver scripts under `chaos/agents/`, one per role, each
  parameterized with an interval/intensity.
- **A bounded run.** The whole stack runs for a fixed wall-clock duration
  (`CHAOS_DURATION_SECONDS`, short for a local run, longer for a
  scheduled job), then a `verifier` service runs last: audits a *fresh
  clone of the remote* plus the shared run report — deliberately no
  access to any actor's workspace or key material, the same access a real
  repository auditor would actually have — and exits nonzero only if one
  of the three hard invariants (see Overview) is violated. Everything
  else observed is reported, not forced into pass/fail — an
  already-documented fail-closed/recoverable state is the expected,
  correct outcome of most of what the chaos agents attempt, and telling
  that apart from a genuine bug automatically is exactly what the Open
  Questions below say this script doesn't try to fully solve.
- **Output.** A structured JSON report: what each chaos agent attempted,
  what each actor observed, whether recovery succeeded. Closer to a
  fuzzing campaign's report than a single pass/fail — "found an
  interesting near-miss, still triaging" is a valid and useful outcome
  here, not something to force into red/green.
- **`chaos/viewer/index.html`.** A standalone, no-build replay viewer for
  that report — the run rendered as a match: three "friendly systems"
  weathering three "hostile contacts", a live event log, and the three
  invariants as gauges that resolve at the end. Opens into an
  auto-playing demo (clearly labeled as simulated) when no real run has
  happened yet, built from the same message shapes the real scripts
  produce, so the shape of a match is visible before Docker is ever
  touched. See `chaos/README.md`'s "Watching it happen" section and
  [02](02-viewer.md) for the viewer's own design spec.

## Verifying the invariants

The `verifier` (no key, fresh clone only) can check the first two
invariants directly:

1. **No plaintext leaked** — every `secrets/` blob in every commit that
   ever existed on the branch must be envelope-shaped
   (`looksLikeEnvelope()`), checked across all of history, not just HEAD.
2. **Repository intact** — `git fsck --full --no-dangling` against the
   fresh clone exits clean. Needs no key material; this is Git's own
   object-graph consistency, not securegit's.

The third — **zero data loss** — the verifier cannot check itself,
because proving a blob still decrypts needs a key, and the verifier
deliberately has none. Instead, `operator` (the one role chaos-4/chaos-6
never target — see "Chaos agents" above) runs a
`finalIntegritySelfCheck()` at the end of its own loop, using its own
keyring, which is therefore the one keyring in this whole sandbox
guaranteed to hold every generation ever created, uncorrupted:

- Every commit sha this run itself recorded as *confirmed pushed*
  (a `push` report event with exit code 0) must still be reachable in
  `git log --all` — a lost confirmed write is the specific failure this
  catches, not "a push attempt that never succeeded in the first place".
- Every protected blob reachable in history must decrypt under
  `securegit smudge --strict` (not plain `smudge`, whose F2/F5 passthrough
  behavior would otherwise read as a false "success" for content that was
  never actually decrypted) to content that parses and matches its own
  recorded shape.

The operator records one `final integrity self-check` report event with
both results; the verifier reads it and elevates any finding to a hard
failure — trusting the operator's self-report rather than re-deriving it.
**That trust boundary is real and worth restating:** it holds only as
long as `operator` stays the one role nothing in this sandbox corrupts.
Extending chaos-4/chaos-6 to also target the operator in a future version
would need a different mechanism for this invariant — likely an
independent, out-of-band copy of the keyring the verifier itself could be
trusted with, which is a bigger design decision than this version makes.

## Scope guardrails

Restated from [00](00-test-plan.md)'s own non-goals, made concrete for
this sandbox:

1. **Every chaos agent is confined to its own container's filesystem and
   network namespace**, torn down when the compose stack exits. Nothing
   here writes outside the sandbox's own ephemeral volumes.
2. **chaos-4 ("virus") tampers only with its own target actor's files.**
   It does not execute arbitrary code, escalate privileges, or reach
   outside its shared namespace. This is file-corruption simulation, not
   malware — the same restatement of T2 as [00](00-test-plan.md)'s C7.
3. **chaos-5 ("attacker") only ever acts through ordinary `git push`**
   against `remote`, exactly as a real hostile collaborator with
   legitimate write access would. It has no access to any actor's
   container.
4. **chaos-6 ("infra") only affects its own paired actor's resources** —
   its own process, its own disk quota, its own network link. Scoped
   fault injection, not a denial-of-service tool.
5. **Nothing built here is reusable as an attack tool outside this
   sandbox.** No generic file-encryption payload, no generic
   network-flooding capability, no credential exfiltration — every
   behaviour is narrowly the specific fault or attack shape already
   catalogued in [15](../securegit/15-failure-modes.md) and
   [16](../securegit/16-adversarial-integrity.md), reproduced here for
   realism and sustained/combined load, never generalized.

## Relationship to 00-test-plan.md

Doesn't replace C1-C7's Vitest-based tests — those stay the fast,
deterministic, CI-running proof for each category in isolation, and keep
running in `npm test`. The sandbox is a slower, opt-in, sustained/combined
complement: it can surface interactions between categories that no single
test could ever construct — does `key rotate`'s dirty-tree gate (F13/C1)
still hold when chaos-6 is killing processes *and* chaos-4 is corrupting
files *and* chaos-5 is pushing hostile commits, all at once, for ten
minutes straight? Likely its own `npm run chaos:sandbox` script, not part
of the default CI run, given the Docker dependency and runtime cost.

## Open Questions before implementation starts

- **Sidecar process vs. separate container for chaos-4/chaos-6.** Both
  need to share their target actor's exact filesystem/namespace, which a
  sidecar process inside the actor's own container gets for free; a
  separate container needs an explicit shared volume and loses the
  ability to `kill -9` the actor's own process by PID. Leaning sidecar
  for chaos-4/chaos-6, separate container for chaos-5 (which only ever
  needs the remote, never an actor's local state) — to be confirmed once
  the first actor image is actually being built.
- **Driver script language.** TypeScript (consistent with the rest of
  the package, can import `src/` directly, needed for anything that
  makes decisions — actors, chaos-4, chaos-5) vs. bash (simpler for
  chaos-6's mostly `kill`/`tc`/`chmod`/disk-quota work). Leaning
  TypeScript for the former, bash acceptable for the latter.
- **Run duration and default intensity.** Needs a first implementation to
  calibrate against empirically — not something to guess in the
  abstract, same lesson [00](00-test-plan.md)'s C1 already learned about
  guessing timing numbers ahead of measuring them.
- **How the verifier tells "expected fail-closed state" from "genuine
  bug" programmatically.** Likely a checklist derived directly from
  [00](00-test-plan.md)'s C1-C7 rows and [15](../securegit/15-failure-modes.md)/
  [16](../securegit/16-adversarial-integrity.md)'s tables, but the exact
  machine-checkable form needs designing against a real report, not
  specified here.

## Relationship to Other Specs

- [00](00-test-plan.md) — the categories this sandbox exercises under
  sustained, combined load
- [../securegit/01-threat-model.md](../securegit/01-threat-model.md) —
  the boundary the verifier checks never leaked plaintext
- [../securegit/15-failure-modes.md](../securegit/15-failure-modes.md) —
  the fail-closed shapes chaos-4/chaos-6 are expected to reproduce
- [../securegit/16-adversarial-integrity.md](../securegit/16-adversarial-integrity.md) —
  the attack catalogue chaos-5 automates
