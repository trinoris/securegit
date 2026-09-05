# Chaos Sandbox

Implements `specs/chaotests/01-sandbox.md`. A Docker Compose stack: a bare
remote repo, three legitimate actors (`collaborator-a`, `collaborator-b`,
`operator`), three chaos agents (`chaos-4-virus`, `chaos-5-attacker`,
`chaos-6-infra`), and a `verifier` that audits the result.

**Update: since verified end-to-end via GitHub Actions' `chaos` job**,
running real `docker compose` (not WSL, where it still isn't available in
the environment this file was originally written in) — see
[chaotests/01-sandbox.md](../specs/chaotests/01-sandbox.md)'s "Later
correction" note. Local `docker compose` runs from WSL remain untested;
see "Troubleshooting" below if that's where you're running this.

## Running it

```sh
# from the repository root
npm run chaos:sandbox
```

which is:

```sh
docker compose -f chaos/docker-compose.yml up --build -d
docker compose -f chaos/docker-compose.yml wait verifier
docker compose -f chaos/docker-compose.yml logs verifier
docker compose -f chaos/docker-compose.yml down -v
```

**Why not a plain `docker compose up --abort-on-container-exit`:** `remote`
(`git daemon`) never exits on its own, and `--abort-on-container-exit`
tears down the whole stack the moment the *first* container exits —
which would be whichever actor or chaos agent finishes its run soonest,
killing the verifier before it's had its own, deliberately-later, chance
to run. Detached mode plus `docker compose wait verifier` waits
specifically for the one container whose exit actually means the sandbox
is done.

`docker compose wait` needs a reasonably recent Compose (v2.20+, 2023 or
later). If it's not available, substitute polling
`docker compose ps verifier` for an `Exited` status instead.

## Watching it happen: the match viewer

`chaos/viewer/index.html` is a self-contained (no build step, no server)
replay viewer — open it directly in a browser. It renders a run as a
game: the three collaborators/operator as "friendly systems", the three
chaos agents as "hostile contacts", a live commit-graph-style event log,
and the three hard invariants as gauges that resolve once the match ends.

- **Load a real run**: "Load report" → pick `report.jsonl` out of the
  `report-data` volume after a run (see "What to look at afterward"
  above for how to get it out of the volume). Or load
  `verifier-result.json` directly for the final audit only, no replay.
- **No real run yet**: it opens straight into an auto-playing **demo
  match** — clearly labeled as simulated data, built from the exact same
  message shapes the real scripts produce — so you can see what a match
  looks like before ever touching Docker. "↻ New demo match" generates a
  fresh one.
- Nothing is uploaded anywhere; a loaded file is read locally by the
  browser and never leaves it.

### Published automatically: GitHub Pages

`.github/workflows/node.js.yml`'s `chaos` job runs the sandbox nightly
(03:00 UTC) and on manual dispatch (Actions tab → "Build CI" → "Run
workflow"), extracts `report.jsonl` and `verifier-result.json`, and
deploys them alongside a copy of the viewer as a GitHub Pages site — the
viewer's `tryLoadPublishedRun()` fetches those same-directory files at
boot and shows the actual latest run automatically, no manual "Load
report" click needed (see [specs/chaotests/02-viewer.md](
../specs/chaotests/02-viewer.md)'s "Auto-loading a published run"). It
never runs on push/PR and a violation never blocks a merge — see the job's
own comment in the workflow file for why.

**One-time setup required, not done by this workflow itself:** GitHub
Pages has to be enabled once in this repo's Settings → Pages → "Build and
deployment" → Source: **GitHub Actions**. Until that's set, the
`deploy-pages` job fails with a clear error; the `chaos` job's own
artifacts (uploaded via `actions/upload-artifact`, 90-day retention) are
still available from the Actions run regardless.

## What "success" means

Three hard invariants, checked regardless of what chaos happened — the
verifier's exit code is 0 only if all three hold:

1. **No plaintext leaked** — every protected file, every commit, all of
   history.
2. **Codebase integrity guaranteed** — `git fsck` on the final repository
   comes back clean.
3. **Zero data loss** — every commit confirmed pushed during the run is
   still reachable, and every protected blob in history still decrypts to
   its original content. Checked by `operator` itself at the end of its
   run (`finalIntegritySelfCheck()` in `chaos/actors/driver.mjs`) — it's
   the one role chaos-4/chaos-6 never target, so its keyring is the one
   guaranteed complete and uncorrupted; the verifier trusts that
   self-report rather than re-deriving it, since it has no key of its
   own. See `specs/chaotests/01-sandbox.md`'s "Verifying the invariants"
   for the full reasoning, including that trust boundary.

Everything else observed during the run — a securegit command exiting
nonzero, an attack landing, a role's error count — is reported, not
scored: distinguishing "expected fail-closed response to chaos" from "an
actual bug" needs judgement this script doesn't try to fully automate.

## What to look at afterward

- `docker compose -f chaos/docker-compose.yml logs verifier` — the
  human-readable summary: each of the three invariants, HELD or VIOLATED,
  ending in `PASS`/`FAIL`.
- The full structured result: it's inside the `report-data` volume at
  `/report/verifier-result.json`. Easiest way to read it after `down`:
  don't pass `-v` to `down` (drop volumes), then
  `docker compose -f chaos/docker-compose.yml run --rm verifier cat /report/verifier-result.json`
  before finally tearing the volumes down.
- The full run report (every action/observation/error from every role,
  one JSON object per line): `/report/report.jsonl` in the same volume.

## Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `CHAOS_DURATION_SECONDS` | 300 | How long actors/chaos agents run their loops. |
| `VERIFIER_STARTUP_GRACE_SECONDS` | 30 | Extra time the verifier waits before the run duration even starts counting, to cover collaborator-a's bootstrap. |
| `VERIFIER_SETTLE_SECONDS` | 60 | Extra time after `CHAOS_DURATION_SECONDS` before the verifier audits. Covers both in-flight pushes/rounds landing *and* the operator's own `finalIntegritySelfCheck()`, which decrypts every protected blob in history before it finishes — its own real cost, scaling with how much history the run accumulated. Raise this for a much longer `CHAOS_DURATION_SECONDS`. |
| `DISK_FILL_MB` | 64 | Size of chaos-6's transient disk-pressure file (C2). |

Set them by exporting before `npm run chaos:sandbox`, or editing
`chaos/docker-compose.yml` directly.

## Design choices worth knowing about

- **Shared-secret model, not recipient/identity.** All three actors get
  the *same* `SECUREGIT_PASSPHRASE` and collaborator-a's `keyring.json` is
  distributed to the other two via a shared volume (`keyring-shared`) —
  simulating how a real team would exchange it out-of-band (05/06's
  documented model: the keyring is deliberately never committed). The
  recipient/identity flow (`key add-recipient`, per-person keypairs) is a
  natural follow-up, not built here.
- **Each collaborator edits only its own file** (`secrets/collaborator-a.json`,
  `secrets/collaborator-b.json`). Real push races (non-fast-forward,
  retry-after-pull) are fully exercised; content-level merge *conflicts*
  are deliberately out of scope for this first version so the driver never
  needs conflict-resolution logic of its own.
- **`operator` has no paired chaos agent.** chaos-4 targets
  collaborator-a, chaos-6 targets collaborator-b — the machine doing key
  rotation stays relatively stable in this v1, a scope choice, not an
  oversight.
- **After a rotation, the operator republishes its keyring** to the same
  shared volume, and collaborators re-copy it in every round before
  `unlock` — simulating the out-of-band re-sync a rotation genuinely
  requires in this model (05-key-hierarchy.md: rotation never
  auto-propagates to another machine's local keyring).
- **The verifier only gets a fresh clone of `remote` plus the shared
  report** — no access to any actor's HOME or the shared keyring — the
  same access a real repository auditor would actually have.

## Troubleshooting (likely first-pass issues)

Ranked by how likely each seems to actually bite, given this was never run:

1. **`git checkout -B main` / `git checkout main` in an empty or
   HEAD-mismatched repo** (`chaos/actors/driver.mjs`,
   `chaos/agents/attacker.mjs`). `remote/entrypoint.mjs` pins the bare
   repo's HEAD to `main` via `git init --bare -b main` specifically to
   avoid this, but if the installed git version predates `-b`
   (needs ≥2.28) this needs a different fix (`git symbolic-ref HEAD
   refs/heads/main` after a plain `git init --bare` instead).
2. **`iptables`/`NET_ADMIN` inside `chaos-6-infra`.** Depending on the
   Docker Desktop/host kernel's iptables backend (legacy vs nftables),
   `apk add iptables` inside `node:20-alpine` may need
   `iptables-legacy` explicitly, or the commands may need adjusting for
   `nft`. If C6 (network drop) never actually applies, this is the first
   place to look — the script logs `iptables insert failed: …` when it
   can tell.
3. **`pid: "service:collaborator-b"` / `network_mode: "service:collaborator-b"`
   ordering.** Some Compose versions are stricter than others about
   requiring the *named* service's container to already exist. If
   `chaos-6-infra` fails to start, try starting `collaborator-b` first
   (`docker compose up -d collaborator-b`) before bringing up the rest.
4. **`git daemon --enable=receive-pack`.** If pushes are rejected by
   `remote`, double check this flag actually took — some git builds want
   it set via `git config daemon.receivepack true` *and* the CLI flag
   rather than either alone (the entrypoint sets both, but worth
   confirming first if pushes fail).
5. **Alpine's `git` version and `git commit-tree` reading the message
   from stdin.** Should be standard behaviour on any git ≥ ancient, but
   `chaos/lib/git-plumbing.mjs`'s `buildAndPushCommit()` is the one place
   a lot of plumbing commands are chained — if chaos-5 never manages to
   push an attack commit, add temporary logging of each intermediate
   step's `stderr` there first.
6. **The zero-data-loss check (`dataLossCheck.ran: false`, or `COULD NOT
   CHECK` in the verifier's summary).** `finalIntegritySelfCheck()`'s core
   logic (`git log --all` + `smudge --strict` per blob) was confirmed
   correct against a real local build outside Docker — see
   `specs/chaotests/01-sandbox.md`'s Status note — so if this specific
   check comes back empty, the more likely culprits are Docker-specific:
   `operator`'s container exiting before the self-check finishes (raise
   `VERIFIER_SETTLE_SECONDS`, or check `docker compose logs operator` for
   whether it even reached "running final integrity self-check"), or the
   `securegit` wrapper script not resolving inside that container for
   some reason `--help` inside it would immediately reveal.

## Relationship to `npm test`

Not part of `npm test` / CI. Needs Docker, takes minutes not seconds, and
its report is meant to be read, not just asserted on — see
`specs/chaotests/00-test-plan.md`'s "Relationship to 01-sandbox.md".
