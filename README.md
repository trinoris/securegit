# `@trinoris/securegit`

[![Build CI](https://github.com/trinoris/securegit/actions/workflows/node.js.yml/badge.svg)](https://github.com/trinoris/securegit/actions/workflows/node.js.yml)
[![CodeQL](https://github.com/trinoris/securegit/actions/workflows/codeql.yml/badge.svg)](https://github.com/trinoris/securegit/actions/workflows/codeql.yml)
[![Secret Scan](https://github.com/trinoris/securegit/actions/workflows/gitleaks.yml/badge.svg)](https://github.com/trinoris/securegit/actions/workflows/gitleaks.yml)
[![Release](https://github.com/trinoris/securegit/actions/workflows/release.yml/badge.svg)](https://github.com/trinoris/securegit/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Chaos Match Viewer](https://img.shields.io/badge/chaos%20sandbox-live%20replay-3ecf8e)](https://trinoris.github.io/securegit/)

Client-side Git encryption: a transparent `clean`/`smudge` filter that
encrypts selected files on your own workstation, so the repository — every
commit, every push, every mirror, every backup — is AES-256-GCM ciphertext
everywhere it goes afterward.

> **The boundary is the process, not the network.** Plaintext exists in the
> working tree, on a machine that holds a key. `.git/objects`, the remote,
> the mirror, the backup and the bundle hold ciphertext, and no cloud
> provider ever holds anything that can decrypt it.

```
   worktree                          object database              remote
   ────────                          ───────────────              ──────
   plaintext  ──── clean ─────────▶  ciphertext  ──── push ────▶  ciphertext
   plaintext  ◀─── smudge ────────   ciphertext  ◀─── fetch ───   ciphertext
                   textconv ──────▶  plaintext, for display only
```

Day to day, nothing about the workflow changes:

```sh
git add . && git commit -m "hello" && git push
```

`git add`, `git status`, `git diff`, `git log -p` all behave normally — the
filter is invisible until you go looking for it.

## Why this matters

Leaked credentials in version control are a well-documented, recurring
cause of real breaches — not a hypothetical. A committed `.env` file, a
database connection string, an API key in a config file: the moment it's
pushed, it's in every clone, every fork, every CI runner's cache, and
every backup snapshot that's already run. Rewriting history afterward
rarely reaches all of them, and by then the secret itself has to be
treated as burned regardless.

What client-side encryption actually buys, concretely:

- **A compromised third party's blast radius drops to zero for file
  contents.** Your cloud storage provider, your CI runner, a mirror you
  don't administer, a backup vendor — every one of them ends up holding
  ciphertext only. A breach at any of them is not a breach of your
  source, which matters as much for compliance narratives ("can this
  cloud provider produce our plaintext under compulsion?") as for
  security ones — see
  [specs/securegit/01-threat-model.md](specs/securegit/01-threat-model.md)'s
  "requirement that rules out KMS as a root".
- **Revoking access is a real, forward-acting operation, not a hope.**
  `key rotate` moves the repository onto a generation a departed
  contractor's or employee's key cannot unwrap for anything written
  afterward — see
  [specs/securegit/09-rotation-recovery.md](specs/securegit/09-rotation-recovery.md).
  It does not (and cannot) erase what they already read; nothing can.
  But it stops the leak from continuing, which is the part every other
  "revoke access" story in a plain Git repo can't actually deliver.
- **No new habits for the team to remember.** `git add`, `git commit`,
  `git push`, `git diff`, `git log -p` all behave exactly as before. A
  security control that depends on people remembering an extra step
  under deadline pressure is a control that eventually gets skipped —
  this one doesn't ask for that.
- **Zero runtime dependencies.** A tool that holds encryption keys is an
  unusually attractive supply-chain target. This one has nothing to
  compromise besides itself.

**The adoption cost is `securegit init` and a few minutes; the incident
this prevents is measured in days of response, forced credential
rotation across every system the secret touched, and — depending on
what leaked — mandatory disclosure.** And unlike almost every other
control on this list, it works *before* the first plaintext byte ever
leaves the workstation, not after something has already gone wrong.

None of this is only asserted — [CHAOS.md](CHAOS.md) is a live,
adversarial simulation that measures it against real Git, real attacks,
and three real-world code-review workflows compared side by side, with
results published from an actual run every night.

## Quickstart

```sh
securegit init
securegit protect config/production.json
git add . && git commit -m "hello" && git push
```

On a second machine that already holds a key for this repository:

```sh
git clone …
securegit unlock
```

## Install

Not yet published to a package registry (no tagged release exists yet —
see `.github/workflows/release.yml`). For now, build from source:

```sh
git clone git@github.com:trinoris/securegit.git
cd securegit
npm ci
npm run build
npm link          # puts `securegit` on your PATH, or run
                   # node dist/bin/securegit.js directly
```

Once a `v*` tag is pushed, releases publish to GitHub Packages under the
`@trinoris` scope — install with an `.npmrc` pointing that scope at
`https://npm.pkg.github.com`.

## Why this, and not `git-crypt` / SOPS / `age`

The mechanism — a Git clean/smudge filter — isn't novel. What this bets on
is what sits behind it: no single custodial party can ever be the sole
decryption path, and key lifecycle (losing a machine, adding one, rotating
a compromised generation) works without ever touching already-committed
ciphertext. Zero runtime dependencies, on purpose — a package that holds
encryption keys is an unusually attractive place for a supply-chain
attack. The full comparison and reasoning: [specs/securegit/README.md](
specs/securegit/README.md#why-this-and-not-git-crypt--sops--age).

## Documentation

- **[specs/securegit/](specs/securegit/README.md)** — the full design: threat
  model, envelope format, key hierarchy, every CLI command's contract, and
  the current build status of each piece.
- **[specs/chaotests/](specs/chaotests/00-test-plan.md)** — resilience and
  chaos testing: process kills mid-write, concurrent races, a multi-actor
  Docker sandbox with adversarial agents, and the match-replay viewer that
  renders a run as a game (published nightly — see below).
- **[CHAOS.md](CHAOS.md)** — what the chaos sandbox actually proves, in
  plain terms: the three-workflow comparison, what real runs found, and
  how to watch it live or run it yourself.

## Chaos sandbox

A Docker Compose stack simulates real collaborators, a hostile pusher, a
file-corrupting "virus", and infrastructure faults (kills, disk pressure,
network drops) running concurrently against a shared remote — across
three different git workflows (direct push, a gated shared branch, or a
fully PR-gated `master`) — then audits three hard invariants: no
plaintext ever leaked, the repository's object graph stayed intact, and
zero confirmed-pushed data was lost. **[CHAOS.md](CHAOS.md)** has the full
story, including what real runs actually found.

```sh
npm run chaos:sandbox
```

See [chaos/README.md](chaos/README.md) for prerequisites and exact
commands. A nightly run of all three workflows is published as a GitHub
Pages site (`.github/workflows/node.js.yml`'s `chaos` job) — the latest
comparison is viewable at `https://trinoris.github.io/securegit/`.

## Development

```sh
npm ci
npm run build              # tsc -p tsconfig.build.json
npm test                   # unit tests (vitest)
npm run test:integration   # against a real git binary
npm run typecheck
```

CI runs the build/test/`npm audit` gate on every push and PR
([node.js.yml](.github/workflows/node.js.yml)), CodeQL static analysis and
secret scanning alongside it ([codeql.yml](.github/workflows/codeql.yml),
[gitleaks.yml](.github/workflows/gitleaks.yml)), and the chaos sandbox
nightly.

## Security

See [specs/securegit/01-threat-model.md](specs/securegit/01-threat-model.md)
for exactly what this protects against, and — just as important — what it
explicitly does not.

## License

[MIT](LICENSE)
