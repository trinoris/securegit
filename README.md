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

## Chaos sandbox

A Docker Compose stack simulates real collaborators, a hostile pusher, a
file-corrupting "virus", and infrastructure faults (kills, disk pressure,
network drops) running concurrently against a shared remote, then audits
three hard invariants: no plaintext ever leaked, the repository's object
graph stayed intact, and zero confirmed-pushed data was lost.

```sh
npm run chaos:sandbox
```

See [chaos/README.md](chaos/README.md). A nightly run is published as a
GitHub Pages site (`.github/workflows/node.js.yml`'s `chaos` job) — once
Pages is enabled for this repo, the latest run's replay is viewable at
`https://trinoris.github.io/securegit/`.

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
