# 00. Test Plan

What will be tested, where the tests live, what they run against, and in what
order to build it. Test cases themselves are defined per feature in the
individual spec files; this is the inventory, the fixture catalogue, and the
build order.

**Test Fixtures:** `tests/fixtures/`

**Legend:**
- 🔲 = Not started
- ✅ = Implemented and passing

---

## The two kinds of test

Almost every package can be tested with unit tests and a couple of integration
tests. This one cannot, because the component under test is *Git's behaviour
when a filter is attached to it*, and no amount of unit testing tells you
whether `git status` comes back clean.

| | Unit | Integration |
|---|---|---|
| Runs | `npm test` | `npm run test:integration` |
| Needs | nothing | a real `git` binary |
| Speed | milliseconds | seconds |
| Answers | is the cryptography right | does Git agree |
| In CI | every commit | every commit |

Integration tests build a throwaway repository in a temp directory, run real
`git` commands against it, and inspect `.git/objects` directly. They are
excluded from the default `npm test` because they are slower, not because they
are optional — CI runs both, and the [03](03-determinism.md) tests that matter
most are integration tests.

## Fixtures

### Known-answer vectors — `vectors/`

The most important fixture in the package. A JSON file of
`{ rmk, path, bindPath, plaintext, expectedEnvelope }` tuples, all hex.

```json
{
  "algorithm": 1,
  "cases": [
    { "name": "empty",        "rmk": "00…", "path": "a.txt", "bindPath": false,
      "plaintext": "",        "envelope": "005345…" },
    { "name": "one byte",     "…": "…" },
    { "name": "4095 bytes",   "…": "…" },
    { "name": "utf8 bom",     "…": "…" },
    { "name": "crlf content", "…": "…" },
    { "name": "bindPath",     "bindPath": true, "…": "…" }
  ]
}
```

A change that alters any of these bytes is a **format break**, and the test
failure should say so in those words rather than reporting a mismatch. These
vectors are what make [03](03-determinism.md)'s cross-machine, cross-version
promise checkable rather than aspirational. They are generated once, by hand,
reviewed, and never regenerated.

### Content — `blobs/`

| Fixture | What it is for |
|---|---|
| `empty` | zero bytes; must encrypt, not pass through |
| `tiny` | one byte |
| `boundary-4095`, `boundary-4096`, `boundary-4097` | padding and packet-size edges |
| `packet-65516`, `packet-65517` | pkt-line split boundary ([11](11-filter-process.md)) |
| `binary` | uniformly random bytes, including NUL and `0xFF` runs |
| `crlf` | CRLF line endings, for the `-text` tests |
| `utf8-bom` | a byte-order mark, which some tools rewrite |
| `magic-prefixed` | plaintext that begins with `\0SECUREGIT\0` ([04](04-envelope-format.md)) |
| `large` | generated, not committed; `maxFileBytes` tests |

### Envelopes — `envelopes/`

| Fixture | What it encodes |
|---|---|
| `v1-basic.bin` | canonical generation-1 envelope; must decrypt forever |
| `v1-bindpath.bin` | same with the flag set |
| `v1-truncated.bin` | header claims more than is present |
| `v1-flipped.bin` | one ciphertext byte flipped |
| `v1-header-flipped.bin` | one header byte flipped — AAD test |
| `v1-unknown-format.bin` | `format = 0x02` |
| `v1-unknown-algorithm.bin` | `algorithm = 0x7f` |
| `v1-reserved-flag.bin` | a reserved flag bit set |
| `v1-unknown-keyid.bin` | a generation not in any test keyring |

### Identities — `identities/`

Two fixed X25519 keypairs, `alice` and `bob`, with their public encodings and
fingerprints pinned. Fixed rather than generated so [08](08-multi-recipient.md)'s
wrapping tests have known answers and so a failure is reproducible.

### Repositories — built, not committed

Committing a `.git` directory inside a `.git` directory is a fight with Git that
nobody wins. These are builder functions in `src/testing/repo.ts` that
construct a repository in a temp directory and return its path.

| Builder | The situation it encodes | Used by |
|---|---|---|
| `repo-protected` | initialised, installed, unlocked, three protected files | 01, 02, 03, 07, 09, 11, 12, 15 |
| `repo-keyless` | the same repository, cloned with no key | 07, 15 |
| `legacy-plaintext` | secrets committed before adoption, then protected | 13, 16 |
| `attributes` | variants: no exclusion, inherited `* text`, removed line | 02, 13, 16 |
| `two-recipients` | alice and bob, one rotation, one removal | 08, 09, 13 |
| `conflict` | two branches editing one protected file | 12 |

## Test file layout

| File | Covers | Specs |
|---|---|---|
| `src/crypto.test.ts` | derivations, determinism, AEAD | 03, 05 |
| `src/envelope.test.ts` | format, parsing, tamper, padding | 04, 14 |
| `src/vectors.test.ts` | known-answer vectors | 03, 04, 05 |
| `src/filter.test.ts` | clean, smudge, textconv, passthrough | 02, 04, 07 |
| `src/pktline.test.ts` | pkt-line codec | 11 |
| `src/process.test.ts` | long-running filter protocol | 11 |
| `src/keyring.test.ts` | generations, rotation, atomic writes | 05, 09 |
| `src/provider.test.ts` | passphrase provider | 06 |
| `src/provider.conformance.test.ts` | every provider, one contract | 06 |
| `src/session.test.ts` | unlock, TTL, permissions | 07 |
| `src/identity.test.ts` | X25519 identities, encoding | 08 |
| `src/recipients.test.ts` | recipient wrapping | 08 |
| `src/recovery.test.ts` | export, import, code encoding | 09 |
| `src/install.test.ts` | git config, `.gitattributes`, `.gitignore` | 02, 10, 16 |
| `src/verify.test.ts` | every check, every leak class | 13, 16 |
| `src/merge.test.ts` | three-way merge driver | 12 |
| `src/failure.test.ts` | F1–F20 messages and exit codes | 15 |
| `src/cli.test.ts` | commands, exit codes, output discipline | 10 |
| `src/config.test.ts` | repo config, paths, `repoId` | 05, 14 |
| `src/package.test.ts` | zero dependencies, import hygiene | 16 |
| `src/git.integration.test.ts` | real `git`, real repositories | all |

## Build order

Each phase ends somewhere the tool is honestly usable.

### Phase 1 — one person, one machine

Nothing here can be revisited cheaply, because phase 1 defines the format.

1. `crypto.ts` + the known-answer vectors — [03](03-determinism.md), [05](05-key-hierarchy.md)
2. `envelope.ts` — [04](04-envelope-format.md)
3. `clean` / `smudge` / `textconv` — [02](02-git-integration.md)
4. `keyring.ts` + the passphrase provider — [06](06-key-provider-port.md)
5. `session.ts` — [07](07-unlock-session.md)
6. `install` / `protect` — [02](02-git-integration.md)
7. the CLI — [10](10-cli-contract.md)

**Ends at:** `init`, `protect`, `unlock`, commit, push, clone, unlock, check out
— with `git status` clean throughout. That last clause is the acceptance
criterion; if it does not hold, nothing later matters.

### Phase 2 — safe to rely on

8. `verify` — [13](13-verify.md). The highest-value component in the package.
9. the merge driver — [12](12-diff-merge.md)
10. failure messages and exit codes — [15](15-failure-modes.md)
11. residue `.gitignore` entries and the untracked-residue check — [16](16-adversarial-integrity.md)

**Ends at:** a repository where a silent downgrade is caught by a `pre-push`
hook and a conflicted merge does not leave a plaintext `.orig`.

### Phase 3 — more than one person

12. identities and recipients — [08](08-multi-recipient.md)
13. rotation, re-encryption and recovery — [09](09-rotation-recovery.md)
14. `filter-process` — [11](11-filter-process.md)
15. padding — [14](14-metadata-leakage.md)

**Ends at:** the full CLI in [10](10-cli-contract.md).

### Deliberately not phased

Hardware providers (`tpm2`, `piv`, `os-keychain`) sit behind
[06](06-key-provider-port.md)'s port and can be added at any point without
touching anything else. That is the whole reason the port exists, and adding one
early would prove nothing the conformance suite does not already assert.

## Current status

**Phase 1 is complete and proven end to end.** `src/crypto.ts`,
`src/envelope.ts`, `src/filter.ts`, `src/provider.ts`, `src/keyring.ts`,
`src/install.ts` (`install`/`protect`, writing real `.git/config` and
`.gitattributes`/`.gitignore` against a real `git` binary), `src/session.ts`,
`src/config.ts`, and `src/cli.ts` — every command in [10](10-cli-contract.md)
except key rotation/recipients/recovery, wired through an injected `CliIO`
and unit-tested without a subprocess — are all implemented, plus
`src/bin/securegit.ts`, the thin real-process adapter. 314 unit tests, all
green.

The phase 1 acceptance criterion — `init`, `protect`, `unlock`, commit, push,
clone, unlock, check out, with `git status` clean throughout — is now proven
by `src/git.integration.test.ts` against the real, compiled `dist/bin/securegit.js`
binary as a real Git filter (not injected `CliIO`): 9 tests, all green,
covering a single real repository (clean status after commit, ciphertext in
`.git/objects`, plaintext in the worktree, deterministic re-add, `git diff`
via `textconv`, `stash`/`stash pop`, branch switching) and a real clone
(ciphertext before `install` has ever run there; `install` + `unlock` +
the documented recovery restoring real plaintext — see
[07](07-unlock-session.md) and [15](15-failure-modes.md) for why that
recovery is `git rm --cached -r -q . && git checkout HEAD -- .`, not
`git checkout --force .`). 1 further subprocess smoke test
(`src/bin.integration.test.ts`) covers the CLI directly.

**Phase 2 has started.** `src/verify.ts` — the always-on configuration and
index checks in [13](13-verify.md) (L1–L3, L7–L10, plus the leak/advice
content scan) — and `src/merge.ts` — the three-way merge driver in
[12](12-diff-merge.md), real `git merge-file` under the hood, fail-closed on
any undecrypted side, temp files cleaned up on every exit path — are both
implemented and green, and both are now wired into `src/cli.ts` as
`securegit verify` and `securegit merge -- <base> <ours> <theirs>
<markerSize> <path>` ([10](10-cli-contract.md)). Still open: `verify
--history`/`--access` (`--access` needs spec 08's recipient list, which does
not exist yet) and the real-`git`-through-`git merge`/`git diff` proof of the
merge driver (needs `src/git.integration.test.ts`).

Failure-message discipline ([15](15-failure-modes.md)) is now largely
verified rather than designed: `src/failure.test.ts` checks that every
message this package controls (locked, missing generation, authentication
failure, CRLF corruption) names what/where/action; `unlockKeyring` gained an
`expectedRepoId` check (F19 — a keyring written for a different repository is
now rejected with both ids named, before ever attempting to unwrap anything);
`src/keyring.test.ts` proves a write failure leaves the previous keyring file
untouched (F11); `src/git.integration.test.ts` proves F16 (a keyless commit
of an unmodified protected file is a silent no-op) is Git's own stat-cache
short-circuit on `add`, not `clean`'s passthrough rule as originally
(incorrectly) documented — `clean` has no passthrough case at all when
locked, proven directly in `src/filter.test.ts`. Still open: F1/F13 exit
codes and index-state assertions, `status`/`verify`'s single-recipient
warnings (blocked on specs 08/09), and the residue/untracked-residue check
([16](16-adversarial-integrity.md)). 361 unit tests, all green; 11
integration tests, all green. Everything in phase 3 is designed only. The
package is TypeScript (`src/` → `dist/`,
NodeNext, `strict` plus `noUncheckedIndexedAccess` and
`exactOptionalPropertyTypes`), matching `@trinoris/decision-core`. Unit tests
sit beside the source as `*.test.ts`; integration tests are
`*.integration.test.ts` and run from `vitest.integration.config.ts`.

| | Implemented | Designed only |
|---|---|---|
| Cryptography | derivations, envelope | known-answer vectors |
| Git integration | filters, attributes, real-`git` round trip | process protocol |
| Keys | keyring, passphrase provider, session | recipients, rotation, recovery |
| Tooling | CLI (`init`/`install`/`protect`/`unlock`/`lock`/`status`/`verify`/`clean`/`smudge`/`textconv`/`merge`/`encrypt`/`decrypt`/`inspect`) | `verify --history`/`--access`, `filter-process` |

The three things that had to be got right before anything else, because they
cannot be changed later without breaking every repository already in use, are
now all proven rather than merely designed:

1. **The derivations and the envelope format** ([03](03-determinism.md),
   [04](04-envelope-format.md), [05](05-key-hierarchy.md)). Once a byte is
   committed to a real repository it is permanent.
2. **`git status` staying clean.** The whole cryptographic design exists to
   satisfy this one behavioural property, checked against real `git` in
   `src/git.integration.test.ts`.
3. **The clean/smudge asymmetry** ([07](07-unlock-session.md)). `clean` fails
   closed; `smudge` fails open. Getting this backwards produces either a tool
   that writes plaintext or one that cannot be cloned.
