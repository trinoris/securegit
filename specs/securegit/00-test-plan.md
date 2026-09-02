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

**Phase 2's four build-order steps are all done.** `src/verify.ts` — the
always-on configuration and index checks in [13](13-verify.md) (L1–L3,
L7–L10, the leak/advice content scan, and the T12 residue scan) — and
`src/merge.ts` — the three-way merge driver in [12](12-diff-merge.md), real
`git merge-file` under the hood, fail-closed on any undecrypted side, temp
files cleaned up on every exit path — are both implemented, green, and wired
into `src/cli.ts` as `securegit verify` and `securegit merge -- <base> <ours>
<theirs> <markerSize> <path>` ([10](10-cli-contract.md)).

Failure-message discipline ([15](15-failure-modes.md)) is largely verified
rather than designed: `src/failure.test.ts` checks that every message this
package controls (locked, missing generation, authentication failure, CRLF
corruption) names what/where/action; `unlockKeyring` gained an
`expectedRepoId` check (F19 — a keyring written for a different repository is
rejected with both ids named, before ever attempting to unwrap anything);
`src/keyring.test.ts` proves a write failure leaves the previous keyring file
untouched (F11); `src/git.integration.test.ts` proves F16 (a keyless commit
of an unmodified protected file is a silent no-op) is Git's own stat-cache
short-circuit on `add`, not `clean`'s passthrough rule as originally
(incorrectly) documented — `clean` has no passthrough case at all when
locked, proven directly in `src/filter.test.ts`.

The residue/untracked-residue check ([16](16-adversarial-integrity.md), T12)
is built into `verify.ts` as a third `Finding` kind, `'residue'`, checked
against the real filesystem rather than `git status` (the point is catching
what `.gitignore` hides from view); `RESIDUE_SUFFIXES` is exported from
`install.ts` so `protect`'s `.gitignore` entries and `verify`'s scan share one
list. `src/package.test.ts` is new this pass too, proving T11 (zero runtime
dependencies, no `src/` import outside `node:` builtins) and the
timing-safe-comparison requirement statically, and T1/T7/T8/T10/T12/T13's
rows in [16](16-adversarial-integrity.md) are now cross-checked against
modules built in earlier phases.

The real-`git`-through-`git merge` proof landed too: `install` now writes
`merge.securegit.name`/`.driver`, `protect` writes `merge=securegit` into
every attribute line, `merge.securegit.driver` joined `IDENTITY_KEYS` (so
T10's foreign-config refusal covers it), and
`src/git.integration.test.ts` drives an actual `git merge` — a
non-overlapping merge resolving cleanly with ciphertext committed and
plaintext in the worktree, and a real conflict leaving plaintext markers in
the worktree and exiting nonzero.

Still open from Phase 2: F1/F13's exit-code and index-state assertions, and
`status`'s single-recipient recovery warnings — neither was on the
four-step build order, so Phase 2 as scoped is complete. `verify
--history`/`--access` are no longer open either: both are built now, in the
Phase 3 pass below — `--access` once specs 08/09 existed to read from,
`--history` once the rest of the module (and its real-`git` test setup) was
already in place to build the commit walk on top of.

**Phase 3 has started.** `src/identity.ts` — the X25519 identity keypair,
checksummed public-key encoding, fingerprint, and the identity file that
wraps a private key via the same `KeyProvider` port a repository's master
key uses — and `src/recipients.ts` — the repository-key-sharing
wrap/unwrap construction exactly as specified (fresh ephemeral keypair,
zero nonce, `repoId ‖ generation ‖ fingerprint` AAD), `wrapAllGenerations`
(the `add-recipient` primitive), and `unlockFromRecipientFile` (the
`unlock`-from-a-recipient-file-alone primitive) — are both implemented and
green ([08](08-multi-recipient.md)). The join flow is wired into
`src/cli.ts` too: `identity init`/`show`, `key add-recipient`/
`remove-recipient`, and a second path inside `unlock` that bootstraps a
session straight from a recipient file when no local keyring exists — proven
end to end twice: `src/cli.test.ts` (two `home`s against one shared repo
directory, standing in for two machines) and `src/git.integration.test.ts`
(a real bare remote, `git clone`, `git push`, `git pull`). The real-`git`
version found a genuine bug the CLI-level test couldn't: **F21** —
`git pull` runs `clean` as a pre-merge safety check even on untouched
tracked paths, so a locked repository with the filter already attached
cannot `git pull` at all. Fixed by reordering the join flow (a brand-new
machine's first pull happens before `install`, not after) rather than by
changing any production code; documented in [02](02-git-integration.md),
[08](08-multi-recipient.md) and [15](15-failure-modes.md).

`key rotate` and `reencrypt` ([09](09-rotation-recovery.md)) are wired into
`src/cli.ts` too, on top of `rotateKeyring` (`src/keyring.ts`), which
predated this pass. Building `key rotate`'s dirty-tree refusal caught
another real ordering bug: `git status`'s comparison also has to run `clean`
(the same class of behaviour as F21), so checking it before checking
"locked" turns a clean "you're locked" message into a confusing subprocess
failure — fixed by checking locked first. `reencrypt` stages re-encrypted
blobs via `hash-object`/`update-index` plumbing, never touching the worktree
file itself, and is a genuine no-op (byte-identical re-encryption, not a
separate "already current" check) for anything already on the current
generation, since `clean` is deterministic.

`src/recovery.ts` — the export/import recovery file, the recovery code's
format/parse/checksum, and the committed recovery log — is implemented and
green too ([09](09-rotation-recovery.md)). It reuses `identity.ts`'s
Crockford codec rather than duplicating it; the code itself is 32 random
bytes plus a 4-byte checksum, Crockford-encoded to 58 characters, not the
52 the spec's own illustrative example showed (256 bits of pure entropy
alone already takes exactly 52, leaving no room for a checksum inside that
count without weakening the code). `key export-recovery`/`import-recovery`
are now wired into `src/cli.ts`, on top of a new
`keyringFromRecoveredGenerations` in `src/keyring.ts` — the primitive
neither `createKeyring` (always fresh generation 1) nor `rotateKeyring`
(always exactly one new generation) could provide: building a full keyring
from an arbitrary, already-known set of generations for a brand-new
provider. Export needs no separate secret (it reads the already-unlocked
session, the same way `key add-recipient` does); import needs two — the
recovery code and a fresh local passphrase — resolved from two independent
env vars or, on the stdin fallback, two lines in that order.

`filter-process` ([11](11-filter-process.md)) is built too: `src/pktline.ts`
(pkt-line framing) and `src/process.ts` (`FilterProcessServer`, plus the
`process.stdout` write guard), wired into `bin/securegit.ts` via its own
entrypoint (`runFilterProcess` — it needs a real stream, not `CliIO`'s
whole-buffer single-shot contract, so it bypasses `readStdin()`/`runCli()`
entirely). Session expiry is re-checked by re-invoking the injected `keys()`
before every command rather than caching anything from handshake time.
Proven against a real `git` binary — `install --process` checked out
through, byte-for-byte identical output to the `clean`/`smudge` form. Two
real bugs surfaced building this: the locked-`clean` path wrote its error
status without ever calling `warn` (found against a real `git add`, not from
the spec — Git's own "clean filter failed" carried none of the actual
diagnostic until fixed), and `onData` chunks needed explicit chaining, since
handing each one to the server independently could let two arrive-close
chunks process concurrently against its shared parse state. Both fixed and
regression-tested. Padding ([14](14-metadata-leakage.md)) remains designed
only — that spec's own status is "inherent" (most metadata leakage cannot be
fixed within Git's object model at all), not a build-order item in the same
sense as the others.

`verify --access` ([13](13-verify.md)) is built too — `accessReport()`, on
top of the same no-session-no-key discipline `verify()` itself already
follows. It reads recipient files, the keyring's own `provider` field per
generation (never a fresh unwrap), and two committed logs: the recovery log
(extended with `generations: number[]` per export, since the spec's own
example reports what an export covers) and a new
`removed-recipients.json` that `key remove-recipient` now writes to —
deleting a recipient's file leaves no other record that the fingerprint ever
had access at all, so the log is written from the file's own content, read
just before it's deleted.

`verify --history` ([13](13-verify.md)) closes out Phase 2's `verify` work:
`historyReport()` walks every commit reachable from any ref (`git rev-list
--all`), resolving `filter=securegit` protection as it stood *at each
commit* via a temporary index (`GIT_INDEX_FILE` + `read-tree` +
`check-attr --cached -z --stdin`, batched) rather than `check-attr --source
<tree-ish>`, which needs a newer Git than this tool can assume. Each blob's
content is read at most once via a `Map` keyed by SHA — content-addressed
storage means the same SHA is always the same bytes — and findings
aggregate per path (first/last commit, a count, which branches can still
reach it), plus a check for `refs/notes/textconv/securegit`, the residue
Git's own `cachetextconv` optimisation leaves if it was ever enabled. The
spec's "read only the first 11 bytes" optimisation is not built (full
content is read); documented as a real, low-priority simplification.

`init --pad-to` ([14](14-metadata-leakage.md)) is the last build-order-scale
item: M2's mitigation, and the one part of metadata leakage this design can
actually close (the rest of spec 14 is genuinely inherent — Git needs the
repository's shape to be a Git repository). `envelope.ts` gained a
length-prefixed pad/unpad scheme behind a new flags bit (`FLAG_PADDED`),
self-describing so `unseal` never needs to know what `padTo` a blob was
sealed under. `config.ts`'s `RepoConfig.padTo` is set only at `init`,
immutable after — the same constraint `bindPath` already has (no "update a
field in place" primitive exists for either); `reencrypt` is the existing
tool for applying a hand-edited `padTo` retroactively, same as it already is
for a key rotation. Every `seal` call site — `clean`, `reencrypt`, `merge`,
`filter-process`, `encrypt` — threads `padTo` through; `unseal` needs no
such threading. Proven against a real commit in `git.integration.test.ts`:
`init --pad-to 256`, a 3-byte file, a committed blob well over 256 bytes,
an exact 3-byte checkout.

554 unit tests, all green; 25 integration tests, all green. The package is
TypeScript (`src/` → `dist/`, NodeNext, `strict` plus
`noUncheckedIndexedAccess` and `exactOptionalPropertyTypes`), matching
`@trinoris/decision-core`. Unit tests sit beside the source as `*.test.ts`;
integration tests are `*.integration.test.ts` and run from
`vitest.integration.config.ts`.

| | Implemented | Designed only |
|---|---|---|
| Cryptography | derivations, envelope, padding | known-answer vectors |
| Git integration | filters, attributes, filter-process, real-`git` round trip | — |
| Keys | keyring, passphrase provider, session, identity keypair/encoding, recipient wrap/unwrap, rotation, recovery export/import | — |
| Tooling | CLI (`init`/`init --pad-to`/`install`/`protect`/`unlock`/`lock`/`status`/`identity`/`key add-recipient`/`key remove-recipient`/`key rotate`/`reencrypt`/`key export-recovery`/`key import-recovery`/`verify`/`verify --access`/`verify --history`/`clean`/`smudge`/`textconv`/`merge`/`encrypt`/`decrypt`/`inspect`/`filter-process`) | `verify --json` |

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
