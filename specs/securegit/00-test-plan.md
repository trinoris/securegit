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

**Built:** `tests/fixtures/vectors/v1.json`, asserted in `src/vectors.test.ts`.
Each case also carries `keyId` (needed by `seal()`'s options but not part of
this sketch), and the file has one extra top-level `hkdf` block — a fixed
key/path/plaintext with the `deriveTagKey`/`contentTag`/`deriveFileKey`
outputs pinned as hex, closing [05](05-key-hierarchy.md)'s "HKDF labels
match the committed vectors" row independently of the envelope-level cases.

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

**Built:** `v1-basic.bin` and `v1-bindpath.bin` only, asserted in
`src/vectors.test.ts`. The seven tampered/malformed variants above are
deliberately not committed as separate files — `src/envelope.test.ts` covers
that exact ground already, by tampering a freshly-`seal()`ed envelope in
memory per test. Those are tests of the parser rejecting corruption *today*;
a static fixture would be meaningful only if the past mattered for that
question, and for corruption detection it doesn't the way it does for
"must decrypt forever." See [04](04-envelope-format.md)'s status note.

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

`--json` closes out the CLI contract's own remaining gap
([10](10-cli-contract.md)): `status`, `verify` (base/`--access`/`--history`),
and `inspect` all now accept it, each writing the same report object the
human-readable form already builds — `JSON.stringify`'d, to stdout, nothing
to stderr — rather than a separately-defined JSON shape to keep in sync.
`key list`/`list-recipients`, the other two commands the spec names for
`--json`, don't exist yet.

`status` reporting M1–M12 ([14](14-metadata-leakage.md)) is the last item:
`metadataReport()` in `verify.ts`, a static catalogue crossed with local
config rather than a live scan — nine of the twelve observables are
unconditional (inherent to committing to a Git repository at all), and only
`padTo` (M2), `bindPath` (M8), and whether any recipients exist (M11)
actually vary. Wired into `status --json`'s `metadata` field; the
human-readable form gets one pointer line rather than twelve mostly-static
ones repeated on every call.

Everything from the original build order (this file's own Phase 1–3 steps,
plus `verify --history`/`--access`/`--json`, padding, and `status` M1–M12)
is implemented. Work since has moved to closing the backlog of
test-coverage and small-feature rows the specs still list open — see each
spec's own "What this pass actually built" section for detail as they land.
First: the single-recovery-path advisory
([09](09-rotation-recovery.md)/[13](13-verify.md)/[15](15-failure-modes.md))
— `recoveryPathStatus()` in `verify.ts` (a cheap, session-free read: the
local keyring's provider slot for the current generation, plus every
recipient covering it, plus the recovery log), shared by `verify()`'s new
`'recovery'` finding kind and `securegit status`'s own warning line. A solo
repository — the default state of every freshly `init`ed one in this test
suite — has exactly one path and warns by default; existing `verify()`
tests that expected `findings: []` were updated to expect this finding
once it landed, not weakened to hide it.

`key rotate`'s recipient-count confirmation ([16](16-adversarial-integrity.md),
T5) is next: recipient files are read once in `cmdKeyRotate`, right after
the locked check, and the same in-memory list both drives a mandatory
`--confirm-recipients <n>` gate (printing every current recipient's
fingerprint and label; refusing on a missing or mismatched count) and,
once confirmed, is what actually gets rewrapped — closing the window
between "here's who this affects" and "here's who it affected." Every
existing `key rotate` call in `cli.test.ts` needed `--confirm-recipients`
added once this landed, matching the actual recipient count each test sets
up.

`verify --access` naming the commit that added each recipient
([16](16-adversarial-integrity.md), T5) is next: `AccessRecipient` gained
`addedCommit: string | null` in `accessReport()`, resolved via `git log
--diff-filter=A --format=%h -- <path>` — the one field in that report that
spawns `git`, everything else there being a plain filesystem read. The
*oldest* add (the last line of `git log`'s newest-first output), correct
even across a removed-then-re-added recipient; `null` for a file never
committed or a repository with no commits yet, not an error. Surfaced in
both `verify --access`'s human-readable form and `--json`.

`--repo <path>` ([10](10-cli-contract.md)) is next: `runCli` parses and
strips it from `argv` once, before dispatch, reassigning its own `io`
parameter to a derived object with `cwd` resolved (`node:path`'s
`resolve`) and the flag removed, rather than threading an override through
the roughly 30 places `cli.ts` reads `io.cwd` directly. Every existing
command case picks it up for free. Works before or after the command name;
missing its path argument exits 4.

`unprotect <pattern>…` ([02](02-git-integration.md)) is next: `protect`'s
counterpart, removing patterns from `.gitattributes` only.
`.gitignore`'s residue entries stay untouched (harmless once unprotected,
and removing them could unhide files a user still wants ignored for
unrelated reasons), and it's forward-only exactly like key rotation: a
blob already committed as ciphertext stays ciphertext until the file is
actually edited and re-added. A pattern that was never protected, or a
call before `.gitattributes` exists at all, is a silent no-op — the file
is left exactly as it was, not written unconditionally.

Known-answer vectors ([03](03-determinism.md), [04](04-envelope-format.md),
[05](05-key-hierarchy.md)) are next: `src/vectors.test.ts` plus two
committed fixtures. `tests/fixtures/vectors/v1.json` freezes six
`seal()`/`unseal()` cases (empty, one byte, 4095 bytes, a UTF-8 BOM, CRLF
content, `bindPath`) as hex, generated once from the implementation as it
stands today, and pins the `securegit/tag/v1` / `securegit/dek/v1` HKDF
labels directly via a `hkdf` block computed the same way — so a rename of
either label is a test failure here even though it would also,
indirectly, break the envelope vectors. `tests/fixtures/envelopes/`
holds two committed envelopes (`v1-basic.bin`, `v1-bindpath.bin`) that must
keep decrypting under their frozen key forever; the tampered-envelope
fixtures this file's own catalogue below used to list are deliberately not
built as separate files, since `envelope.test.ts` already covers that
ground by tampering a freshly-sealed envelope in memory — a test about the
parser rejecting corruption today, not about compatibility with the past.
`src/crypto.test.ts` gained a dedicated LF/CRLF round-trip check (the
primitives operate on raw bytes, no text-mode normalization of their own),
and `src/bin.integration.test.ts` gained a two-separate-`node`-processes
determinism check for `clean`, alongside the existing in-process one in
`src/filter.test.ts`.

The provider conformance suite ([06](06-key-provider-port.md)) is next:
`src/provider.conformance.test.ts` runs `describe.each` over a
`{ name, makeProvider }` registration list — one row today,
`passphrase-file` — so the same contract battery (`describe()`'s shape,
`available()` resolving promptly without a prompt, `init()` producing
flat JSON-serialisable state, `wrap`/`unwrap` round-tripping and returning
`Secret`-marked material, failing under a wrong `repoId` or `generation`)
runs once per provider rather than being specific to
`PassphraseFileProvider`. A second real provider is a new row, not a new
test file. "Never receives a path or file content" is proved
behaviourally: a recording wrapper intercepts every argument actually
passed to `init`/`wrap`/`unwrap` across a full cycle and asserts none of
it carries a key matching `path`, `content` or `plaintext`, recursing
through nested objects but treating a `Buffer` as opaque key material
rather than a container to inspect. `src/provider.test.ts` is unchanged —
it keeps everything specific to `passphrase-file` itself.

`-v`/`--verbose` ([10](10-cli-contract.md)) is next: real per-file tracing
for `clean`, `smudge` and `merge`, not a no-op. `FilterContext` and
`MergeOptions` each gained an optional `trace?: (message: string) => void`
called at most once per invocation — the path, the generation, and which
branch was taken (encrypted, decrypted, or a passthrough), never plaintext
or key material, same redaction discipline as the existing `warn`
callback. Parsed like `--strict` (a flag collected from before the `--`
separator by each command's own arg parser) rather than stripped globally
from `argv` the way `--repo` is — a path after `--` is legally allowed to
begin with `-`, and a global scan for `-v` would risk matching one.
`cli.ts` wires `trace: io.stderr` only when the flag is present; the
filter functions themselves never know "verbose" as a concept, only
whether a callback exists, so every existing non-verbose call site is
unchanged.

`--quiet` ([10](10-cli-contract.md)) closes out the CLI-wide flags. It
required splitting `CliIO`'s single `stderr` callback into two: `stderr`
stays error-only plus every report-type command's actual report, `info` is
new and carries just the one-shot success confirmations (`init`, `unlock`,
`protect`/`unprotect`, `identity init`, the `key` subcommands that
succeed, `lock`) — suppressed under `--quiet`, unlike `stderr`. The reason
for the split rather than a blanket "suppress everything non-error": spec
10's own stdout/stderr rule already puts `status`, `identity show`,
`verify`, and `inspect`'s human-readable reports on stderr, since Git never
treats them as data — but a report command's report is not a diagnostic
aside, it is the entire reason to run the command, the same content
`--json` puts on stdout instead for a script. Suppressing it under
`--quiet` would leave a report command silently printing nothing on
success. So those reports (and `reencrypt`'s per-file summary, and `key
export-recovery`'s one-time recovery code — the only place that code is
ever displayed) stay on `stderr`, exempt from `--quiet`, the same way they
were already exempt from being stdout output. `runCli` checks
`argv.includes('--quiet')` once before dispatch and swaps `io.info` for a
no-op; unlike `--repo`, the flag is not stripped from `argv` — it takes no
value, and no command parses `args` positionally in a way an unconsumed
`--quiet` token could disrupt.

A first batch of "prove existing behavior against real git" rows (specs
[01](01-threat-model.md), [02](02-git-integration.md),
[07](07-unlock-session.md), [12](12-diff-merge.md),
[15](15-failure-modes.md)) is closed out — no product code changed, only
`src/git.integration.test.ts` gaining five new tests plus one spec
correction. Two extend the existing `'a clone of the repository'` describe
block, reusing its bare remote: a forced `repack -a -d` on the bare repo
scans every resulting `.pack` file's raw bytes for the plaintext, and a
`git bundle create --all` is scanned the same way, then cloned into a
fresh, keyless home to prove it checks out as ciphertext, not just that its
raw bytes look clean. Two more reuse the shared top-level fixture read-only
(`git log -p` shows plaintext via `textconv`, never the envelope's magic
marker; `git count-objects` is unchanged across a `log -p` that invokes
`textconv` once per commit). The fifth is one combined test for F1 — a
locked `git add` rejects, leaves the index pointing at the old blob, and
leaves `git count-objects` unchanged — which turns out to prove three
separate spec rows at once (02's "filter exiting non-zero aborts `git
add`", 15's F1, and 15's "no failure path writes plaintext to the object
database"), since `clean`'s only failure mode is `LockedError`: there is no
other failure path to separately exercise. Spec 07's "`git add` of a
protected file fails when locked" turned out to already be proven by the
existing F16 test (touching then re-adding a locked, unmodified file
touches this exact assertion along the way) — corrected to ✅ rather than
duplicating it. `core.autocrlf=true`/inherited-`* text` round-trips, the
removed-recipient pre/post-rotation pair, `reencrypt` across a real clone,
and the remaining small unit-file gaps are still open, left for further
cycles of the same batch.

637 unit tests, all green; 31 integration tests, all green. The package is
TypeScript (`src/` → `dist/`, NodeNext, `strict` plus
`noUncheckedIndexedAccess` and `exactOptionalPropertyTypes`), matching
`@trinoris/decision-core`. Unit
tests sit beside the source as `*.test.ts`; integration tests are
`*.integration.test.ts` and run from `vitest.integration.config.ts`.

| | Implemented | Designed only |
|---|---|---|
| Cryptography | derivations, envelope, padding, known-answer vectors | — |
| Git integration | filters, attributes, filter-process, real-`git` round trip | — |
| Keys | keyring, passphrase provider, session, identity keypair/encoding, recipient wrap/unwrap, rotation, recovery export/import | — |
| Tooling | CLI (`init`/`init --pad-to`/`install`/`protect`/`unprotect`/`unlock`/`lock`/`status`/`status --json`/`identity`/`key add-recipient`/`key remove-recipient`/`key rotate`/`reencrypt`/`key export-recovery`/`key import-recovery`/`verify`/`verify --access`/`verify --history`/`verify --json`/`clean`/`smudge`/`textconv`/`merge`/`encrypt`/`decrypt`/`inspect`/`inspect --json`/`filter-process`) | — |

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
