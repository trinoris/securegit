# Client-Side Git Encryption

Design for `@trinoris/securegit` — a Git clean/smudge filter that encrypts
selected files on the workstation, so the repository is ciphertext everywhere it
goes afterwards.

> **The boundary is the process, not the network.** Plaintext exists in the
> working tree on a machine that holds a key. `.git/objects`, the remote, the
> mirror, the backup and the bundle hold ciphertext, and no cloud provider ever
> holds anything that can decrypt it.

The lifecycle, which is the whole architecture:

```
   worktree                          object database              remote
   ────────                          ───────────────              ──────
   plaintext  ──── clean ─────────▶  ciphertext  ──── push ────▶  ciphertext
   plaintext  ◀─── smudge ────────   ciphertext  ◀─── fetch ───   ciphertext
                   textconv ──────▶  plaintext, for display only
```

Three properties make it work rather than merely encrypt:

1. `clean` is a **pure function of its input**, so Git's change detection still
   works ([03](03-determinism.md)).
2. `filter.securegit.required = true`, so a missing key **fails the commit**
   instead of storing plaintext ([02](02-git-integration.md)).
3. The master key is wrapped by something the cloud provider does not hold — and
   a provider that could be compelled is marked as such, in the tool's own
   output ([06](06-key-provider-port.md)).

## Why this, and not `git-crypt` / SOPS / `age`

The mechanism — a Git clean/smudge filter — is not novel. `git-crypt` has done
transparent file encryption for years, and wiring SOPS through the same
filter hooks is a well-known pattern. **The differentiation this project
bets on is not the mechanism; it's what sits behind it.**

| | `git-crypt` | SOPS | `age` (+ plugins) | `securegit` |
|---|---|---|---|---|
| Transparent (`add`/`commit`/`push`, workflow unchanged) | yes | no — `sops` runs explicitly, outside Git | no — a primitive, not a Git integration | yes |
| Multi-recipient without duplicating the secret | GPG only | yes — its strength | yes — its strength | yes, via the `KeyProvider` port ([06](06-key-provider-port.md)) |
| Hardware-backed keys | no | via whichever backend it's pointed at | yes — a growing plugin ecosystem | designed for, not yet shipped — same port |
| States which custodians could be compelled | no | no | no | yes — `securegit status`'s own output |
| Runtime dependencies | none | several | none | none ([16](16-adversarial-integrity.md), T11) |

Two things make "another `git-crypt`" or "a SOPS wrapper" the wrong frame:

1. **No single custodial party can ever be the sole decryption path.** That
   was the design mandate from the first line of this project
   ([01](01-threat-model.md)): "KMS may never be the sole root of the key
   hierarchy... a repository whose only unwrap path is a KMS key has
   re-created the property it set out to remove." `securegit status` prints
   which of a repository's providers are custodial — not as a feature, as a
   warning. A team that wraps every generation with one KMS key has rebuilt
   the exact single point of trust this tool exists to avoid.
2. **Key lifecycle is the hard part, and it has to work without touching
   already-committed ciphertext.** Losing a hardware key revokes its
   wrapper; a new machine adds one; neither operation re-encrypts anything.
   The per-generation wrapping in [05](05-key-hierarchy.md) is built for
   exactly this — it's the reason a random per-file DEK (the "obvious"
   design) was rejected in favour of deriving one, and the reason
   [09](09-rotation-recovery.md) exists at all.

**What this deliberately rules out:** depending on `age` (or a similar
library) at the crypto layer. `age`'s own file format is non-deterministic —
a fresh ephemeral key per encryption — which would break the one property
[03](03-determinism.md) is built around: `clean` must be a pure function of
its input, or `git status` never goes clean after `git add`. And a runtime
dependency at all conflicts with T11
([16](16-adversarial-integrity.md)) — a package that holds encryption keys is
an unusually attractive place for a supply-chain attack, which is why this
one has none. Hardware-backed identities stay reachable the way
[06](06-key-provider-port.md) already intends: a future provider that shells
out to an already-installed binary (`age-plugin-yubikey`, `ykman`, whatever a
given backend needs) — the same relationship this tool already has with
`git` itself — not an npm dependency.

The bar for the first thirty seconds, once this ships:

```
securegit init
securegit protect config/production.json
git add . && git commit -m "hello" && git push
```

and, on a second machine that already holds a key for this repository:

```
git clone …
securegit unlock
```

Everything the repository holds is ciphertext in between. Nothing about the
day-to-day workflow changes — which is the whole pitch, and the reason the
mechanism being unoriginal doesn't matter.

## Documents

### Foundations (01–03)
| # | Document | Description |
|---|----------|-------------|
| 01 | [Threat Model & Trust Boundary](01-threat-model.md) | Who the adversaries are, and the four things this does not do |
| 02 | [Git Integration Model](02-git-integration.md) | Filters not hooks, and the attributes that must be set |
| 03 | [Determinism](03-determinism.md) | **The load-bearing constraint** — why a random nonce breaks Git |

### Cryptography (04–06)
| # | Document | Description |
|---|----------|-------------|
| 04 | [Envelope Format](04-envelope-format.md) | The bytes, the AAD, and the passthrough rules |
| 05 | [Key Hierarchy](05-key-hierarchy.md) | Master key, derived per-file keys, generations |
| 06 | [Key Provider Port](06-key-provider-port.md) | Passphrase, TPM, PIV, KMS behind one interface |

### Key lifecycle (07–09)
| # | Document | Description |
|---|----------|-------------|
| 07 | [Unlock & Session](07-unlock-session.md) | **The asymmetry** — `clean` fails closed, `smudge` fails open |
| 08 | [Multi-Recipient Sharing](08-multi-recipient.md) | X25519 in the repository, no key server |
| 09 | [Rotation & Recovery](09-rotation-recovery.md) | Generations, re-encryption, and the offline way back in |

### Surface (10–13)
| # | Document | Description |
|---|----------|-------------|
| 10 | [CLI Contract](10-cli-contract.md) | Commands, exit codes, and the stdout rule |
| 11 | [Long-Running Filter Process](11-filter-process.md) | pkt-line protocol, one process per checkout |
| 12 | [Diff, Merge & What Stays Broken](12-diff-merge.md) | textconv, a three-way merge driver, an honest list |
| 13 | [Verify & Leak Detection](13-verify.md) | **The highest-value component** — finding the silent failures |

### Residue & Integrity (14–16)
| # | Document | Description |
|---|----------|-------------|
| 14 | [Metadata Leakage](14-metadata-leakage.md) | Everything still visible, and why paths are not encrypted |
| 15 | [Failure Modes](15-failure-modes.md) | F1–F20, what Git does, and what to tell the user |
| 16 | [Adversarial Integrity](16-adversarial-integrity.md) | **Threat catalogue** — the configuration and workflow attacks |

Fixtures, test layout and build order: [00-test-plan.md](00-test-plan.md).

## Current status

**Phase 1 is complete and proven end to end.** `src/crypto.ts` (the derivations in
[05](05-key-hierarchy.md), the determinism property in
[03](03-determinism.md)), `src/envelope.ts` (the wire format in
[04](04-envelope-format.md)) and `src/filter.ts` (`clean`/`smudge`/`textconv`
and the asymmetry in [07](07-unlock-session.md)) and `src/provider.ts` (`passphrase-file`, [06](06-key-provider-port.md)) are
implemented and green, plus `src/keyring.ts` — generations, atomic disk
persistence, and `unlockKeyring`, which is the real `KeySource` the filter now
plugs into instead of a test stub, and `src/install.ts` — `install`/`protect`,
writing real `.git/config` filter entries and `.gitattributes`/`.gitignore`
against a real `git` binary — plus `src/session.ts`, `src/config.ts`, and `src/cli.ts` — the full command
surface in [10](10-cli-contract.md) except key rotation, recipients and
recovery, backed by the real `dist/bin/securegit.js` binary
(`src/bin/securegit.ts`). 314 unit tests, all green.

The phase 1 acceptance criterion is now proven against real `git`, not just
injected `CliIO`: `src/git.integration.test.ts` drives the actual compiled
binary as a real filter through `init`/`install`/`protect`/`unprotect`/`unlock`, a
commit, a push to a bare remote, and a clone — `git status` clean throughout,
ciphertext in `.git/objects`, plaintext in the worktree, `git diff` showing a
real plaintext hunk via `textconv`, `stash`/`stash pop` and branch switches
leaving a clean tree, and a keyless clone's ciphertext repaired once
`install` + `unlock` run there (see [07](07-unlock-session.md) — the working
recovery turned out not to be `git checkout --force .`, which Git's
stat-cache silently no-ops on an already-checked-out path). 9 tests, all
green, plus one further subprocess smoke test
(`src/bin.integration.test.ts`) proving the CLI wiring itself.

**Phase 2:** `src/verify.ts` ([13](13-verify.md)) implements the
always-on configuration and index checks — missing filter config, `required`
turned off, a removed attribute, a conflicting `text`/`ident` attribute, key
material inside the worktree, a custodial-only provider set — plus the
leak/advice content scan (19 module tests). `src/merge.ts`
([12](12-diff-merge.md)) implements the three-way merge driver: real
`git merge-file` over the three decrypted plaintexts, fails closed (unlike
`smudge`) rather than guessing when a side can't be decrypted, cleans up its
temp directory on every exit path (10 module tests). Both are now wired into
`src/cli.ts` as `securegit verify` and `securegit merge`, with CLI-level
tests proving the wiring (7 more tests).

Failure-message discipline ([15](15-failure-modes.md)) went from designed to
mostly verified: `src/failure.test.ts` checks that every message this
package controls names what happened, where, and what to do; `unlockKeyring`
now rejects a keyring written for a different repository, naming both ids,
before ever attempting to unwrap anything (F19); a simulated write failure
is proven to leave the previous keyring file untouched (F11). Along the way,
a real bug in this very document surfaced: F16 ("a keyless clone can commit
an unmodified protected file") was attributed to `clean`'s passthrough rule —
but `clean` has no such case; it always fails closed when locked, proven in
`src/filter.test.ts`. What actually makes F16 true is Git's own stat-cache
short-circuit skipping `add` entirely for a path whose worktree content
already matches the index — the same mechanism, from the opposite side, as
why the F2/F4/F8 recovery isn't `checkout --force`.

The residue/untracked-residue check ([16](16-adversarial-integrity.md), T12)
is the fourth and last item on Phase 2's build order, and it's done: `verify`
now reports a third finding kind, `residue`, for an untracked `.orig`/`.bak`/
vim-swap-shaped file sitting beside a protected path — checked against the
real filesystem, since the whole point is catching what `.gitignore` would
otherwise hide from view. `src/package.test.ts` is new too, statically
proving T11 (zero runtime dependencies, no `src/` import outside `node:`
builtins) and that every non-AEAD comparison in the codebase goes through
`equalCt`.

**Phase 2 is done, including the real-`git` proof of the merge driver:**
`install` writes `merge.securegit.name`/`.driver`, `protect` writes
`merge=securegit` into every attribute line, and
`src/git.integration.test.ts` drives an actual `git merge` through that
routing — a non-overlapping merge resolves cleanly (ciphertext committed,
plaintext in the worktree) and a real conflict leaves plaintext markers in
the worktree and exits nonzero, exactly as [12](12-diff-merge.md) describes.
`merge.securegit.driver` joined the T10 foreign-config check too, so a
repository that already has one configured refuses `install` the same way
`clean`/`smudge`/`textconv` already did.

374 unit tests total, all green; 13 integration tests, all green.

**Phase 3 has started:** `src/identity.ts` ([08](08-multi-recipient.md))
implements the X25519 identity keypair, the checksummed `SGPUB1…`
public-key encoding, the fingerprint, and the identity file — wrapping a
private key via the same `KeyProvider` port that already protects a
repository's master key, rather than a parallel wrapping mechanism.
`src/recipients.ts` implements the repository-key wrap/unwrap construction
exactly as specified (fresh ephemeral keypair, zero nonce, `repoId ‖
generation ‖ fingerprint` AAD), `wrapAllGenerations` (the `add-recipient`
primitive) and `unlockFromRecipientFile` (the recipient-file bootstrap
primitive). Both are wired into `src/cli.ts`: `identity init`/`show`, `key
add-recipient`/`remove-recipient`, and a second path inside `unlock` that
bootstraps a session straight from a recipient file when no local keyring
exists — no persisted local keyring is written that way yet, since
`keyring.ts` has no primitive for wrapping several already-known generations
for a brand-new provider (only fresh-generation-1 creation and
single-new-generation rotation). An end-to-end `cli.test.ts` test proves the
whole join flow: a second identity is created, added as a recipient, unlocks
with zero local keyring, and decrypts what the first identity encrypted.

The same flow is now proven against a real `git clone`/`push`/`pull` too,
and building that proof caught a real bug the CLI-level test never could:
**`git pull` runs `clean` as a pre-merge safety check even on tracked paths
the incoming change never touches**, so a locked repository with the filter
already attached cannot `git pull` at all — including the very pull that
would deliver a brand-new recipient the file they need in order to unlock.
The fix is an ordering constraint in the join flow (a new machine's first
pull happens before `install`, not after), not a code change — the same
shape as why a keyless clone that never runs `install` still works.
Documented as F21 in [15](15-failure-modes.md), with the general mechanism
in [02](02-git-integration.md).

`key rotate` and `reencrypt` ([09](09-rotation-recovery.md)) are wired in
too, on top of `rotateKeyring` (`src/keyring.ts`), which already existed.
Building `key rotate`'s dirty-tree refusal turned up a sibling of F21:
`git status`'s own comparison has to run `clean` too, so checking status
before checking "locked" produces a confusing subprocess failure instead of
a clean "you're locked" message — fixed the same way, by ordering (locked
checked first). `reencrypt` stages re-encrypted blobs via plumbing, never
touching the worktree file, and needs no separate "already current" check —
`clean` is deterministic, so a file already on the current generation
re-encrypts to byte-identical ciphertext and the diff naturally sees no
change.

`src/recovery.ts` ([09](09-rotation-recovery.md)) rounds out Phase 3's key
lifecycle: the export/import recovery file, the recovery code's own
format/parse/checksum, and the committed recovery log that records that an
export happened without ever recording the code or the file. It reuses
`identity.ts`'s Crockford codec instead of a second copy of the same base32
variant, and the code itself is 58 Crockford characters (32 random bytes
plus a 4-byte checksum) — the spec's own illustrative example showed 52,
which is exactly what 256 bits of entropy alone requires with no room left
for a checksum; adding the checksum as extra characters keeps the code at
its full promised strength rather than shipping one slightly weaker to fit
a specific count. `key export-recovery`/`import-recovery` are now wired into
`src/cli.ts` too, on top of a new `keyringFromRecoveredGenerations`
(`src/keyring.ts`) — the primitive `unlock`-via-recipient-file was missing
back in [08](08-multi-recipient.md), needed here to turn a recovered set of
generations into a full local keyring. Export needs no separate secret (it
reads the already-unlocked session); import needs two — the recovery code
and a fresh local passphrase — the one command in this codebase that does.

The long-running filter process ([11](11-filter-process.md)) is built too:
`src/pktline.ts` (pkt-line framing — `PktLineReader` exposes both a
whole-list read for headers/capabilities and a one-packet-at-a-time read for
content, so an oversized blob can be rejected while draining instead of
buffered whole first) and `src/process.ts` (`FilterProcessServer`, a small
explicit state machine, plus the `process.stdout` write guard). Session
expiry is re-checked by re-invoking the injected `keys()` function before
every command rather than caching anything from handshake time — cheap
enough that it costs nothing next to the Node-startup savings this exists
for, and it's the only way a concurrent `lock` gets noticed mid-checkout.
Proven against a real `git` binary, `install --process` checked out through,
byte for byte identical to the `clean`/`smudge` form. Two real bugs surfaced
building this, both fixed and regression-tested: the locked-`clean` path
originally wrote its error status without ever calling `warn`, so Git's own
"clean filter failed" carried none of the actual diagnostic (found by
running a real `git add` against a locked process filter, not from reading
the spec); and `runFilterProcess` originally handed each stdin chunk to the
server independently, which could let two chunks process concurrently
against the server's shared parse state — fixed by chaining chunks onto one
promise instead.

`verify --access` ([13](13-verify.md)) is built too — `accessReport()` reads
recipient files, the keyring's own per-generation `provider` field (no
unwrap), and two committed, append-only logs: the recovery log (now
recording `generations: number[]` per export, not just the event) and a new
`.securegit/removed-recipients.json` that `key remove-recipient` writes to
before deleting a recipient's file, since the deletion itself leaves no
other trace that the fingerprint ever had access.

`verify --history` is built too — `historyReport()` walks every commit
reachable from any ref (`git rev-list --all`, not just the checked-out
branch), resolving `filter=securegit` protection *as it stood at each
commit* via a temporary index (`GIT_INDEX_FILE` + `read-tree` +
`check-attr --cached`, batched over every path in one call) rather than
`check-attr --source <tree-ish>`, which needs Git 2.40 — newer than this
tool can assume a real clone has. Each blob is content-read at most once via
a `Map` keyed by its SHA, regardless of how many unchanged commits reference
it. Findings aggregate per path (first/last commit, a count, which branches
can still reach it) rather than one row per offending commit, and it also
reports on `refs/notes/textconv/securegit` — residue from Git's own
`cachetextconv` optimisation, which caches *decrypted* content once enabled.
Reading only the first 11 bytes of each blob (the spec's stated
optimisation) is not built — full content is read instead, a real but
low-priority simplification, since leaked files are overwhelmingly small.

`init --pad-to` ([14](14-metadata-leakage.md)) is built too — M2's
mitigation, the one part of metadata leakage this design can actually
close. `envelope.ts` gained a length-prefixed pad/unpad scheme behind a new
flags bit (`FLAG_PADDED`), self-describing so `unseal` never needs to know
what `padTo` a blob was sealed under; `config.ts`'s `RepoConfig.padTo` is
set only at `init`, immutable after — the same constraint `bindPath`
already has, for the same reason (no "update a field in place" primitive
exists for either). Every place that calls `seal` — `clean`, `reencrypt`,
`merge`, `filter-process`, `encrypt` — now threads it through; `unseal`/
`smudge`/`decrypt` need no such threading, since the padded state travels
with the envelope itself. Proven against a real commit: `init --pad-to 256`,
a 3-byte file, a committed blob well over 256 bytes, and an exact
3-byte checkout.

`--json` is built too, for every command that currently produces a report —
`status`, `verify` (all three forms), and `inspect`. Each just
`JSON.stringify`s the same report object the human-readable rendering reads
from, to stdout, nothing to stderr — no separate schema to define or keep
in sync. `key list`/`list-recipients`, the other two commands spec 10 names
for `--json`, don't exist yet, so there's nothing for it to do there.

`status` reporting M1–M12 ([14](14-metadata-leakage.md)) is built too —
`metadataReport()` in `verify.ts` is a static catalogue crossed with local
config, not a live scan: nine of the twelve observables are unconditional
(inherent to committing to a Git repository at all), and only M2 (`padTo`),
M8 (`bindPath`), and M11 (whether any recipients exist) actually vary.
Wired into `status --json`'s `metadata` field; the human-readable form gets
one pointer line rather than twelve mostly-static ones repeated on every
call.

The full build order is done; work since has been closing out the backlog
of test-coverage and small-feature rows left across the specs. First:
the single-recovery-path advisory (specs [09](09-rotation-recovery.md),
[13](13-verify.md), [15](15-failure-modes.md)) — `recoveryPathStatus()` in
`verify.ts`, a cheap, session-free read (the local keyring's provider slot
for the current generation, plus every recipient covering it, plus the
recovery log) shared by both `verify()`'s new `'recovery'` `Finding` kind
and `securegit status`'s own warning line. Fewer than two independent paths
and no recovery export on record now surfaces in both places — advice-tier,
never affecting the exit code, but real: a solo repository (the default
state of every freshly `init`ed one) has exactly one path and warns by
default, which is the intended behavior, not a false positive to suppress.

Next: `key rotate`'s recipient-count confirmation
([16](16-adversarial-integrity.md), T5). Recipient files are now read once
in `cmdKeyRotate`, right after the locked check — the same in-memory list
both drives a mandatory `--confirm-recipients <n>` gate (printing every
current recipient's fingerprint and label, refusing on a missing or
mismatched count) and, once confirmed, is what actually gets rewrapped, so
there's no window for the set to change between "here's who this affects"
and "here's who it affected." Named for the count specifically, not a bare
`--yes`, so it catches a genuine mismatch — a recipient added or removed
since the operator last checked — rather than just acknowledging a warning.

`verify --access` naming the commit that added each recipient
([16](16-adversarial-integrity.md), T5) is next — `AccessRecipient` gained
`addedCommit: string | null`, resolved via `git log --diff-filter=A
--format=%h -- <path>` against the recipient file's own repo-relative path.
The one field in `accessReport()` that spawns `git`; everything else there
is a plain filesystem read. The *oldest* add (the last line of `git log`'s
newest-first output), correct even across a removed-then-re-added
recipient sharing the same fingerprint and filename; `null`, not an error,
for a file that was never committed (the ordinary state right after `key
add-recipient`) or a repository with no commits yet. Surfaced in both the
human-readable form (`commit <sha>` / `commit (uncommitted)`) and `--json`.

`--repo <path>` ([10](10-cli-contract.md)) is next — the global flag that
lets any command operate on a repository other than the current directory.
`io.cwd` is read directly in roughly 30 places across `cli.ts`; rather than
thread an override through each of them, `runCli` parses and strips
`--repo` from `argv` once, before dispatch, and reassigns its own `io`
parameter to a derived object with `cwd` resolved (`node:path`'s
`resolve`, so a relative path works against the real `cwd`) and the flag
removed. Every existing command case picks it up for free, since none of
them changes — the whole implementation is those few lines at the top of
`runCli`. Works with the flag before or after the command name; missing
its path argument exits 4.

`unprotect <pattern>…` ([02](02-git-integration.md)) is next — `protect`'s
counterpart, removing patterns from `.gitattributes` only.
`.gitignore`'s residue entries stay untouched (harmless once unprotected,
and removing them could unhide files a user still wants ignored for
unrelated reasons), and it's forward-only exactly like key rotation: a
blob already committed as ciphertext stays ciphertext until the file is
actually edited and re-added. A pattern that was never protected, or a
call before `.gitattributes` exists at all, is a silent no-op — the file
is left exactly as it was, not written unconditionally.

Known-answer vectors ([03](03-determinism.md), [04](04-envelope-format.md),
[05](05-key-hierarchy.md)) are next — `src/vectors.test.ts` plus committed
fixtures. `tests/fixtures/vectors/v1.json` freezes six `seal()`/`unseal()`
cases as hex (empty, one byte, 4095 bytes, a UTF-8 BOM, CRLF content,
`bindPath`), generated once from the implementation as it stands today, and
pins the `securegit/tag/v1`/`securegit/dek/v1` HKDF labels directly via an
`hkdf` block. `tests/fixtures/envelopes/v1-basic.bin` and `v1-bindpath.bin`
are two committed envelopes that must keep decrypting under their frozen
key forever — the tampered-envelope fixtures 00-test-plan.md's own
catalogue lists were deliberately not built as separate files, since
`envelope.test.ts` already covers that ground by tampering a freshly-sealed
envelope in memory, a test about the parser today rather than compatibility
with the past. `src/crypto.test.ts` gained an LF/CRLF round-trip check, and
`src/bin.integration.test.ts` gained a two-separate-processes determinism
check for `clean`.

The provider conformance suite ([06](06-key-provider-port.md)) is next —
`src/provider.conformance.test.ts` runs the same contract battery
(`describe()`'s shape, `available()` resolving promptly, `wrap`/`unwrap`
round-tripping and returning `Secret`-marked material, failing under a
wrong `repoId` or `generation`, never receiving a path or file content —
proved behaviourally via a recording wrapper, not just by the TypeScript
types) via `describe.each` over a `{ name, makeProvider }` list. One row
today, `passphrase-file`; a second real provider is a new row, not a new
test file. `src/provider.test.ts` stays specific to `passphrase-file`
itself.

`-v`/`--verbose` ([10](10-cli-contract.md)) is next — real per-file tracing
for `clean`, `smudge` and `merge`. `FilterContext`/`MergeOptions` each
gained an optional `trace?: (message: string) => void`, called at most
once per invocation with the path, the generation, and which branch was
taken, never plaintext or key material. Parsed like `--strict` — a flag
collected from before the `--` separator by each command's own arg parser
— rather than stripped globally from `argv` like `--repo`, since a path
after `--` may legally begin with `-`.

`--quiet` ([10](10-cli-contract.md)) closes out the CLI-wide flags —
splitting `CliIO`'s single `stderr` callback into `stderr` (errors, plus
every report-type command's actual report — status/`identity show`/
`verify`/`inspect`, `reencrypt`'s per-file summary, and `key
export-recovery`'s one-time recovery code, none of them suppressible) and a
new `info` (one-shot success confirmations only, suppressed under
`--quiet`). The split matters because spec 10 already routes a report
command's human-readable output to stderr since Git never treats it as
data — a naive "suppress all non-error stderr" would silence that report
entirely, when it's the actual point of running the command, not a
diagnostic aside. `runCli` checks `argv.includes('--quiet')` once and swaps
`io.info` for a no-op; unlike `--repo` it isn't stripped from `argv`, since
it takes no value and nothing parses `args` positionally.

A first batch of "prove existing behavior against real git" rows (specs
[01](01-threat-model.md), [02](02-git-integration.md),
[07](07-unlock-session.md), [12](12-diff-merge.md),
[15](15-failure-modes.md)) is closed out — no product code changed, five
new tests in `src/git.integration.test.ts` plus one spec correction (spec
07's "`git add` fails when locked" was already proven by the existing F16
test). A forced `repack` on a real pushed bare remote and a real `git
bundle` are each scanned raw for plaintext bytes, and the bundle is also
cloned into a fresh keyless home to prove it checks out as ciphertext.
`git log -p` is proven to show plaintext via `textconv`, never the
envelope's magic marker, and `git count-objects` stays unchanged across it.
One combined F1 test (a locked `git add` rejects, the index is unchanged,
`count-objects` is unchanged) turns out to prove three separate spec rows
at once, since `clean`'s only failure mode is `LockedError`. Remaining rows
in the same batch — `core.autocrlf`/inherited-attribute round-trips,
removed-recipient pre/post-rotation reads, `reencrypt` across a real clone,
and a few small unit-file gaps — are left for further cycles.

637 unit tests total, all green; 31 integration tests, all green. TypeScript,
`src/` → `dist/`, unit tests beside the source, matching
`@trinoris/decision-core`.

| | Implemented | Designed only |
|---|---|---|
| Cryptography | derivations, envelope, padding, known-answer vectors | — |
| Git integration | clean/smudge/textconv, attributes, filter-process, real-`git` round trip | — |
| Keys | keyring, passphrase provider, session, identity keypair/encoding, recipient wrap/unwrap, rotation, recovery export/import | — |
| Tooling | CLI (`init`/`init --pad-to`/`install`/`protect`/`unprotect`/`unlock`/`lock`/`status`/`status --json`/`identity`/`key add-recipient`/`key remove-recipient`/`key rotate`/`reencrypt`/`key export-recovery`/`key import-recovery`/`verify`/`verify --access`/`verify --history`/`verify --json`/`clean`/`smudge`/`textconv`/`merge`/`encrypt`/`decrypt`/`inspect`/`inspect --json`/`filter-process`) | — |

Ten things worth knowing before reading any spec here. The first three are the
load-bearing ones; the last two are about scope.

1. **A random nonce breaks Git, and this is not a small problem.**
   `clean` runs on `git add`, `git diff`, `git stash` and every branch switch.
   If it returns different bytes for the same input, every protected file is
   permanently modified, no commit is ever clean, and the user cannot get back
   to a clean tree — so nothing that depends on a clean tree works.
   [03](03-determinism.md) solves it with a keyed convergent nonce, and pays for
   it in a documented leak. Build and test this first.

2. **The clean/smudge asymmetry is deliberate and easy to get backwards.**
   `clean` without a key **fails**, always, with no exception for a file that
   is already a valid envelope — it cannot verify a passthrough is even safe
   without the key. `smudge` without a key **passes the ciphertext through**,
   because the alternative is a repository nobody without a key can clone.
   The recovery once a key is available is *not* `git checkout --force .` —
   Git's stat-cache treats an already-checked-out path that matches the index
   as up to date and never reruns `smudge` on it, `--force` or not, confirmed
   against a real clone. It is `git rm --cached -r -q . && git checkout HEAD
   -- .`. The same stat-cache behaviour also explains why a locked, keyless
   clone can silently `commit` an unmodified protected file: Git never calls
   `clean` at all for a path whose content hasn't changed, so "locked" never
   gets a chance to block it. `clean` also runs somewhere non-obvious in the
   *other* direction: `git pull`, even a plain fast-forward, runs it as a
   pre-merge safety check on tracked paths the incoming change never
   touches — so a locked repository with the filter attached cannot `pull`
   at all (F21), which is why a brand-new recipient's very first pull has to
   happen before `install`, not after. [02](02-git-integration.md),
   [07](07-unlock-session.md), [08](08-multi-recipient.md),
   [15](15-failure-modes.md).

3. **`verify` is what makes the rest trustworthy.** Every interesting failure of
   this design is silent: an attribute removed in a merge, a directory renamed
   out from under a pattern, a fresh clone that never ran `install`. Nothing
   errors; the file just goes to the remote in plaintext. [13](13-verify.md) is
   the detector, and it belongs in `pre-push` and in CI.

4. **`-text` on every protected path is a correctness requirement.** Git's
   check-in order is filter → `ident` → `text`, so CRLF conversion operates on
   the *ciphertext*. Under `core.autocrlf` or an inherited `* text`, the blob is
   mangled and fails to decrypt later, on another machine. [02](02-git-integration.md).

5. **`diff.securegit.cachetextconv` must be `false`.** Set to `true`, Git caches
   textconv output in a notes ref — which means writing the decrypted plaintext
   into `.git/objects` as an ordinary blob, undoing the design as a performance
   optimisation. [12](12-diff-merge.md).

6. **Per-file keys are derived, not wrapped.** The obvious design — a random DEK
   per file, wrapped by the master key — is non-deterministic and therefore
   fails (1). Deriving the DEK from the master key and a keyed hash of the
   content keeps the isolation property, costs 48 bytes less per file, and is
   the only version that works. [05](05-key-hierarchy.md).

7. **Removing a recipient does not un-share anything.** They have the
   repository, they had the key, and every blob committed under that generation
   stays readable to them forever. Removal, rotation and re-encryption are three
   separate steps and only the first two are about the future.
   [09](09-rotation-recovery.md).

8. **The dominant risk is losing the key, not breaking the cipher.** For a tool
   whose premise is that the cloud provider cannot help you, the most likely bad
   outcome is that nobody can. `init`, `status` and `verify` all push toward two
   independent recovery paths, because a user who has not lost a key yet does
   not feel the need. [15](15-failure-modes.md), F14.

9. **Paths, sizes, commit messages and blob equality are all visible**, and
   encrypting paths would stop this being Git. `secrets/prod-db-password.json`
   discloses its own inventory no matter what the file contains. If the
   *existence* of a secret is sensitive, it does not belong in this repository.
   [14](14-metadata-leakage.md).

10. **This tool authenticates blobs, not history.** A GCM tag proves a ciphertext
    was produced by a key holder — not that it belongs at that path, in that
    commit, at that point in the branch. An adversary with push access can
    relocate or roll back a blob and it will decrypt perfectly. Signed commits
    and protected branches remain necessary and are not in scope here.
    [16](16-adversarial-integrity.md), T3 and T4.
