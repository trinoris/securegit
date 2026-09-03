# 09. Rotation & Recovery

## Overview

Adding a key generation, moving content onto it, and the offline path back in
when every workstation is gone.

**Status: MOSTLY IMPLEMENTED.** `key rotate`, `reencrypt`, `key
export-recovery`, and `key import-recovery` are all built and wired into
`src/cli.ts`, on top of `rotateKeyring` and the new
`keyringFromRecoveredGenerations` (`src/keyring.ts`). `src/recovery.ts` — the
export/import recovery file, the recovery code's format/parse/checksum, and
the recovery log — is built and tested at both the module level and, now,
end-to-end through the CLI, giving [16](16-adversarial-integrity.md)'s T6
(recovery theft) a real mitigation to test against, where none existed
before. `rotate` now also requires the recipient-count confirmation T5 asks
for — `--confirm-recipients <n>`, checked before the dirty-tree/locked
refusals hand off to the actual rotation. Not built:
[15](15-failure-modes.md)'s F13 (concurrent rotate and add), which needs a
real race, not just the commands existing. See "What this pass actually
built" below.

## Core Principle

> Rotation is forward-only. It changes who can read what you commit **next**;
> it cannot change who could read what you already pushed, because they already
> pushed it and somebody else already has it.

## Rotation

```
securegit key rotate [--bind-path]
```

1. Refuse if the working tree has uncommitted changes.
2. Refuse if the keyring is not unlocked.
3. Generate a new 32-byte RMK; assign generation `current + 1`.
4. Wrap it with every configured provider ([06](06-key-provider-port.md)).
5. Wrap it for every current recipient ([08](08-multi-recipient.md)) and write
   the recipient files.
6. Set `current` to the new generation. **Keep every earlier generation.**
7. Invalidate the session cache, so the next operation re-reads the keyring.

Nothing in the repository's *content* changes. Rotation on its own means the
next commit of a protected file uses the new generation; files not touched again
stay on their old one indefinitely, which is correct and is why old generations
are never deleted.

### `securegit reencrypt`

```
securegit reencrypt [--paths <pathspec>] [--dry-run]
```

Re-runs `clean` over every protected file in the working tree under the current
generation and stages the result. It is an ordinary commit — reviewable, and
revertable — not a history rewrite.

```
$ securegit reencrypt --dry-run
 config/production.json   generation 2 → 4
 config/staging.json      generation 2 → 4
 .env                     generation 4  (already current)
 3 protected files, 2 would change
```

**It does not touch history.** Blobs already committed under generation 2 remain
in the object database under generation 2. If the requirement is that a departed
holder of generation 2 cannot read *any* version of the file, the only answer is
`git filter-repo` plus a force-push plus rotating the secret itself — and
rotating the secret itself is the answer that actually works, because they had
the plaintext.

`reencrypt` says so, once, on first use:

```
note: this re-encrypts the current worktree. Earlier commits keep their
      earlier generations, and anyone who had those keys can still read them.
      If a secret was exposed, rotate the secret, not the repository.
```

## Recovery

The case this exists for: the laptop is gone, the desktop is gone, and the
repository is a ciphertext blob in S3.

### Export

```
securegit key export-recovery --out proj.recovery.txt
```

- Generate 32 random bytes — the **recovery code**.
- `wrapKey = HKDF-SHA256(code, info = "securegit/recovery/v1")`.
- Encrypt every generation's RMK under it with AES-256-GCM,
  `aad = repoId ‖ format` — plus a `"securegit/recovery-file/v1"` domain
  label prefix as built, matching every other AAD construction in this
  codebase (`provider.ts`'s key wrap, `recipients.ts`'s recipient wrap).
- Write the ciphertext to the named file, ASCII-armoured.
- Print the code **once**, to the terminal, and never store it.

```
   ┌──────────────────────────────────────────────┐
   │  SECUREGIT RECOVERY CODE — repo 4f9a1c22     │
   │                                              │
   │    K7M2-9XQF-3JBN-P0RT-5W8V-YH4C-2ZDG        │
   │    -A1KE-6NSU-M9PB-QT3F-XJ7R-40WY            │
   │                                              │
   │  Write this down. It is not stored anywhere. │
   │  It decrypts every generation of this        │
   │  repository, now and in the past.            │
   └──────────────────────────────────────────────┘
```

Crockford base32 — no `I`, `L`, `O` or `U`, case-insensitive, `1`/`I` and
`0`/`O` folded on input — because this string gets copied by hand under stress.
256 bits of entropy, plus a checksum group: as built, that's a 4-byte
checksum appended to the 32-byte code before encoding, 58 Crockford
characters total rather than the 52 this section originally illustrated —
52 characters is exactly what 256 bits alone requires, leaving no room for
a checksum inside that count without weakening the code itself. See "What
this pass actually built" below.

As built, `--out <file>` is required (no default filename — a recovery
file is significant enough that naming it is deliberate, not incidental),
and export needs no separate secret at all: it reads every generation the
current **session** already holds (the same `available()`/`find()` a
recipient-add reads from), so exporting only requires an unlocked session,
not the passphrase again.

### Import

```
securegit key import-recovery --in proj.recovery.txt
```

Prompts for the code, decrypts, and writes a fresh local keyring wrapped by a
newly chosen provider. The machine is then a full holder: it can rotate, add
recipients, and re-export.

As built, `--in <file>` is required for the same reason `--out` is.
`import-recovery` needs *two* secrets in one invocation — the recovery code
(to open the file) and a brand-new local passphrase (to wrap the keyring
this machine is about to become a holder under) — where every other command
in this codebase needs at most one. Each has its own env var
(`SECUREGIT_RECOVERY_CODE`, `SECUREGIT_PASSPHRASE`); when either falls back
to reading from `stdin`, the code is read as line 1 and the passphrase as
line 2, the order a human would naturally be prompted in. A recovery file
whose `repoId` doesn't match the current repository is checked and refused
*before* attempting to decrypt anything (exit 2, misconfigured — the F19
pattern from [15](15-failure-modes.md)); a syntactically valid code that
simply doesn't decrypt the file (wrong code) is a separate failure (exit 1,
locked — "a key was needed and unavailable," per
[10](10-cli-contract.md)'s exit code table) from a malformed code that fails
`parseRecoveryCode`'s own checksum (exit 4, usage).

### The two-part split is the point

```
   recovery FILE   →  ciphertext, safe to commit, back up freely,
                      put it in the repository if you like
   recovery CODE   →  256 bits, offline, on paper, in a safe
```

Neither half alone is anything. The file may be stored with the cloud provider
the whole design distrusts, because without the code it is noise. The code is
short enough to be written on a card, which is the storage medium with the best
survival record for this kind of secret.

### It is a full bypass, permanently

Say it in the documentation and in the command's own output:

- The code decrypts **every generation**, including ones created after the
  export. (Generations added later are not in that file — but `export-recovery`
  can be re-run, and users will re-use the code. Assume compromise of the code
  is compromise of the repository.)
- It is not revocable. Rotation does not invalidate a code for the generations
  it already covers.
- Anyone holding both halves is a full recipient, invisibly — they leave no
  entry in `.securegit/recipients/`, so `verify`'s "who can read this" list
  cannot see them.

That last point is the real cost, and it is why `export-recovery` records the
*event* — timestamp, identity, a random export id, and which generations it
covers — in `.securegit/recovery-log.json`, committed. Not the code, not the
file: just the fact that an export happened and what it reaches, so the
answer to "who can read this repository" is "these recipients, plus whoever
holds the two exports taken in January" ([13](13-verify.md)'s `verify
--access`, built on this log directly).

`key remove-recipient` gets the same treatment for the same reason: deleting
the recipient file leaves no record that the fingerprint ever had access, so
it now reads the file *before* deleting it and appends `{fingerprint, label,
removedAt, removedBy, generations}` — the generations that file covered at
the moment of removal — to a committed `.securegit/removed-recipients.json`.
Removal doesn't revoke access already shared (only `key rotate` +
`reencrypt` do), so this log is the only record of who used to be able to
read what.

## What this pass actually built

`cmdKeyRotate` and `cmdReencrypt` in `src/cli.ts`, plus `listTrackedPaths`/
`checkAttr`/`readIndexBlob` exported from `verify.ts` for `reencrypt` to
reuse rather than duplicate.

- **Locked has to be checked before the dirty-tree check, not after — found
  by testing, not by reading the spec.** `git status`'s dirty comparison has
  to run `clean` to compare a plaintext worktree against a ciphertext index
  correctly, and `clean` fails closed when locked ([07](07-unlock-session.md),
  F1). Checking status first on a locked repository doesn't produce "you're
  locked" — it produces a confusing `git status` subprocess failure instead,
  since the status check itself can't complete. `cmdKeyRotate` checks
  `loadKeys().current()` first for exactly this reason; the ordering is load
  bearing, not stylistic.
- **The recipient-count confirmation (`--confirm-recipients <n>`) is loaded
  and checked right after the locked check, before the dirty-tree check —
  not after rotation, where the old version only used the recipient list to
  decide what to rewrap.** Recipient files are read once, into memory, for
  both purposes: the confirmation gate compares `recipientEntries.length`
  against the operator's claimed count, and — once confirmed — the exact
  same in-memory list is what gets rewrapped, so there is no window where
  the set could change between "here's who I'm about to affect" and "here's
  who I actually affected." Named `--confirm-recipients`, not a bare
  `--yes`, deliberately: it has to catch a genuine mismatch (someone added
  or removed since the operator last looked), not just acknowledge a
  warning was shown.
- **`--bind-path` is refused, not silently ignored.** `config.ts` has no
  function to update an already-initialised repository's `bindPath` — only
  `initConfig` sets it, once, at `init`. Silently ignoring the flag would be
  worse than refusing it: the operator asked for one thing and got another
  with no indication. Refusing with a clear message is the honest choice
  until that primitive exists.
- **`reencrypt` never writes ciphertext to the worktree file.** It stages a
  new blob via `hash-object`/`update-index` plumbing directly — the same
  technique the test fixtures throughout this project use to stage content
  without invoking a filter. The worktree copy stays exactly what it was
  (plaintext), which is the whole point: a file the user isn't editing
  should never visibly change out from under them.
- **`--dry-run` and the real run share one loop, deciding "would change" by
  actually computing the re-encrypted bytes and comparing.** `clean` is
  deterministic, so a file already on the current generation always
  re-encrypts to byte-identical ciphertext — there is no need to separately
  parse each blob's envelope to find its generation number just to decide
  whether it would change; the comparison already answers that. The spec's
  example output names actual generation numbers (`2 → 4`); what's built
  reports `would change`/`already current` instead — accurate about the
  decision, simpler to implement, and the generation-number version can be
  added later without changing the underlying logic.
- **`--paths <pathspec>` is a prefix match, not real git pathspec syntax.**
  Full pathspec support (globs, magic signatures) is real complexity for a
  flag that exists to scope a re-encrypt to part of a large repository — a
  prefix match covers the common case (`--paths config/`) and is honestly
  documented as a simplification rather than silently mishandling the
  syntax someone might reasonably expect.

`src/recovery.ts` exports `generateRecoveryCode`/`formatRecoveryCode`/
`parseRecoveryCode`, `exportRecovery`/`importRecovery`, and
`recoveryLogPath`/`appendRecoveryLogEntry`/`readRecoveryLog`.

- **The recovery code's own Crockford codec is imported from `identity.ts`,
  not duplicated.** `crockfordEncode`/`crockfordDecode` were already built
  and tested for `SGPUB1…` public-key encoding ([08](08-multi-recipient.md));
  exporting them was a two-line change against writing (and separately
  testing) a second copy of the same base32 variant.
- **The recovery code is 32 random bytes plus a 4-byte checksum
  (`SHA-256(code)[0:4]`), Crockford-encoded to 58 characters — not the
  "52 characters" the spec's illustrative example shows.** The spec doesn't
  give the checksum an exact formula, and 256 bits of pure entropy alone
  already Crockford-encodes to 52 characters with no room left for a
  checksum inside that count. Adding the checksum as extra characters,
  rather than trying to steal bits from the 256 to fit exactly 52, keeps
  the code's actual entropy at the full 256 bits the spec promises
  ("256 bits of entropy in 52 characters" — read as the payload, not the
  total encoded length) rather than shipping a slightly weaker code to hit
  a specific character count.
- **Parsing folds `O`→`0` and `I`/`L`→`1`, exactly as specified — this is
  the one place in the codebase that does, deliberately.**
  `identity.ts`'s public-key decoding does not fold anything; the spec
  only asks for folding on the recovery code, which is read off a printed
  card under stress rather than pasted from a chat window, and the
  difference is intentional, not an oversight to reconcile later.
- **Every generation is encrypted under one wrap key derived from the code,
  each with its own random nonce — not a fresh key per generation the way
  `recipients.ts`'s wrap is.** `recipients.ts` can afford a zero nonce
  because a fresh ephemeral keypair makes every wrap key single-use by
  construction; here there is only one code and therefore one wrap key
  reused across every generation, so a random nonce per generation is not
  optional the way it was there.
- **`importRecovery` fails the whole operation on the first generation that
  won't decrypt, rather than skipping it the way `unlockFromRecipientFile`
  skips a generation it wasn't given.** A recipient may legitimately hold
  only some generations; a recovery code has no such partial case — the
  same code either decrypts every generation in the file or none of them,
  so a per-generation failure only ever means "wrong code" or "corrupted
  file," and silently returning fewer generations than the file actually
  has would hide that.
- **`checksum(code).equals(given)` in `parseRecoveryCode` is a plain
  `Buffer#equals()`, not `equalCt` — allowlisted in `src/package.test.ts`
  alongside `identity.ts`'s and `envelope.ts`'s exceptions.** Both sides of
  that comparison come from the same caller-supplied string; it can never
  reveal anything about a secret the caller doesn't already hold. The
  actual secrecy boundary is `importRecovery`'s AEAD auth tag, timing-safe
  by construction via Node's own crypto.

`cmdKeyExportRecovery`/`cmdKeyImportRecovery` in `src/cli.ts`, plus a new
`keyringFromRecoveredGenerations` in `src/keyring.ts` that neither
`createKeyring` (always fresh generation 1) nor `rotateKeyring` (always
exactly one new generation atop an existing file) could do: build a full
keyring from an arbitrary, already-determined set of generations, wrapped
for a brand-new provider. This was the missing piece flagged during the
multi-recipient join-flow work — the reason `unlock`-via-recipient-file
bootstraps only a session, never a persisted keyring — and closing it here
also means that gap could now be closed for the recipient path too, though
that is out of scope for this pass.

- **`export-recovery` reads from the unlocked *session*, exactly like
  `key add-recipient` does, not from a freshly-read-and-unlocked keyring
  file.** Both commands need "every generation this holder can currently
  decrypt," and the session already has that in hand — re-deriving it from
  the keyring file a second time would need the passphrase again for no
  benefit. One consequence: exporting recovery needs no secret at all beyond
  an unlocked session.
- **`import-recovery` is the one command in this codebase that needs two
  secrets in a single invocation**, and the existing `resolvePassphrase`
  convention (one env var, else the whole of `stdin`) doesn't extend to two.
  Built as `resolveImportRecoverySecrets`: each secret gets its own env var
  (`SECUREGIT_RECOVERY_CODE`, `SECUREGIT_PASSPHRASE`), and whichever ones
  fall back to `stdin` consume it in order — code first, then passphrase —
  so a fully-interactive invocation still works with one secret per line, in
  the order a person would naturally be asked.
- **A `repoId` mismatch is checked directly against the recovery file before
  calling `importRecovery`, rather than relying on `importRecovery`'s own
  internal check.** Both a wrong repository and a wrong code raise the same
  `RecoveryError`, but they belong to different exit codes — misconfigured
  (2, F19-style) versus locked (1, "a key was needed and unavailable"). The
  CLI needed to tell them apart before the exit code was decided, so the
  cheap, non-cryptographic check runs first, in `cli.ts`, exactly as
  `unlockKeyring`'s `expectedRepoId` option already does for the ordinary
  unlock path.
- **`--out`/`--in` are both required flags, with no default filename.** A
  recovery file is significant enough — it is a permanent, irrevocable
  bypass of every access control the repository has — that naming it should
  be a deliberate act, not something that falls out of an unnamed default.

## Test Cases

| Test | Test File | Fixture | Status |
|------|-----------|---------|--------|
| `rotate` adds a generation and keeps all earlier ones | `src/keyring.test.ts` | — | ✅ |
| `rotate` refuses `--bind-path` (not implemented) | `src/cli.test.ts` | — | ✅ |
| `rotate` refuses on a dirty working tree | `src/cli.test.ts` | `repo-protected/` | ✅ |
| `rotate` refuses when locked (checked before the dirty-tree check) | `src/cli.test.ts` | — | ✅ |
| `rotate` refuses without `--confirm-recipients`, printing the recipient list | `src/cli.test.ts` | — | ✅ |
| `rotate` refuses a `--confirm-recipients` count that does not match reality | `src/cli.test.ts` | — | ✅ |
| `rotate` wraps the new generation for every provider | `src/keyring.test.ts` | — | ✅ |
| `rotate` wraps the new generation for every recipient | `src/cli.test.ts` | — | ✅ |
| `rotate` invalidates the session | `src/cli.test.ts` | — | ✅ |
| Blobs from every generation decrypt after two rotations | `src/git.integration.test.ts` | `repo-protected/` | ✅ |
| `reencrypt --dry-run` stages nothing | `src/cli.test.ts` | `repo-protected/` | ✅ |
| `reencrypt` moves a protected file to `current`, staged not committed | `src/cli.test.ts` | — | ✅ |
| `reencrypt` moves every protected file to `current` across a real clone | `src/git.integration.test.ts` | `repo-protected/` | ✅ |
| `reencrypt` leaves history untouched | `src/cli.test.ts` | — | ✅ |
| `reencrypt` is a no-op when everything is current | `src/cli.test.ts` | — | ✅ |
| `reencrypt` exits locked when the repository is locked | `src/cli.test.ts` | — | ✅ |
| Recovery export/import round-trips every generation | `src/recovery.test.ts` | — | ✅ |
| Recovery file alone does not decrypt | `src/recovery.test.ts` | — | ✅ |
| Wrong recovery code fails cleanly | `src/recovery.test.ts` | — | ✅ |
| Recovery code is accepted lowercase, unspaced, and with `O`/`0` confused | `src/recovery.test.ts` | — | ✅ |
| Recovery code checksum rejects a single-character error | `src/recovery.test.ts` | — | ✅ |
| Recovery file bound to `repoId` fails against another repo | `src/recovery.test.ts` | — | ✅ |
| `import-recovery` produces a keyring able to rotate | `src/keyring.test.ts` | — | ✅ |
| `export-recovery` appends to the committed recovery log | `src/recovery.test.ts` | — | ✅ |
| The recovery code never appears in any file written | `src/recovery.test.ts` | — | ✅ |
| `key export-recovery` requires `--out`, requires an unlocked session | `src/cli.test.ts` | — | ✅ |
| `key export-recovery` writes a recovery file and prints the code to stderr, never stdout | `src/cli.test.ts` | — | ✅ |
| `key export-recovery` appends to the committed recovery log, via the CLI | `src/cli.test.ts` | — | ✅ |
| `key import-recovery` requires `--in`, exits usage on a missing file | `src/cli.test.ts` | — | ✅ |
| `key import-recovery` exits misconfigured on a `repoId` mismatch (checked before decrypting) | `src/cli.test.ts` | — | ✅ |
| `key import-recovery` exits locked on a syntactically valid but wrong code | `src/cli.test.ts` | — | ✅ |
| `key import-recovery` falls back to two-line stdin (code, then passphrase) with no env vars | `src/cli.test.ts` | — | ✅ |
| End-to-end: export on one machine, import onto a fresh home, unlock, and decrypt | `src/cli.test.ts` | — | ✅ |

## Relationship to Other Specs

- [05](05-key-hierarchy.md) — generations and why old ones are kept
- [06](06-key-provider-port.md) — the `recovery-code` provider
- [08](08-multi-recipient.md) — removal requires rotation to mean anything
- [13](13-verify.md) — the "who can read this" report and its blind spot;
  also `recoveryPathStatus()`, the single-recovery-path advisory both
  `verify` and `status` now surface — fewer than two independent paths to
  the current generation, and no export on record
- [16](16-adversarial-integrity.md) — theft of a recovery file
