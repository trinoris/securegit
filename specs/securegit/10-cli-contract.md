# 10. CLI Contract

## Overview

The public surface. Commands, exit codes, and the output discipline that keeps a
tool which is sometimes a Git filter and sometimes a human interface from
confusing the two.

**Status: IMPLEMENTED.** `src/cli.ts` now covers every command below,
including `key list-recipients`, built on the same `accessReport()`
(`src/verify.ts`, [13](13-verify.md)) that `verify --access` already uses
— that report already computes fingerprint/label/added-at/added-by/
generations per recipient, `git log`-derived `addedCommit` included, so
`key list-recipients` re-derives nothing, just renders the `recipients`
slice of it. `key add-provider`, `key remove-provider` and `key list` are
implemented too — see the "Key providers" section below for what they mean
when `passphrase-file` is the only provider type that exists. `unprotect`
is implemented ([02](02-git-integration.md)) — `.gitattributes` only,
`.gitignore` residue entries untouched, forward-only exactly like key
rotation. `verify` now covers its base form, `--history`, and `--access`.
`--json` is implemented too, for every command that currently exists and
produces a report — `status`, `verify` (all three forms), `inspect`,
`key list`, and now `key list-recipients` — writing the underlying report
object straight to stdout via `JSON.stringify`, no separate schema to keep
in sync with the human-readable rendering. `identity
init`/`show` and `key add-recipient`/`remove-recipient` — the
multi-recipient join flow — are implemented, including `unlock` bootstrapping
a session from a recipient file alone when no local keyring exists. `key
rotate` and `reencrypt` are implemented too ([09](09-rotation-recovery.md)) —
`key rotate` refuses a dirty tree or a locked repository (locked checked
first, since the dirty-tree check itself needs to run `clean`, which fails
closed when locked) and rewraps every existing recipient; `reencrypt` stages
re-encrypted blobs via plumbing, never touching the worktree file. `key
export-recovery`/`import-recovery` are implemented on top of `src/recovery.ts`
and a new `keyringFromRecoveredGenerations` in `src/keyring.ts` — export reads
straight from the unlocked session (no separate secret needed); import is the
one command that needs two secrets in one invocation (the recovery code and a
fresh local passphrase), each with its own env var and, on the stdin
fallback, its own line. `filter-process` ([11](11-filter-process.md)) is
implemented too, on `src/pktline.ts`/`src/process.ts` — it doesn't fit
`CliIO`'s single-shot, whole-buffer contract (a long-running stream can't be
one `stdin` buffer and one `runCli()` return), so it gets its own entrypoint,
`runFilterProcess`, called directly from `bin/securegit.ts` before either
`readStdin()` or `runCli()` runs. `--repo <path>` is implemented too:
`runCli` parses and strips it from `argv` once, before dispatch — not
threaded through the ~30 places in `cli.ts` that read `io.cwd` individually
— by reassigning its own `io` parameter to a derived object with `cwd`
resolved (`node:path`'s `resolve`, so a relative path works) and the flag
removed from `argv`. Every existing command case picks up the override for
free, since none of them changes.

`--quiet` is implemented too, splitting `CliIO`'s `stderr` into `stderr`
(errors, and report-type commands' actual reports — never suppressed) and a
new `info` (one-shot success confirmations — suppressed under `--quiet`).

`-v`/`--verbose` is implemented for `clean`, `smudge` and `merge` — the
three commands that actually perform a per-file operation. Unlike
`--repo`, it is parsed the same way `--strict` already was: as one of the
flags each command's own arg parser collects from *before* the `--`
separator (`parsePathArg`'s existing `flags: Set<string>`, and a matching
addition to `parseMergeArgs`), not stripped from `argv` globally in
`runCli`. That's a deliberate difference from `--repo`: a path after `--`
is allowed to begin with `-` ([02](02-git-integration.md)), and a global
scan for `-v` anywhere in `argv` would risk matching a file that happens to
be named `-v` rather than the flag. `FilterContext` and `MergeOptions` each
gained an optional `trace?: (message: string) => void`, called at most
once per invocation with a line naming the path, the generation, and (for
`clean`/`smudge`) which branch was taken (encrypted, decrypted, or one of
the passthrough cases) — never plaintext, never key material, same
redaction discipline as `warn`. `cli.ts` wires `trace: io.stderr` only when
the flag is present; the filter functions themselves don't know what
"verbose" means, only whether a callback was given, so nothing changes for
every existing non-verbose call site.

`--quiet` is implemented too, and required splitting `CliIO`'s single
`stderr` callback into two: `stderr` (unchanged — errors, and the reasoning
below applies to report-type commands too) and a new `info` for one-shot
success confirmations only (`init`'s "initialized repository …",
`unlock`'s "unlocked (generation …)", `protect`/`unprotect`,
`identity init`, `key add-recipient`/`remove-recipient`/`rotate`/
`import-recovery`, `lock`). The naive reading of "suppress non-error
stderr output" would also silence `status`, `identity show`, `verify`, and
`inspect`'s human-readable reports — but a report command's report *is*
its output, the same thing `--json` puts on stdout for a script instead of
a human; suppressing it under `--quiet` would leave the command printing
nothing at all on success, which is not what "quiet" means for a command
whose entire job is to report. So those four, plus `reencrypt`'s per-file
change summary and `key export-recovery`'s one-time recovery code (the
only place that code is ever shown — it is not written to `--out`, only
the encrypted file is), stay on `stderr`, exempt from `--quiet`, same as
they were exempt from being a stdout writer in the first place. `runCli`
checks `argv.includes('--quiet')` once, before dispatch, and — unlike
`--repo` — does not need to strip the flag from `argv`: it takes no value,
and no command does positional (index-based) parsing that an unconsumed
`--quiet` token could be mistaken for. When present, `io.info` is swapped
for a no-op; every command still just calls `io.info(...)`, unaware of
whether it's live.

`key add-provider`, `key remove-provider` and `key list` are implemented
too — see [06](06-key-provider-port.md) for what "add a provider" honestly
means today, with only `passphrase-file` as a real provider type: a
second, independently-passphrased secret, given its own id
(`passphrase-file:<label>`) so it doesn't collide with the unlabeled one
`init` always creates. Building this surface exposed a real usage
collision worth calling out explicitly: `key add-provider` needs two
different things from the operator in one invocation — proof they can
currently unlock this keyring, and the *new* passphrase to wrap it under —
and both would naturally read from `SECUREGIT_PASSPHRASE` if nothing
distinguished them, since `loadKeys()` already treats that variable as a
filter-time unlock credential ([07](07-unlock-session.md)). Resolved the
same way `key import-recovery`'s two-secrets-one-command shape already
does: authenticate via whatever's already unlocked (a session, in the
ordinary case — `SECUREGIT_PASSPHRASE` is deliberately left unconsulted
for this specific call, precisely because it's spoken for), and take the
new passphrase from stdin. `key remove-provider` needs no unlock at all —
it only ever deletes a wrapped slot, refusing (never re-wrapping) if doing
so would leave any generation with no provider left to unlock it. `key
list` needs no key either — generation numbers, fingerprints, creation
dates, and provider ids are keyring metadata, not anything requiring
decryption, the same reasoning `verify` and `key export-recovery`'s read
side already follow; `--json` writes `{current, generations: [{generation,
fingerprint, createdAt, providers}]}` straight to stdout, matching every
other report command's convention.

`key list-recipients` closes out the last command spec 10 names. Built on
`accessReport()` ([13](13-verify.md)) — the same report `verify --access`
already renders — rather than its own enumeration: that report already
walks `.securegit/recipients/*.json` and computes fingerprint, label,
added-at, added-by and covered generations per file (plus a `git
log`-derived `addedCommit`, not shown in this command's own report but
present in its `--json` form since it's just the report's `recipients`
array unmodified). No key required, matching `key list`. `--json` writes
that `recipients` array directly, not wrapped in an outer object — there's
only the one thing this command reports, unlike `key list`'s
`{current, generations}` shape.

## Core Principle

> Some of these commands have Git on the other end of the pipe. **stdout is a
> data channel.** Every diagnostic, prompt, progress indicator and warning goes
> to stderr, in every command, without exception — because the exception is the
> one that corrupts a file.

## Commands

### Repository

| Command | Effect |
|---|---|
| `securegit init [--bind-path] [--pad-to <n>]` | Create `.securegit/config.json`, generate `repoId`, generation 1. Refuses outside a repository, or if already initialised. `--pad-to` ([14](14-metadata-leakage.md)) sets `padTo`, a non-negative integer, `0` (disabled) by default; refused if negative or non-numeric. Neither can be changed by re-running `init` (it refuses a second run) — `bindPath` has its own dedicated update path, `key rotate --bind-path`, below; `padTo` doesn't need one ([05](05-key-hierarchy.md), [14](14-metadata-leakage.md)). |
| `securegit install [--process] [--no-required] [--bin <cmd>]` | Write `.git/config` filter, diff and merge driver entries ([02](02-git-integration.md), [12](12-diff-merge.md)). Idempotent. `--bin` overrides the command Git invokes (default: the resolved `securegit` on `PATH`) — for a global install where `securegit` is not literally the right invocation on every machine (e.g. `node /path/to/securegit.js`, or a version-pinned wrapper), and for the integration test suite, which cannot assume `securegit` is on `PATH` for a binary that was just built. Not meant to be reached for by a normal user. |
| `securegit protect <pattern>…` | Add patterns to `.gitattributes` with `filter`, `diff`, `merge` and `-text`, keeping the `.securegit/**` exclusion last. |
| `securegit unprotect <pattern>…` | Remove patterns from `.gitattributes` only — `.gitignore`'s residue entries are left alone. Warns that already-committed blobs stay encrypted until re-committed. A pattern that was never protected is a silent no-op (exit 0), and doesn't touch the file. |
| `securegit status [--json]` | The diagnostic report in [07](07-unlock-session.md). `--json`: `{repository, repoId, bindPath, padTo, locked, generation, metadata, recoveryPaths}` to stdout — `metadata` is [14](14-metadata-leakage.md)'s M1–M12 report, `recoveryPaths` is [13](13-verify.md)'s single-recovery-path advisory (`{paths, hasExport, warn}`, or `null` with no local keyring); the human-readable form prints `padTo` alongside `bindPath`, a pointer to `status --json` for the M1–M12 detail, and a `⚠` line when `recoveryPaths.warn` is true. |
| `securegit verify [--history\|--access] [--json]` | The audit in [13](13-verify.md). Implemented: the base form (config + index checks, leak/advice scan), `--history` (a real commit walk — CI-tier speed, not pre-commit), `--access` (who can read this repository), and `--json` for all three. |
| `securegit reencrypt [--paths <pathspec>] [--dry-run]` | Move protected files to the current generation ([09](09-rotation-recovery.md)). Stages via plumbing — never writes the worktree file. `--paths` is a prefix match, not full git pathspec syntax. |

### Filters — invoked by Git, not by people

| Command | stdin | stdout |
|---|---|---|
| `securegit clean -- <path>` | plaintext | ciphertext |
| `securegit smudge -- <path>` | ciphertext | plaintext |
| `securegit textconv -- <file>` | — | plaintext, for display |
| `securegit merge -- <base> <ours> <theirs> <markerSize> <path>` | — | — (writes ciphertext to `<ours>` directly; see [12](12-diff-merge.md)) |
| `securegit filter-process` | pkt-line ([11](11-filter-process.md)) | pkt-line |

### Identity ([08](08-multi-recipient.md))

| Command | Effect |
|---|---|
| `securegit identity init [--label <label>]` | Generate an X25519 keypair, wrap the private half via the same `KeyProvider` port a repository uses, write `~/.securegit/identity.json`. Refuses if one already exists. |
| `securegit identity show` | Print the identity's fingerprint and `SGPUB1…`-encoded public key — the string to hand to someone who already has access. |

### Keys

| Command | Effect |
|---|---|
| `securegit key init` | Generate generation 1 and wrap it. Implied by `init`. |
| `securegit key list [--json]` | Generations, fingerprints, dates, current marker, and which provider ids can unlock each. No key required. |
| `securegit key rotate [--bind-path] --confirm-recipients <n>` | Add a generation ([09](09-rotation-recovery.md)); wraps it for every provider and every existing recipient. Refuses a dirty working tree, a locked repository (locked is checked first), or a missing/mismatched `--confirm-recipients <n>` — printing the recipient list either way, checked before the dirty-tree refusal. `--bind-path` additionally flips `config.json`'s `bindPath` to `true` (`setBindPath()`, `src/config.ts`), written only after the rotation itself succeeds — every already-committed blob keeps decrypting under whatever `bindPath` produced it, recorded in its own envelope flags, never read from config. |
| `securegit key add-provider <type> [--label <label>]` | Wrap every generation with an additional provider. `passphrase-file` is the only `<type>` today — this adds a second, independent passphrase, given id `passphrase-file:<label>` so it doesn't collide with the unlabeled one `init` creates. Needs the repository already unlocked; the new passphrase comes from stdin, not `SECUREGIT_PASSPHRASE` (already spoken for as the *current* unlock credential). Refuses (exit 4) a colliding id, an unknown `<type>`, or a session that doesn't hold every generation. |
| `securegit key remove-provider <id>` | Delete a provider's wrapped slot from every generation. Refused (exit 4) if it is the last provider that can unlock any generation, or if `<id>` was never present. No unlock needed — this only ever deletes, never re-wraps. |
| `securegit key add-recipient <pubkey> [--label <label>]` | Wraps every generation the caller currently holds for a recipient's public key ([08](08-multi-recipient.md)), writes `.securegit/recipients/<fingerprint>.json`. Refuses a malformed public key or a locked repository. `addedBy` is the caller's own identity fingerprint if `identity init` has been run locally, else blank — not an error, since the caller may only have direct keyring access. |
| `securegit key remove-recipient <fingerprint>` | Delete the recipient file. Prints the rotation warning — removal alone does not revoke access to generations already shared; that needs `key rotate` + `reencrypt`, both built now. Refuses (exit 4) if no file exists for that fingerprint. Deliberately does not refuse removing the last recipient — see [08](08-multi-recipient.md); the risk that would guard against is already caught, more precisely, by `verify`/`status`'s single-point-of-failure advisory. |
| `securegit key list-recipients [--json]` | Fingerprint, label, added-at, added-by, generations covered — one row per `.securegit/recipients/*.json` file. No key required. |
| `securegit key export-recovery --out <file>` | Recovery file plus a one-time code, printed to stderr once ([09](09-rotation-recovery.md)). Reads every generation from the unlocked session — no separate secret needed. `--out` is required (no default filename); exits locked if the session is locked. Appends an entry to the committed `.securegit/recovery-log.json` (never the code, never the file's content). |
| `securegit key import-recovery --in <file>` | Rebuild a keyring from file + code, wrapped by a freshly chosen local passphrase. `--in` is required. Needs two secrets: `SECUREGIT_RECOVERY_CODE` and `SECUREGIT_PASSPHRASE` (or, on the stdin fallback, code then passphrase, one per line). A `repoId` mismatch exits misconfigured (2, checked before decrypting); a syntactically valid but wrong code exits locked (1); a malformed code (fails its own checksum) exits usage (4). |

`unlock` itself now has two paths, tried in order: the ordinary local
keyring, and — only when no local keyring exists — a bootstrap from
`.securegit/recipients/<the local identity's fingerprint>.json`, decrypting
via the local `~/.securegit/identity.json` and writing a session (not a
persisted local keyring; see [08](08-multi-recipient.md) for why). A machine
with neither a keyring nor an identity gets a message naming both ways
forward: `securegit init`, or `securegit identity init` plus asking an
existing member to run `key add-recipient`.

The local-keyring path tries the entered passphrase against every
passphrase-file-shaped provider id actually present in the keyring, not
only the unlabeled default — `key add-provider --label` can add more than
one — since the caller never says in advance which id their passphrase
belongs to. Only the one whose passphrase genuinely matches ever succeeds;
this is what `loadKeys()`'s `SECUREGIT_PASSPHRASE` filter-time source
([07](07-unlock-session.md)) and `rewrapOutdatedGenerations()`
([06](06-key-provider-port.md)) both do too, via the same shared
`passphraseProvidersFor()` helper in `src/cli.ts`.

### Session

| Command | Effect |
|---|---|
| `securegit unlock [--ttl <duration>]` | Unwrap and cache ([07](07-unlock-session.md)). |
| `securegit lock` | Remove the session cache. |

### Identity

| Command | Effect |
|---|---|
| `securegit identity init [--label]` | Create an X25519 identity for this machine. |
| `securegit identity show` | Print the public key and fingerprint. |

### Ad hoc

| Command | Effect |
|---|---|
| `securegit encrypt <file> [--out <file>]` | Envelope a file outside Git. `-` for stdin/stdout. |
| `securegit decrypt <file> [--out <file>]` | The inverse. |
| `securegit inspect <file> [--json]` | Header fields, no key required ([04](04-envelope-format.md)). `--json`: `{format, algorithm, bindPath, padded, keyId, ciphertextLength}` to stdout. |

`encrypt` / `decrypt` exist because a spec that offers no way to test the
cryptography without a repository is a spec whose cryptography does not get
tested. They use the same code path as the filters.

## Exit codes

| Code | Meaning | Used by |
|---|---|---|
| 0 | success | all |
| 1 | locked — a key was needed and unavailable | `clean`, `status`, key commands |
| 2 | misconfigured — repository, attributes or git config wrong | `status`, `verify`, `install`, `unlock` (F19: keyring belongs to a different `repoId`) |
| 3 | cryptographic failure — authentication failed, unknown format | `smudge`, `decrypt`, `inspect` |
| 4 | usage error | all |
| 5 | leak found — a protected path's committed content is not a real envelope | `verify` (base form and `--history`) |

`merge` is the one exception to this table having one meaning per code: exit
1 means either "locked" (this table's usual meaning) or "conflict, ciphertext
with markers written to `%A`", mirroring `git merge-file`'s own convention —
and the implementation does not give these two outcomes different codes,
because Git's merge-driver protocol only distinguishes zero from nonzero for
that specific invocation, so a caller who only forwards the exit code to Git
loses nothing. A caller who needs to tell them apart still can: a locked
failure always writes a diagnostic to stderr (why, and what to run); a
conflict writes nothing to stderr, because it isn't a failure — Git shows the
conflict on its own.

Distinct codes exist so a pre-push hook can be one line:

```sh
securegit verify --history || exit 1
```

and so a shell prompt can distinguish "locked" from "broken" without parsing
English.

## Global flags

| Flag | Effect |
|---|---|
| `--repo <path>` | Operate on a repository other than the current directory. Resolved against `cwd` (relative paths work), and stripped from `argv` before per-command parsing so a path value is never mistaken for a positional argument. Can appear before or after the command name. Missing its path argument exits 4. |
| `--strict` | `smudge` fails rather than passing ciphertext through ([07](07-unlock-session.md)). |
| `--json` | Machine-readable output for `status`, `verify` (all three forms), `inspect`, `key list` and `key list-recipients` — the report object itself, `JSON.stringify`'d, straight to stdout. |
| `--quiet` | Suppress one-shot success confirmations (`io.info`). Never suppresses errors or a report command's actual report (`status`, `identity show`, `verify`, `inspect`, `reencrypt`, `key export-recovery`'s recovery code) — those stay on `stderr` regardless, same as they were never a stdout writer. |
| `-v`, `--verbose` | Per-file tracing to stderr, on `clean`/`smudge`/`merge` only. Never includes plaintext, key material, or a passphrase. Parsed like `--strict` — before the `--` separator, not stripped from `argv` globally like `--repo`, so a path beginning with `-` after `--` is never at risk of being mistaken for the flag. |

## Implementation: `src/cli.ts`

`runCli(io: CliIO): Promise<number>` is the whole surface — every command is a
plain function of an injected `CliIO` (`argv`, `cwd`, `env`, `stdin` as a
pre-read `Buffer`, `home`, and `stdout`/`stderr`/`info` as callbacks), never
touching `process.*` directly. `stderr` and `info` both write to the real
`process.stderr` in `bin/securegit.ts` — the only difference between them is
that `runCli` swaps `info` for a no-op when `--quiet` is present; `stderr`
is always live. `src/bin/securegit.ts` is the only place that does: it
reads real stdin to a `Buffer`, wires real `process.argv`/`env`/`homedir()`,
and sets `process.exitCode`. This is what makes the entire CLI testable
without spawning a subprocess per test — `src/cli.test.ts` drives `runCli`
directly with an in-memory harness, and a single `src/bin.integration.test.ts`
(which builds the package once, then spawns the real `dist/bin/securegit.js`
through real pipes) exists only to prove the thin adapter itself is wired
correctly, not to re-test command logic.

### Exit codes, concretely

The table above states the five codes; here is what actually produces each of
them, since "misconfigured" and "usage error" are a judgment call per command:

| Situation | Code | Why |
|---|---|---|
| `init` outside a Git checkout, or run twice | 4 | a usage mistake by the invoker, not a broken repository |
| `init`'s passphrase rejected by the provider (`ProviderError`) | 4 | bad input |
| `install` / `protect` / `unlock` / `lock` / `status` reading a missing or malformed `.securegit/config.json` | 2 | the *repository* was never set up, or is broken |
| `install` refusing a foreign filter entry (`InstallError`) | 2 | the repository's Git config disagrees with reality |
| `unlock` where every provider fails to open every generation | 1 | locked — right shape of failure, no key available |
| `clean` throwing `LockedError` | 1 | the asymmetry in [07](07-unlock-session.md), enforced at the CLI boundary too |
| `smudge --strict` locked | 1 | still "locked", not "broken" |
| `smudge --strict` on a generation the keyring lacks | 3 | `filter.ts` reports this as `EnvelopeError`, not `LockedError` — it is *some* key, just not the right one, closer to an authentication problem than an absence of one |
| `decrypt`/`inspect` on malformed input (`EnvelopeError`) | 3 | a cryptographic/format failure, independent of lock state |
| `encrypt`/`decrypt` with no key for the operation at all | 1 | locked |
| unknown command, missing `--` on `clean`/`smudge`/`textconv`, missing positional args | 4 | usage |

### The stdout/stderr line, drawn concretely

The stated rule ("stdout carries data only... everything else is stderr,
without exception") settles a case the abstract wording leaves ambiguous:
**`status` and `inspect`'s plain-text reports go to stderr, not stdout**, even
though nothing pipes them into Git. The reasoning: Git only ever treats
`clean`/`smudge`/`textconv` output as data — those three, plus `encrypt`
and `decrypt` writing to `-`, are the exhaustive list of stdout writers in
`src/cli.ts`. Every other command's human-readable report is a diagnostic by
the rule's own definition, and routing it to stderr uniformly means a script
can never be surprised by which stream carries which command's output — the
answer is always "content commands only," not "commands a human is unlikely to
pipe." `--json` is the escape hatch for a script that wants `status`/
`inspect`/`verify`/`key list`/`key list-recipients` output on stdout
deliberately, now built for all five.

## Output discipline

1. **stdout carries data only** — filter content, `--json`, `decrypt --out -`.
   Everything else is stderr.
2. **No plaintext in any diagnostic**, at any verbosity, including error
   messages about content that failed to parse. Paths and byte lengths are
   permitted; content is not.
3. **No key material anywhere**, including `--verbose` and crash traces. Key
   objects carry a `toJSON` that returns `"[redacted]"`, so an accidental
   interpolation prints a marker rather than a secret.
4. **Prompts to `/dev/tty`** when it exists, never to stdout, never at all when
   `interactive` is false ([06](06-key-provider-port.md)).
5. **Errors name the path** they concern. "authentication failed" is unhelpful
   during a 400-file checkout.

## Test Cases

| Test | Test File | Fixture | Status |
|------|-----------|---------|--------|
| Every command writes diagnostics to stderr only | `src/cli.test.ts` | — | ✅ |
| Exit codes match the table | `src/cli.test.ts` | — | ✅ |
| `status --json` writes `{repository, repoId, bindPath, padTo, locked, generation}` to stdout, nothing to stderr | `src/cli.test.ts` | — | ✅ |
| `verify --json` / `--access --json` / `--history --json` each write their report object to stdout | `src/cli.test.ts` | — | ✅ |
| `inspect --json` writes header fields (including `padded`) to stdout | `src/cli.test.ts` | — | ✅ |
| Unknown flag exits 4 with usage | `src/cli.test.ts` | — | ✅ |
| `init` outside a repository exits 4 | `src/cli.test.ts` | — | ✅ |
| `init` twice exits 4 rather than regenerating a key | `src/cli.test.ts` | — | ✅ |
| `init --pad-to` sets `padTo`; `0` by default; a negative or non-numeric value exits 4 | `src/cli.test.ts` | — | ✅ |
| `clean`/`smudge` round-trip through the real CLI with `padTo` set, `padded` flag correctly recorded | `src/cli.test.ts` | — | ✅ |
| `encrypt`/`decrypt` round-trip via stdin and stdout | `src/cli.test.ts` | — | ✅ |
| `encrypt`/`decrypt` produce the same bytes as the filters | `src/cli.test.ts` | — | ✅ |
| No command prints key material at `--verbose` | `src/cli.test.ts` | — | ✅ |
| A key object interpolated into a string yields `[redacted]` | `src/crypto.test.ts` | — | ✅ |
| Error messages name the offending path | `src/cli.test.ts` | — | ✅ |
| No error message contains plaintext bytes | `src/cli.test.ts` | `blobs/` | ✅ |
| `--repo` operates on the named repository, before or after the command, relative paths resolve against `cwd` | `src/cli.test.ts` | — | ✅ |
| `--repo` with no path argument exits 4 | `src/cli.test.ts` | — | ✅ |
| `--quiet` suppresses a success confirmation without changing the exit code or side effect | `src/cli.test.ts` | — | ✅ |
| `--quiet` never suppresses an error message | `src/cli.test.ts` | — | ✅ |
| `--quiet` never suppresses `status`'s or `identity show`'s human-readable report | `src/cli.test.ts` | — | ✅ |
| `protect` keeps the `.securegit/**` exclusion last | `src/install.test.ts` | — | ✅ |
| `unprotect` removes the pattern, keeping the exclusion line | `src/install.test.ts` | — | ✅ |
| `unprotect` removes only the named pattern, leaving others intact | `src/install.test.ts` | — | ✅ |
| `unprotect` is a silent no-op for a pattern that was never protected, and doesn't touch a nonexistent `.gitattributes` | `src/install.test.ts` | — | ✅ |
| `unprotect` does not touch `.gitignore` residue entries | `src/install.test.ts` | — | ✅ |
| `securegit unprotect` warns that already-committed blobs stay encrypted | `src/cli.test.ts` | — | ✅ |
| `install --bin` points the filter at an unpublished build | `src/cli.test.ts` | — | ✅ |
| `verify` exits misconfigured (2) before `init`, and 0 on a correctly configured repository | `src/cli.test.ts` | — | ✅ |
| `verify` exits leaked (5) and writes nothing to stdout | `src/cli.test.ts` | — | ✅ |
| `merge` resolves a clean merge, writes ciphertext to `%A`, exits 0 | `src/cli.test.ts` | — | ✅ |
| `merge` exits 1 on a real conflict, with markers visible once decrypted | `src/cli.test.ts` | — | ✅ |
| `merge` exits 4 when an argument is missing | `src/cli.test.ts` | — | ✅ |
| `merge` exits locked (1) with no current generation to encrypt the result under | `src/cli.test.ts` | — | ✅ |
| `identity init` writes `~/.securegit/identity.json`, refuses a second run | `src/cli.test.ts` | — | ✅ |
| `identity show` exits misconfigured (2) before init, prints the public key to stderr after | `src/cli.test.ts` | — | ✅ |
| `key add-recipient` exits locked (1) against a locked repository | `src/cli.test.ts` | — | ✅ |
| `key add-recipient` exits usage (4) on a malformed public key | `src/cli.test.ts` | — | ✅ |
| `key remove-recipient` deletes the file, exits usage (4) if it never existed | `src/cli.test.ts` | — | ✅ |
| `key add-provider` wraps every generation for a second, independent passphrase, unlockable via `unlock` on its own | `src/cli.test.ts` | — | ✅ |
| `key add-provider` exits usage (4) without `--label`, colliding with the existing unlabeled provider | `src/cli.test.ts` | — | ✅ |
| `key add-provider` exits locked (1) against a locked repository | `src/cli.test.ts` | — | ✅ |
| `key add-provider` exits usage (4) for an unknown provider type | `src/cli.test.ts` | — | ✅ |
| `key remove-provider` deletes a provider's slot; the removed passphrase stops unlocking, the remaining one still works | `src/cli.test.ts` | — | ✅ |
| `key remove-provider` exits usage (4) removing the only provider a generation has, or an id that was never present | `src/cli.test.ts` | — | ✅ |
| `key list` / `key list --json` report generations, fingerprints, dates, current marker and provider ids, without needing a key | `src/cli.test.ts` | — | ✅ |
| `key list-recipients` exits misconfigured (2) before `init` | `src/cli.test.ts` | — | ✅ |
| `key list-recipients` reports "(none)" for a fresh repository | `src/cli.test.ts` | — | ✅ |
| `key list-recipients` / `key list-recipients --json` report fingerprint, label, added-at and generations, without needing a key | `src/cli.test.ts` | — | ✅ |
| End-to-end: a second identity joins via `add-recipient`, `unlock`s with no local keyring, and decrypts | `src/cli.test.ts` | — | ✅ |
| `unlock` names both `init` and `identity init` when neither a keyring nor an identity exists | `src/cli.test.ts` | — | ✅ |
| `key rotate --bind-path` rotates and enables `bindPath`; `key rotate` refuses a dirty tree, a locked repository, and a missing/mismatched `--confirm-recipients` (locked checked first) | `src/cli.test.ts` | — | ✅ |
| `key rotate` invalidates the session and rewraps every existing recipient | `src/cli.test.ts` | — | ✅ |
| `reencrypt` stages a re-encrypted blob without touching the worktree file; `--dry-run` stages nothing; a no-op once current | `src/cli.test.ts` | — | ✅ |
| `key export-recovery` requires `--out`, exits locked without an unlocked session, prints the code to stderr only | `src/cli.test.ts` | — | ✅ |
| `key export-recovery` appends to the committed recovery log | `src/cli.test.ts` | — | ✅ |
| `key import-recovery` requires `--in`, exits usage on a missing file | `src/cli.test.ts` | — | ✅ |
| `key import-recovery` exits misconfigured on a `repoId` mismatch, checked before decrypting | `src/cli.test.ts` | — | ✅ |
| `key import-recovery` exits locked on a syntactically valid but wrong code | `src/cli.test.ts` | — | ✅ |
| `key import-recovery` falls back to two-line stdin (code, then passphrase) with no env vars set | `src/cli.test.ts` | — | ✅ |
| End-to-end: `export-recovery` on one machine, `import-recovery` onto a fresh home, `unlock`, and decrypt | `src/cli.test.ts` | — | ✅ |
| `runFilterProcess` exits misconfigured before `init`; resolves once stdin ends | `src/cli.test.ts` | — | ✅ |
| `runFilterProcess` serves a real handshake, capabilities, and a clean/smudge round trip | `src/cli.test.ts` | — | ✅ |
| `filter-process` output matches the one-shot `clean` CLI form, byte for byte | `src/cli.test.ts` | — | ✅ |
| `runFilterProcess` resolves with the usage exit code on a protocol violation, without hanging | `src/cli.test.ts` | — | ✅ |
| `runFilterProcess` serializes chunks that arrive before the previous one finished | `src/cli.test.ts` | — | ✅ |
| `verify --history` exits 0 with no plaintext ever committed | `src/cli.test.ts` | — | ✅ |
| `verify --history` exits leaked (5), reporting first/last commit | `src/cli.test.ts` | — | ✅ |
| `verify --access` reports "(none)" everywhere for a fresh solo repository | `src/cli.test.ts` | — | ✅ |
| `verify --access` lists a recipient, a recovery export, and a removed recipient | `src/cli.test.ts` | — | ✅ |

## Relationship to Other Specs

- [02](02-git-integration.md) — what `install` and `protect` write
- [07](07-unlock-session.md) — `unlock`, `lock`, `status`
- [08](08-multi-recipient.md) — `identity`, `key add-recipient`/`remove-recipient`, and `unlock`'s recipient-file path
- [09](09-rotation-recovery.md) — `key rotate`, `reencrypt`, and why locked is checked before the dirty-tree check
- [11](11-filter-process.md) — `filter-process`
- [12](12-diff-merge.md) — `merge`, and why exit 1 has two meanings there
- [13](13-verify.md) — `verify` and exit code 5
