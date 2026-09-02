# 10. CLI Contract

## Overview

The public surface. Commands, exit codes, and the output discipline that keeps a
tool which is sometimes a Git filter and sometimes a human interface from
confusing the two.

**Status: MOSTLY IMPLEMENTED.** `src/cli.ts` covers every command below except
`unprotect`, `reencrypt`, `filter-process`, and everything under Keys/Recipients
(those need spec 08/09, not yet built). `verify` and `merge` are wired but only
in their base form — `verify --history`/`--access`/`--json` are not implemented.

## Core Principle

> Some of these commands have Git on the other end of the pipe. **stdout is a
> data channel.** Every diagnostic, prompt, progress indicator and warning goes
> to stderr, in every command, without exception — because the exception is the
> one that corrupts a file.

## Commands

### Repository

| Command | Effect |
|---|---|
| `securegit init [--bind-path]` | Create `.securegit/config.json`, generate `repoId`, generation 1. Refuses outside a repository, or if already initialised. |
| `securegit install [--process] [--no-required] [--bin <cmd>]` | Write `.git/config` filter and diff entries ([02](02-git-integration.md)). Idempotent. `--bin` overrides the command Git invokes (default: the resolved `securegit` on `PATH`) — for a global install where `securegit` is not literally the right invocation on every machine (e.g. `node /path/to/securegit.js`, or a version-pinned wrapper), and for the integration test suite, which cannot assume `securegit` is on `PATH` for a binary that was just built. Not meant to be reached for by a normal user. |
| `securegit protect <pattern>…` | Add patterns to `.gitattributes` with `filter`, `diff` and `-text`, keeping the `.securegit/**` exclusion last. |
| `securegit unprotect <pattern>…` | Remove patterns. Warns that already-committed blobs stay encrypted until re-committed. |
| `securegit status` | The diagnostic report in [07](07-unlock-session.md). |
| `securegit verify [--history]` | The audit in [13](13-verify.md). Implemented: the base form (config + index checks, leak/advice scan). Not yet: `--history`, `--access`, `--json`. |
| `securegit reencrypt [--paths <pathspec>] [--dry-run]` | Move protected files to the current generation ([09](09-rotation-recovery.md)). |

### Filters — invoked by Git, not by people

| Command | stdin | stdout |
|---|---|---|
| `securegit clean -- <path>` | plaintext | ciphertext |
| `securegit smudge -- <path>` | ciphertext | plaintext |
| `securegit textconv -- <file>` | — | plaintext, for display |
| `securegit merge -- <base> <ours> <theirs> <markerSize> <path>` | — | — (writes ciphertext to `<ours>` directly; see [12](12-diff-merge.md)) |
| `securegit filter-process` | pkt-line ([11](11-filter-process.md)) | pkt-line |

### Keys

| Command | Effect |
|---|---|
| `securegit key init` | Generate generation 1 and wrap it. Implied by `init`. |
| `securegit key list` | Generations, fingerprints, dates, current marker. |
| `securegit key rotate [--bind-path]` | Add a generation ([09](09-rotation-recovery.md)). |
| `securegit key add-provider <id>` | Wrap every generation with an additional provider. |
| `securegit key remove-provider <id>` | Refused if it is the last non-custodial provider. |
| `securegit key add-recipient <pubkey> [--label]` | Wrap every generation for a recipient ([08](08-multi-recipient.md)). |
| `securegit key remove-recipient <fingerprint>` | Delete the recipient file. Prints the rotation warning. |
| `securegit key list-recipients` | Fingerprint, label, added-at, added-by, generations covered. |
| `securegit key export-recovery --out <file>` | Recovery file plus a one-time code. |
| `securegit key import-recovery --in <file>` | Rebuild a keyring from file + code. |

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
| `securegit inspect <file>` | Header fields, no key required ([04](04-envelope-format.md)). |

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
| `--repo <path>` | Operate on a repository other than the current directory. |
| `--strict` | `smudge` fails rather than passing ciphertext through ([07](07-unlock-session.md)). |
| `--json` | Machine-readable output for `status`, `verify`, `key list`, `list-recipients`, `inspect`. Goes to stdout; still nothing else does. |
| `--quiet` | Suppress non-error stderr output. |
| `-v`, `--verbose` | Per-file tracing to stderr. Never includes plaintext, key material, or a passphrase. |

## Implementation: `src/cli.ts`

`runCli(io: CliIO): Promise<number>` is the whole surface — every command is a
plain function of an injected `CliIO` (`argv`, `cwd`, `env`, `stdin` as a
pre-read `Buffer`, `home`, and `stdout`/`stderr` as callbacks), never touching
`process.*` directly. `src/bin/securegit.ts` is the only place that does: it
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
pipe." `--json` (not yet implemented) is the intended escape hatch for a
script that wants `status`/`inspect` output on stdout deliberately.

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
| `--json` output validates against its schema | `src/cli.test.ts` | — | 🔲 |
| Unknown flag exits 4 with usage | `src/cli.test.ts` | — | ✅ |
| `init` outside a repository exits 4 | `src/cli.test.ts` | — | ✅ |
| `init` twice exits 4 rather than regenerating a key | `src/cli.test.ts` | — | ✅ |
| `encrypt`/`decrypt` round-trip via stdin and stdout | `src/cli.test.ts` | — | ✅ |
| `encrypt`/`decrypt` produce the same bytes as the filters | `src/cli.test.ts` | — | 🔲 |
| No command prints key material at `--verbose` | `src/cli.test.ts` | — | 🔲 |
| A key object interpolated into a string yields `[redacted]` | `src/crypto.test.ts` | — | ✅ |
| Error messages name the offending path | `src/cli.test.ts` | — | ✅ |
| No error message contains plaintext bytes | `src/cli.test.ts` | `blobs/` | 🔲 |
| `--repo` operates on the named repository | `src/cli.test.ts` | — | 🔲 |
| `protect` keeps the `.securegit/**` exclusion last | `src/install.test.ts` | — | ✅ |
| `install --bin` points the filter at an unpublished build | `src/cli.test.ts` | — | ✅ |
| `verify` exits misconfigured (2) before `init`, and 0 on a correctly configured repository | `src/cli.test.ts` | — | ✅ |
| `verify` exits leaked (5) and writes nothing to stdout | `src/cli.test.ts` | — | ✅ |
| `merge` resolves a clean merge, writes ciphertext to `%A`, exits 0 | `src/cli.test.ts` | — | ✅ |
| `merge` exits 1 on a real conflict, with markers visible once decrypted | `src/cli.test.ts` | — | ✅ |
| `merge` exits 4 when an argument is missing | `src/cli.test.ts` | — | ✅ |
| `merge` exits locked (1) with no current generation to encrypt the result under | `src/cli.test.ts` | — | ✅ |

## Relationship to Other Specs

- [02](02-git-integration.md) — what `install` and `protect` write
- [07](07-unlock-session.md) — `unlock`, `lock`, `status`
- [11](11-filter-process.md) — `filter-process`
- [12](12-diff-merge.md) — `merge`, and why exit 1 has two meanings there
- [13](13-verify.md) — `verify` and exit code 5
