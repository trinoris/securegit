# 11. Long-Running Filter Process

## Overview

`filter.<name>.process`: one process handling every blob in a checkout over a
pkt-line protocol on stdin/stdout, instead of one process per file.

**Status: IMPLEMENTED.** `src/pktline.ts` (pkt-line framing) and
`src/process.ts` (`FilterProcessServer`, the protocol state machine, and the
`process.stdout` write guard) are built, wired into `bin/securegit.ts` as
`securegit filter-process`, and proven against a real `git` binary in
`src/git.integration.test.ts` — `install --process` checked out through, byte
for byte the same as the `clean`/`smudge` form. See "What this pass actually
built" below.

## Core Principle

> The protocol is the only thing on stdin and stdout. A stray `console.log`
> anywhere in the process is a protocol violation that manifests as a corrupted
> file, not as an error.

## Why it is worth doing

A clone of a repository with 400 protected files spawns 400 Node processes.
Node's startup is roughly 40 ms, so that is ~16 seconds of interpreter
initialisation before any cryptography happens, plus 400 scrypt-free but
still-repeated keyring reads.

| | process-per-file | long-running |
|---|---|---|
| Node startups per checkout | one per file | one |
| Keyring read + session validation | per file | once |
| 400-file checkout, measured target | ~18 s | < 1 s |

The saving is entirely process startup and repeated setup. The cryptography is
identical, byte for byte — a repository written by one form is indistinguishable
from one written by the other, and the conformance tests assert exactly that.

## Protocol

Version 2, as documented in `gitattributes(5)`. Packets are pkt-line: a 4-digit
hex length **including the 4 header bytes**, then payload. `0000` is a flush.
Maximum payload is 65516 bytes.

### Handshake

```
   git > git-filter-client
   git > version=2
   git > 0000
        < git-filter-server
        < version=2
        < 0000
```

### Capabilities

```
   git > capability=clean
   git > capability=smudge
   git > capability=delay
   git > 0000
        < capability=clean
        < capability=smudge
        < 0000
```

We advertise `clean` and `smudge` only. **`delay` is deliberately not
advertised**: it exists so a filter can defer blobs it must fetch remotely
(Git LFS), and we have nothing to fetch. Advertising it would add a queue, an
`list_available_blobs` command and a second state machine for no benefit.

### Per blob

```
   git > command=smudge
   git > pathname=config/production.json
   git > 0000
   git > <content packets…>
   git > 0000
        < status=success
        < 0000
        < <content packets…>
        < 0000
        < 0000
```

The trailing empty list is the protocol's way of saying the final status is
unchanged from the one already sent. A filter that fails **after** it has begun
writing content sends the second status as `status=error`; Git discards what it
received.

### Errors

| Situation | Response | Then |
|---|---|---|
| This blob failed, others may work | `status=error` + flush | keep serving |
| Cannot serve anything further (keyring gone, session expired mid-run) | `status=abort` + flush | keep the process alive; Git stops asking |
| Protocol violation | exit non-zero | Git fails the operation |

`status=abort` is the one worth getting right. When a session expires halfway
through a checkout, aborting tells Git to stop, once, instead of producing a
per-file error for the remaining 300 files and burying the cause.

## Implementation notes

1. **stdout is protocol.** The process installs a guard at startup that makes
   `process.stdout.write` throw outside the pkt-line writer. Diagnostics go to
   stderr, which Git passes through to the user.
2. **stdin must be read exactly.** A pkt-line reader that over-reads corrupts
   the next command. Buffer explicitly; never assume a chunk boundary is a
   packet boundary, and never assume a payload arrives in one chunk.
3. **Content arrives in ≤ 65516-byte packets** and must be reassembled before
   decryption — AES-GCM cannot authenticate a prefix, so streaming a partial
   plaintext out is not an option regardless of protocol.
4. **Content is written in ≤ 65516-byte packets.** A single 4-digit length field
   cannot express more.
5. **The key is loaded once**, at handshake, and held for the process lifetime.
   Session expiry is re-checked per blob; expiry mid-run produces `status=abort`
   for `clean` and, per [07](07-unlock-session.md)'s asymmetry, passthrough for
   `smudge`.
6. **The asymmetry is unchanged.** `clean` without a key is `status=error`;
   `smudge` without a key is `status=success` carrying the ciphertext.
7. **Memory.** Git may pipeline requests. Bound in-flight bytes and apply the
   same `maxFileBytes` limit as [04](04-envelope-format.md); a checkout of a
   large repository must not be an out-of-memory kill.

## Choosing between the two forms

`securegit install` writes `clean`/`smudge`. `securegit install --process`
writes `process`. They are mutually exclusive in `.git/config` and `install`
removes the other form when switching, because Git silently prefers `process`
and a leftover `clean` line is a misleading thing to find while debugging.

## What this pass actually built

`src/pktline.ts`: `encodePacket`/`encodePacketList`/`splitContent`, and
`PktLineReader` — a buffering reader that exposes two levels: `readList()`
(every packet up to the next flush, for headers/capabilities/handshake) and
the lower-level `next()` (one decoded packet or flush at a time, for content
draining that needs to react before a list completes). `MAX_PACKET_PAYLOAD`
is 65516, exactly as specified.

- **An empty buffer still encodes to one (empty) packet, not zero.** pkt-line
  can represent a zero-length non-flush packet (`0004`, header only) —
  distinct from `0000` (flush) — so "the file is empty" and "no content was
  sent" stay distinguishable on the wire, which matters once `splitContent`
  is the thing deciding how many packets a blob becomes.
- **`readList()` returns `undefined` for "not ready yet," `[]` for "a list
  that was just a lone flush," never conflating the two** — a caller
  (`process.ts`'s state machine) needs to tell "keep buffering" apart from
  "the capabilities list was legitimately empty."

`src/process.ts`: `FilterProcessServer`, a small explicit state machine
(`handshake` → `capabilities` → alternating `command-header`/
`command-content`) driven entirely by `push(chunk)` calls, plus
`installStdoutGuard` for implementation note 1.

- **Session expiry is re-checked per blob by re-invoking the injected
  `keys()` function before every command, not by caching a key or an expiry
  timestamp from handshake time.** The spec's implementation note 5 reads as
  "load once, hold for the lifetime," but the actual expensive part
  ([00](00-test-plan.md)'s "why it is worth doing" table) is Node's ~40ms
  startup and the *keyring* read, not the session file — `readSession` is
  already a cheap stat-plus-small-JSON-parse, so calling it fresh per blob
  costs nothing next to that, and it's the only way a concurrent `lock` or
  rotation actually gets noticed mid-checkout without the server polling or
  running its own timer.
- **The abort/error distinction is a single boolean, `everUnlockedForClean`,
  not a comparison against a captured "was unlocked at handshake" state.**
  `clean` while locked yields `status=error` the *first* time (this
  repository was never unlocked this run — an ordinary, expected failure);
  every `clean` after at least one has already succeeded yields
  `status=abort` instead, once the key disappears — this is genuinely the
  worse case the error table calls out, worth cutting the checkout short
  over. The flag never resets, so a repeat `clean` after an abort keeps
  reporting abort, not silently reverting to `error`.
- **Found by testing against real `git add`, not from reading the spec: the
  locked-`clean` path originally wrote `status=error`/`abort` without ever
  calling `warn`.** Git's own error for a failed process-filter command is a
  generic `fatal: <path>: clean filter 'securegit' failed`, with none of our
  diagnostic in it — so a silent locked repository reported literally
  nothing about *why*. Fixed by routing the locked case through the same
  `clean()` call (and its thrown `LockedError`, with its existing message)
  that already builds the diagnostic for the one-shot CLI form, instead of
  short-circuiting on `keys.current() === null` before ever calling `clean`.
  Regression-tested in `process.test.ts` and confirmed against a real `git
  add` in `git.integration.test.ts`.
- **Oversized content is rejected packet by packet while draining, using
  `PktLineReader.next()` instead of `readList()`, so a blob that exceeds the
  limit is never assembled into one large buffer just to find out.** Once the
  running total crosses `maxBytes` (`envelope.ts`'s `DEFAULT_MAX_BYTES` when
  the caller didn't override it — the same default `clean`/`smudge` already
  use), every further packet for that blob is discarded immediately rather
  than buffered, and the command resolves to `status=error`. This bounds
  memory *within* the server's own processing of one blob; it does not (and
  cannot) stop the underlying pipe from having delivered whatever the OS
  already buffered in one `push()` call.
- **`runFilterProcess` (`cli.ts`) chains chunks rather than handing each
  `onData` firing to the server independently — found by writing the test
  for it, not anticipated in the design.** `server.push()` does real async
  work per command (the `keys()` re-read above), so two chunks arriving
  close together — which a real pipe can genuinely do — could otherwise
  start processing concurrently against the server's shared mutable parse
  state (the pending command header, in-progress content) and interleave.
  Every chunk is now `.then()`-chained onto the previous one; `onEnd` waits
  for the chain to drain before resolving, so the exit code is never
  reported before every already-received chunk has actually been handled.
- **`filter-process` gets its own entrypoint, `runFilterProcess`, rather than
  a case in `runCli`'s switch.** Every other command shares `CliIO`'s
  contract — a whole-buffer `stdin`, one `stdout`/`stderr` call each, and
  `runCli` resolving exactly once — which a long-running stream fits
  nowhere. `bin/securegit.ts` intercepts `filter-process` before either
  `readStdin()` or `runCli()` runs, wiring real `process.stdin`
  `'data'`/`'end'` events and a guarded `process.stdout.write` to it instead.
- **`command-header` recognizes only `command=clean`/`command=smudge`; any
  other value (or one Git will never actually send, since only these two
  capabilities are advertised) yields `status=error` and the process keeps
  serving** — matching the "unsupported command" row of the error table
  rather than treating it as a protocol violation.

## Test Cases

| Test | Test File | Fixture | Status |
|------|-----------|---------|--------|
| pkt-line encode/decode round-trips, including `0000` | `src/pktline.test.ts` | — | ✅ |
| Reader handles a packet split across chunk boundaries | `src/pktline.test.ts` | — | ✅ |
| Reader handles several packets in one chunk | `src/pktline.test.ts` | — | ✅ |
| Content over 65516 bytes is split on write and rejoined on read | `src/pktline.test.ts` | — | ✅ |
| Malformed length header errors rather than hanging | `src/pktline.test.ts` | — | ✅ |
| Handshake replies exactly as specified | `src/process.test.ts` | — | ✅ |
| Only `clean` and `smudge` are advertised | `src/process.test.ts` | — | ✅ |
| Unsupported command yields `status=error`, process survives | `src/process.test.ts` | — | ✅ |
| `clean` while locked yields `status=error`, and actually warns | `src/process.test.ts` | — | ✅ |
| `smudge` while locked yields `status=success` with ciphertext | `src/process.test.ts` | — | ✅ |
| Session expiry mid-run yields `status=abort` once | `src/process.test.ts` | — | ✅ |
| Process serves 1000 sequential blobs without leaking memory | `src/process.test.ts` | — | ✅ |
| Output is byte-identical to the `clean`/`smudge` form | `src/process.test.ts` | — | ✅ |
| `process.stdout.write` outside the writer throws | `src/process.test.ts` | — | ✅ |
| Real `git checkout`/`add`/`diff`/branch-switch against the process filter round-trips | `src/git.integration.test.ts` | — | ✅ |
| A real locked `git add` fails closed, with our diagnostic reaching Git's own stderr | `src/git.integration.test.ts` | — | ✅ |
| `install --process` removes the `clean`/`smudge` entries | `src/install.test.ts` | — | ✅ |
| Oversized blob is rejected without buffering it whole | `src/process.test.ts` | — | ✅ |
| Chunks that arrive before the previous one finished processing are serialized, not interleaved | `src/cli.test.ts` | — | ✅ |

## Relationship to Other Specs

- [02](02-git-integration.md) — the configuration this replaces
- [04](04-envelope-format.md) — `maxFileBytes`, and why streaming is impossible
- [07](07-unlock-session.md) — the asymmetry, restated in protocol terms
- [10](10-cli-contract.md) — `filter-process` and the stdout rule
