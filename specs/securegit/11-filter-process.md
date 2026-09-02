# 11. Long-Running Filter Process

## Overview

`filter.<name>.process`: one process handling every blob in a checkout over a
pkt-line protocol on stdin/stdout, instead of one process per file.

**Status: NOT IMPLEMENTED.** `clean`/`smudge` is the correct first
implementation; this is the same contract, faster.

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

## Test Cases

| Test | Test File | Fixture | Status |
|------|-----------|---------|--------|
| pkt-line encode/decode round-trips, including `0000` | `src/pktline.test.ts` | — | 🔲 |
| Reader handles a packet split across chunk boundaries | `src/pktline.test.ts` | — | 🔲 |
| Reader handles several packets in one chunk | `src/pktline.test.ts` | — | 🔲 |
| Content over 65516 bytes is split on write and rejoined on read | `src/pktline.test.ts` | — | 🔲 |
| Malformed length header errors rather than hanging | `src/pktline.test.ts` | — | 🔲 |
| Handshake replies exactly as specified | `src/process.test.ts` | — | 🔲 |
| Only `clean` and `smudge` are advertised | `src/process.test.ts` | — | 🔲 |
| Unsupported command yields `status=error`, process survives | `src/process.test.ts` | — | 🔲 |
| `clean` while locked yields `status=error` | `src/process.test.ts` | — | 🔲 |
| `smudge` while locked yields `status=success` with ciphertext | `src/process.test.ts` | — | 🔲 |
| Session expiry mid-run yields `status=abort` once | `src/process.test.ts` | — | 🔲 |
| Process serves 1000 sequential blobs without leaking memory | `src/process.test.ts` | — | 🔲 |
| Output is byte-identical to the `clean`/`smudge` form | `src/process.test.ts` | `vectors/` | 🔲 |
| `process.stdout.write` outside the writer throws | `src/process.test.ts` | — | 🔲 |
| Real `git checkout` against the process filter round-trips | `src/git.integration.test.ts` | `repo-protected/` | 🔲 |
| `install --process` removes the `clean`/`smudge` entries | `src/install.test.ts` | — | 🔲 |
| Oversized blob is rejected without buffering it whole | `src/process.test.ts` | — | 🔲 |

## Relationship to Other Specs

- [02](02-git-integration.md) — the configuration this replaces
- [04](04-envelope-format.md) — `maxFileBytes`, and why streaming is impossible
- [07](07-unlock-session.md) — the asymmetry, restated in protocol terms
- [10](10-cli-contract.md) — `filter-process` and the stdout rule
