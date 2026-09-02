# 03. Determinism & Convergent Encryption

## Overview

The single constraint that shapes the cryptography. A clean/smudge filter is not
free to be a normal encryption function, because Git compares its output to
decide whether a file has changed.

**Status: IMPLEMENTED.** This was the first thing built and the first thing
tested, because every other design choice follows from it — `src/crypto.ts`'s
keyed convergent nonce, proven in `src/crypto.test.ts` and end to end in
`src/git.integration.test.ts` (`git status` clean immediately after commit,
after branch switches, after `stash`/`stash pop`, after re-adding an
unchanged file). `src/vectors.test.ts` and `tests/fixtures/vectors/v1.json`
close the known-answer-vector row: six cases (empty, one byte, 4095 bytes, a
UTF-8 BOM, CRLF content, `bindPath`) generated once from `seal()`/`unseal()`
as they exist today, frozen as hex, and asserted byte-for-byte on every run —
a failure there means the wire format moved, not that a test assumption
drifted. `src/crypto.test.ts` also gained a dedicated LF/CRLF round-trip
check: the primitives operate on raw bytes and do no text-mode normalization
of their own, which is what makes `-text` on protected paths ([02](02-git-integration.md))
necessary rather than redundant. And `src/bin.integration.test.ts` proves
`clean` byte-identical across two separate `node` processes given the same
stdin — the process-boundary version of the same purity claim.

## Core Principle

> `clean` must be a **pure function of its input**. Same plaintext in, same
> ciphertext out — on every machine, in every process, forever. Randomised
> encryption is not merely inconvenient here; it is incorrect.

## Why textbook AES-GCM breaks Git

AES-256-GCM requires a nonce that is never reused under a given key, and the
standard way to satisfy that is to draw 12 random bytes per message. Do that in
`clean` and:

```
$ git status
nothing to commit, working tree clean

$ git status          # again, no edit
	modified:   .env

$ git checkout .
$ git status
	modified:   .env
```

Git records `stat` information for files it has just checked out, so the first
`status` is answered from the cache. Any operation that invalidates that cache —
`git add`, `git stash`, `git diff`, a branch switch, `touch`, a different
machine, a fresh clone — re-runs `clean`, gets different bytes, computes a
different blob hash, and concludes the file was edited.

The consequences compound:

| Operation | With a random nonce |
|---|---|
| `git status` | permanently dirty, uncorrectable by the user |
| `git add .` | stages a "change" on every unmodified protected file |
| `git commit` | every commit rewrites every protected blob |
| `git diff` | always reports a difference, always meaningless |
| merge / rebase | conflicts on files nobody touched |
| repository size | grows by the full size of every protected file, per commit |
| `git stash` / `git checkout -- .` | cannot discard changes, because there are none to discard |

The last row is the one that ends the argument. A user cannot get to a clean
tree, so no workflow that depends on a clean tree works — which is most of them.

## The scheme: keyed convergent encryption

Derive the nonce from the plaintext, under a secret key.

```
   K_tag  = HKDF(RMK, info = "securegit/tag/v1")          ← 32 bytes, secret

   tag    = HMAC-SHA256(K_tag, [path ‖ 0x00 ‖] plaintext) ← 32 bytes
   nonce  = tag[0..12)
   DEK    = HKDF(RMK, salt = tag, info = "securegit/dek/v1" [‖ path])

   ciphertext ‖ authtag = AES-256-GCM(DEK, nonce, plaintext, aad = header)
```

`tag` is stored in the envelope, because decryption needs it to re-derive the
DEK ([04](04-envelope-format.md)). The bracketed `path` terms are included only
when `bindPath` is enabled ([05](05-key-hierarchy.md)).

### Why this is nonce-safe

The requirement is that a `(key, nonce)` pair is never reused for two different
plaintexts. Here both the key and the nonce are derived from `tag`, and `tag` is
an HMAC of the plaintext:

- Same plaintext → same `tag` → same DEK **and** same nonce → byte-identical
  ciphertext. This is the point.
- Different plaintext → different `tag` (unless HMAC-SHA256 collides) →
  **different DEK**. The nonce is reused only in the sense that a different key
  is being used with it, which is not nonce reuse.

Deriving the DEK from `tag` rather than fixing it per repository is what makes
this safe. A scheme that used one repository-wide AES key with a
content-derived nonce would be one 96-bit truncated-HMAC collision away from a
catastrophic GCM nonce reuse; this one degrades to a full 256-bit collision, and
even then the two colliding messages get different keys.

## What convergence costs

State it plainly, because it is a real and permanent loss:

1. **Equality is visible.** An observer with only the ciphertext can tell that
   two blobs hold identical plaintext — across paths, across branches, across
   the whole history. They learn *that* `config/staging.json` and
   `config/production.json` are the same file, never *what* either says.
2. **Reversion is visible.** If a file returns to a previous content, the blob
   hash returns with it. `git log` on that path shows the shape of the change
   history: edited, edited, reverted.
3. **Length is visible**, as it is under any content-preserving scheme, minus a
   fixed envelope overhead. See [14](14-metadata-leakage.md).

What convergence does **not** cost — and this is why the HMAC is keyed:

4. **Confirmation-of-file is prevented.** In unkeyed convergent encryption
   (content-hash-as-key, as used by deduplicating backup systems) an adversary
   who guesses a plaintext can encrypt it and match the ciphertext, confirming
   the guess. Here `tag` depends on `K_tag`, which the adversary does not have,
   so a guessed plaintext produces nothing checkable. A dictionary attack over
   likely `.env` files gains an adversary exactly nothing.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Random nonce, store it out of band (git notes, a sidecar index) | The sidecar has to be committed to survive a clone, so it is part of the blob content by another name — and it would itself change on every commit. Solves nothing, adds a consistency problem. |
| Random nonce, teach Git to ignore the difference | There is no such mechanism. `core.trustctime`, `assume-unchanged` and friends suppress *detection*, not the differing blob hashes that reach the object database. |
| AES-SIV / AES-GCM-SIV (nonce-misuse-resistant) | The right primitive in principle, and deterministic by construction. Not in Node's stdlib, so it means a native or vendored dependency in a security-critical path. Reconsider if it lands in `node:crypto`; the envelope reserves an algorithm id for it. |
| Encrypt only on `push` | Not a Git extension point. `.git/objects` would hold plaintext, which is precisely the thing [01](01-threat-model.md) is about. |

## Determinism has to hold across machines

Same plaintext, same key, same ciphertext — on Windows, WSL, macOS and a CI
container, across tool versions. That is a portability requirement, not just a
cryptographic one:

- **Paths** are normalised to forward slashes and compared as raw UTF-8 bytes
  before entering any derivation. A Windows checkout must derive what a Linux
  checkout derived.
- **No locale, time, hostname, username, process id, environment or filesystem
  metadata** may enter a derivation. The only inputs are the key, the plaintext
  and (optionally) the normalised path.
- **The format is versioned** and old versions stay decryptable forever
  ([04](04-envelope-format.md)). A change to any derivation label is a new
  algorithm id, never an edit to an existing one.
- **Known-answer vectors are committed** in `tests/fixtures/vectors/`. A change
  that alters any of them is a format break, and CI should say so in those
  words.

## Test Cases

| Test | Test File | Fixture | Status |
|------|-----------|---------|--------|
| `clean` of the same input twice is byte-identical | `src/filter.test.ts` | — | ✅ |
| `clean` in two separate processes is byte-identical | `src/bin.integration.test.ts` | — | ✅ |
| Different plaintexts derive different DEKs | `src/crypto.test.ts` | — | ✅ |
| A one-bit plaintext change changes `tag` and the whole ciphertext | `src/crypto.test.ts` | — | ✅ |
| Known-answer vectors match the committed fixtures | `src/vectors.test.ts` | `vectors/` | ✅ |
| Round-trip is stable across `\n` and `\r\n` content | `src/crypto.test.ts` | — | ✅ |
| Windows-style path input normalises to the POSIX derivation | `src/crypto.test.ts` | — | ✅ |
| `git status` is clean immediately after `commit` | `src/git.integration.test.ts` | `repo-protected/` | ✅ |
| `git status` is clean after `checkout` of another branch and back | `src/git.integration.test.ts` | `repo-protected/` | ✅ |
| Committing an unchanged tree twice produces no new blob | `src/git.integration.test.ts` | `repo-protected/` | ✅ |
| `git stash` / `git stash pop` leaves a clean tree | `src/git.integration.test.ts` | `repo-protected/` | ✅ |
| Identical plaintext at two paths yields identical blobs when `bindPath` is off | `src/crypto.test.ts` | — | ✅ |
| Identical plaintext at two paths yields different blobs when `bindPath` is on | `src/crypto.test.ts` | — | ✅ |

## Relationship to Other Specs

- [02](02-git-integration.md) — the filter contract this constrains
- [04](04-envelope-format.md) — where `tag` is stored and how versions are pinned
- [05](05-key-hierarchy.md) — `K_tag`, the DEK derivation and `bindPath`
- [14](14-metadata-leakage.md) — blob equality as an observable
- [16](16-adversarial-integrity.md) — what an adversary does with equality
