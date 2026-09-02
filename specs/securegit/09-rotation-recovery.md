# 09. Rotation & Recovery

## Overview

Adding a key generation, moving content onto it, and the offline path back in
when every workstation is gone.

**Status: NOT IMPLEMENTED.**

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
  `aad = repoId ‖ format`.
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
256 bits of entropy in 52 characters, with a checksum group.

### Import

```
securegit key import-recovery --in proj.recovery.txt
```

Prompts for the code, decrypts, and writes a fresh local keyring wrapped by a
newly chosen provider. The machine is then a full holder: it can rotate, add
recipients, and re-export.

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
*event* — timestamp, identity, and a random export id — in
`.securegit/recovery-log.json`, committed. Not the code, not the file: just the
fact that an export happened, so the answer to "who can read this repository" is
"these recipients, plus whoever holds the two exports taken in January".

## Test Cases

| Test | Test File | Fixture | Status |
|------|-----------|---------|--------|
| `rotate` adds a generation and keeps all earlier ones | `src/keyring.test.ts` | — | ✅ |
| `rotate` refuses on a dirty working tree | `src/cli.test.ts` | `repo-protected/` | 🔲 |
| `rotate` refuses when locked | `src/cli.test.ts` | — | 🔲 |
| `rotate` wraps the new generation for every provider | `src/keyring.test.ts` | — | ✅ |
| `rotate` wraps the new generation for every recipient | `src/recipients.test.ts` | — | 🔲 |
| `rotate` invalidates the session | `src/session.test.ts` | — | 🔲 |
| Blobs from every generation decrypt after two rotations | `src/git.integration.test.ts` | `repo-protected/` | ✅ |
| `reencrypt --dry-run` stages nothing | `src/cli.test.ts` | `repo-protected/` | 🔲 |
| `reencrypt` moves every protected file to `current` | `src/git.integration.test.ts` | `repo-protected/` | 🔲 |
| `reencrypt` leaves history untouched | `src/git.integration.test.ts` | `repo-protected/` | 🔲 |
| `reencrypt` is a no-op when everything is current | `src/cli.test.ts` | — | 🔲 |
| Recovery export/import round-trips every generation | `src/recovery.test.ts` | — | 🔲 |
| Recovery file alone does not decrypt | `src/recovery.test.ts` | — | 🔲 |
| Wrong recovery code fails cleanly | `src/recovery.test.ts` | — | 🔲 |
| Recovery code is accepted lowercase, unspaced, and with `O`/`0` confused | `src/recovery.test.ts` | — | 🔲 |
| Recovery code checksum rejects a single-character error | `src/recovery.test.ts` | — | 🔲 |
| Recovery file bound to `repoId` fails against another repo | `src/recovery.test.ts` | — | 🔲 |
| `import-recovery` produces a keyring able to rotate | `src/recovery.test.ts` | — | 🔲 |
| `export-recovery` appends to the committed recovery log | `src/recovery.test.ts` | — | 🔲 |
| The recovery code never appears in any file written | `src/recovery.test.ts` | — | 🔲 |

## Relationship to Other Specs

- [05](05-key-hierarchy.md) — generations and why old ones are kept
- [06](06-key-provider-port.md) — the `recovery-code` provider
- [08](08-multi-recipient.md) — removal requires rotation to mean anything
- [13](13-verify.md) — the "who can read this" report and its blind spot
- [16](16-adversarial-integrity.md) — theft of a recovery file
