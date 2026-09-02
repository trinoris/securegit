# 08. Multi-Recipient Sharing

## Overview

Getting the repository master key onto a second workstation, or into a
colleague's hands, without a server that holds plaintext keys and without
sending a secret over a channel either of you would rather not trust.

**Status: NOT IMPLEMENTED.**

## Core Principle

> Sharing is public-key encryption of the master key, stored **in the repository
> itself**. There is no key server, because a key server is a party that can be
> compelled ([01](01-threat-model.md)) and an availability dependency for a tool
> whose entire point is working from a stolen laptop on a plane.

## Identities

Each person — and each machine that needs its own revocable access — has an
X25519 keypair.

```
~/.securegit/identity.json
{
  "version": 1,
  "fingerprint": "7c1e4a09b2d5f836",
  "publicKey":   "SGPUB1<base32>",
  "label":       "laptop",
  "wrapped":     { "provider": "passphrase-file", "payload": { … } }
}
```

The private key is wrapped by a key provider ([06](06-key-provider-port.md)),
the same machinery that protects an RMK. The public form is a checksummed
string safe to paste into a chat message, a ticket, or a README:

```
fingerprint  7c1e4a09b2d5f836   = SHA-256("securegit/identity/v1" ‖ pubkey)[0..8]
public key   SGPUB1<Crockford base32 of 32 key bytes ‖ 4-byte checksum>
```

The checksum catches transcription errors before they become a confusing
decryption failure. It is not a signature and proves nothing about origin — see
*Trust on first use* below.

## Wrapping

For each generation, for each recipient:

```
   eph            = X25519 keypair, fresh per (recipient, generation)
   shared         = X25519(ephPriv, recipientPub)
   wrapKey        = HKDF-SHA256(shared,
                                salt = ephPub ‖ recipientPub,
                                info = "securegit/recipient/v1")
   nonce          = 12 zero bytes
   payload        = AES-256-GCM(wrapKey, nonce, RMK,
                                aad = repoId ‖ generation ‖ fingerprint)
```

The zero nonce is safe and deliberate: `wrapKey` is derived from a fresh
ephemeral key, so it is used for exactly one message. A random nonce here would
add a field and no security. Both public keys are in the salt so a wrapping
cannot be replayed against a different recipient, and the AAD binds it to one
repository and one generation.

This is the same construction `age` uses for X25519 recipients, deliberately —
it is well-reviewed, and a reader who knows `age` can audit it by inspection.

## In the repository

```
.securegit/
├── config.json                  repoId, format, bindPath
└── recipients/
    ├── 7c1e4a09b2d5f836.json    laptop
    ├── b30f92ac1e7d4405.json    desktop
    └── e4a7c0912f38bb61.json    ci-build
```

```json
{
  "version": 1,
  "fingerprint": "7c1e4a09b2d5f836",
  "publicKey": "SGPUB1…",
  "label": "laptop",
  "addedAt": "2026-09-01T10:04:11Z",
  "addedBy": "b30f92ac1e7d4405",
  "keys": {
    "1": { "ephemeral": "…", "payload": "…" },
    "2": { "ephemeral": "…", "payload": "…" },
    "3": { "ephemeral": "…", "payload": "…" }
  }
}
```

These files are **committed, tracked, and excluded from filtering**
([02](02-git-integration.md)). They contain nothing secret: an ephemeral public
key and a ciphertext only the holder of the corresponding private key can open.
Storing them in the repository means the answer to "how do I get the key on my
new laptop" is `git clone` followed by one command, with no infrastructure.

## Flows

### Joining

```
  new machine                          existing machine
  ───────────                          ────────────────
  securegit identity init
  securegit identity show   ──pubkey──▶
                                        securegit key add-recipient \
                                            SGPUB1… --label laptop
                                        git commit .securegit/recipients
                                        git push
  git pull
  securegit unlock              ← finds its own fingerprint, unwraps every
  git rm --cached -r -q .         generation, writes a local keyring
  git checkout HEAD -- .
```

Not `git checkout --force .` — confirmed in [07](07-unlock-session.md) and
[15](15-failure-modes.md) that Git's stat-cache skips rewriting a path whose
worktree content already matches the index, `--force` or not, so `smudge`
never reruns on an already-checked-out ciphertext file. `git rm --cached`
first, then a real re-checkout from `HEAD`, is what actually works.

`unlock` on a machine with no keyring looks for `.securegit/recipients/<own
fingerprint>.json`, unwraps each generation with the identity key, and writes a
local keyring wrapped by that machine's own provider. From then on the identity
key is only needed when a new generation is added.

### Leaving

```
securegit key remove-recipient 7c1e4a09b2d5f836
securegit key rotate
securegit reencrypt
```

All three steps, in that order. **Removing a recipient does not un-share
anything.** They have the repository, they had generation 3's key, and every
blob committed under generation 3 stays readable to them forever. Removal stops
them receiving generation 4; rotation creates generation 4; re-encryption moves
the current content onto it.

`remove-recipient` prints this, and `key rotate` refuses to run against a
repository with uncommitted changes so the re-encryption is a reviewable commit
rather than a surprise.

## Trust on first use

A public key pasted into a chat window is a public key pasted into a chat
window. `add-recipient` prints the fingerprint and requires confirmation, but
nothing here proves the key belongs to the person you think it does. An
adversary who can modify the message can substitute their own.

Mitigations, in the order they are worth doing:

1. **Confirm the fingerprint over a second channel.** Sixteen hex characters,
   read aloud, is the whole protocol. This is enough for the threat model.
2. **Commit signing.** The `add-recipient` commit is signed, so adding a
   recipient is attributable and reviewable in the history like any other
   change. `addedBy` records which identity performed it.
3. Not doing: a web of trust, or a signature chain over recipient files. It
   would be real work, and the fingerprint-over-a-second-channel step it
   replaces takes ten seconds.

`verify` ([13](13-verify.md)) reports the current recipient list with
fingerprints and the commit that added each, so "who can read this repository"
is answerable from the history rather than from memory.

## Test Cases

| Test | Test File | Fixture | Status |
|------|-----------|---------|--------|
| Wrap/unwrap round-trips for a recipient | `src/recipients.test.ts` | `identities/` | 🔲 |
| A different identity cannot unwrap | `src/recipients.test.ts` | `identities/` | 🔲 |
| Wrapping bound to `repoId` fails elsewhere | `src/recipients.test.ts` | — | 🔲 |
| Wrapping bound to `generation` fails on another generation | `src/recipients.test.ts` | — | 🔲 |
| Two wraps for one recipient use different ephemeral keys | `src/recipients.test.ts` | — | 🔲 |
| Public key encoding round-trips | `src/identity.test.ts` | — | 🔲 |
| A one-character corruption fails the checksum | `src/identity.test.ts` | — | 🔲 |
| Fingerprint is derived from the public key, not the file | `src/identity.test.ts` | — | 🔲 |
| `add-recipient` wraps every existing generation | `src/recipients.test.ts` | — | 🔲 |
| `unlock` bootstraps a keyring from a recipient file alone | `src/git.integration.test.ts` | `repo-protected/` | 🔲 |
| End-to-end join on a second identity, then decrypt | `src/git.integration.test.ts` | `identities/` | 🔲 |
| `remove-recipient` deletes the file and warns about history | `src/recipients.test.ts` | — | 🔲 |
| Removed recipient can still read pre-rotation blobs | `src/git.integration.test.ts` | `identities/` | 🔲 |
| Removed recipient cannot read post-rotation blobs | `src/git.integration.test.ts` | `identities/` | 🔲 |
| Recipient files are never filtered | `src/install.test.ts` | — | 🔲 |
| Removing the last recipient is refused | `src/recipients.test.ts` | — | 🔲 |

## Relationship to Other Specs

- [05](05-key-hierarchy.md) — what is being wrapped, and the generation model
- [06](06-key-provider-port.md) — what protects the identity private key
- [07](07-unlock-session.md) — machine identities for CI
- [09](09-rotation-recovery.md) — why removal requires rotation
- [16](16-adversarial-integrity.md) — a hostile `add-recipient` commit
