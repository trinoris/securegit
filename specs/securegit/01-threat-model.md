# 01. Threat Model & Trust Boundary

## Overview

`securegit` moves the encryption boundary from the server to the workstation.
The repository leaves the machine as ciphertext and stays ciphertext everywhere
it is subsequently copied — CodeCommit, an S3 backup, a GitHub mirror, a bundle
on a USB stick.

This document states what that buys and, more importantly, **what it does not**.
Every later spec is a consequence of one of the lines below.

**Status: NOT IMPLEMENTED.** Nothing in this package exists yet.

## Core Principle

> The key never crosses the boundary. Everything else does — including every
> byte of repository *structure*. Encryption here protects file **contents**
> and nothing else.

## The boundary

```
                      TRUSTED
   ┌──────────────────────────────────────────┐
   │  workstation                             │
   │                                          │
   │   working tree (plaintext)               │
   │        │                                 │
   │        │  clean ─── encrypt              │
   │        ▼                                 │
   │   .git/objects (ciphertext)              │
   │        ▲                                 │
   │        │  smudge ── decrypt              │
   │                                          │
   │   key material: repo master key,         │
   │   session cache, identity private key    │
   └────────────────────┬─────────────────────┘
                        │  ← the boundary
   ════════════════════ │ ═══════════════════════
                        │
   ┌────────────────────▼─────────────────────┐
   │  UNTRUSTED                               │
   │  CodeCommit · S3 · GitHub mirror ·       │
   │  bundles · backups · anyone who obtains  │
   │  a clone                                 │
   │                                          │
   │  holds: ciphertext + all metadata        │
   │  holds: no key material, ever            │
   └──────────────────────────────────────────┘
```

The boundary is drawn at the *process*, not the network. A clone written to an
external disk is on the untrusted side. So is a CI runner, unless that runner
has been given a key — at which point it is a trusted machine and must be
treated as one ([07](07-unlock-session.md)).

## Adversaries

| | Adversary | Holds | Wants | Addressed by |
|---|---|---|---|---|
| A1 | Cloud storage operator (AWS) | ciphertext, all metadata, all history | file contents | the whole design |
| A2 | Mirror or backup host | same as A1 | same | same |
| A3 | Thief of a repository copy | ciphertext + `.git` | file contents | [05](05-key-hierarchy.md) |
| A4 | Thief of the *workstation*, powered off | above + wrapped keyfile | the passphrase | scrypt cost, [06](06-key-provider-port.md) |
| A5 | Departed collaborator | history up to their removal | future contents | [09](09-rotation-recovery.md) |
| A6 | Someone who can push to the repo | write access | to make a future commit land in plaintext | [16](16-adversarial-integrity.md) |
| A7 | Someone who can push to the repo | write access | to move a ciphertext blob to a path where its plaintext is dangerous | [16](16-adversarial-integrity.md) |

**A6 and A7 are the two that surprise people.** Encryption at rest says nothing
about an adversary who can write to the repository. `.gitattributes` is an
ordinary tracked file; deleting a line from it causes the *next* commit of that
path to be stored in plaintext, silently, on a colleague's machine. That is a
supply-chain problem, not a cryptography problem, and [13](13-verify.md) exists
to detect it.

## Explicitly not in scope

1. **An attacker with code execution on an unlocked workstation.** They have the
   plaintext working tree. Nothing here helps.
2. **Repository integrity and authenticity.** AES-256-GCM authenticates each
   blob individually, which stops bit-flipping but not blob substitution,
   history rewriting or force-pushing. Use signed commits and protected
   branches; they are orthogonal and both are still required.
3. **Availability.** An adversary who deletes the remote has deleted the remote.
4. **Metadata.** Paths, sizes, commit messages, authorship, timestamps, branch
   names and the shape of the commit graph are all visible to A1. This is not a
   gap to be closed later; it is inherent to storing content in Git objects.
   [14](14-metadata-leakage.md) enumerates it, because a threat model that lets
   the reader believe otherwise is worse than no threat model.

## The requirement that rules out KMS as a root

The requirement that motivates this package is:

> AWS must not possess the ability to decrypt the repository.

A CodeCommit repository encrypted with a KMS CMK fails that requirement by
construction: AWS performs the decryption, so AWS can perform the decryption.
The account owner's IAM policy is the only thing standing in the way, and IAM is
administered by the same party.

Therefore **KMS may never be the sole root of the key hierarchy.** It may appear
as one *recipient* among several ([08](08-multi-recipient.md)) — an escrow path
the organisation deliberately opts into — but a repository whose only unwrap
path is a KMS key has re-created the property it set out to remove.

The same test applies to any candidate root: *if this party is compelled, can
they produce plaintext?* Passphrase-wrapped keyfile, TPM-sealed key and PIV
smartcard all answer no. KMS, SSO-gated secret managers and "encrypted with the
CI provider's secret store" all answer yes.

## What the untrusted side actually sees

For a repository containing `config/production.json`:

```
path          config/production.json      ← visible
size          1,184 bytes (± envelope)    ← visible
content       \0SECUREGIT\0…              ← opaque
changed-in    a3f9c21, 8b0e114, …         ← visible
changed-by    author, email, timestamp    ← visible
identical-to  the blob at v2.1.0          ← visible ([03](03-determinism.md))
```

A reviewer who concludes from this that the repository contains production
database credentials is correct, and no amount of content encryption will change
that. If the *existence* of the secret is itself sensitive, the file does not
belong in this repository at all.

## Test Cases

| Test | Test File | Fixture | Status |
|------|-----------|---------|--------|
| Pushed pack contains no plaintext byte from any protected file | `src/git.integration.test.ts` | `repo-protected/` | 🔲 |
| `.git/objects` contains no plaintext after `add`+`commit` | `src/git.integration.test.ts` | `repo-protected/` | ✅ |
| A bundle of the repo decrypts to nothing without the key | `src/git.integration.test.ts` | `repo-protected/` | 🔲 |
| Clone by a keyless third party yields ciphertext in the worktree | `src/git.integration.test.ts` | `repo-protected/` | ✅ |
| Removing the `.gitattributes` line is reported by `verify` | `src/verify.test.ts` | `attributes/` | 🔲 |
| Session cache and keyring are never written inside the repo | `src/config.test.ts` | — | 🔲 |

## Relationship to Other Specs

- [02](02-git-integration.md) — the mechanism that enforces this boundary
- [06](06-key-provider-port.md) — where the root key is allowed to live
- [13](13-verify.md) — detecting a boundary that has stopped holding
- [14](14-metadata-leakage.md) — the residue this model does not cover
- [16](16-adversarial-integrity.md) — A6 and A7 in full
