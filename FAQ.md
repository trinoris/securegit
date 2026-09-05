# FAQ

## Revoking access — what does `key rotate` actually do? What's an RMK? Who's allowed to revoke whom?

### RMK

**RMK = Repository Master Key** — a 32-byte secret, one per "generation"
(generation 1, 2, 3…). It's the root of the whole per-file encryption tree:

```
RMK ──HKDF("securegit/tag/v1")──▶ K_tag ──HMAC(plaintext)──▶ tag
RMK ──HKDF("securegit/dek/v1", salt=tag)──▶ DEK ──AES-256-GCM──▶ ciphertext
```

It never exists in plaintext outside a workstation's memory. At rest it
only ever exists **wrapped**: once for your local passphrase (in
`~/.securegit/repos/<repoId>/keyring.json`), and once more per recipient's
X25519 public key (in `.securegit/recipients/<fingerprint>.json`,
committed to the repo). Full derivation tree and every HKDF label:
[specs/securegit/05-key-hierarchy.md](specs/securegit/05-key-hierarchy.md).

### Revoking access = generating a new RMK ("rotation"), not deleting the old one

`key rotate` does exactly this: generates a brand-new 32-byte RMK, assigns
it the next generation number, and **keeps every earlier RMK forever** —
old commits were encrypted under old generations, and they have to stay
decryptable. Nothing about rotation touches history; it only changes what
happens to the *next* commit.

### Why rotating revokes someone — it's omission, not force

Rotation wraps the new RMK for **whoever is currently listed** in
`.securegit/recipients/` (plus your local passphrase). The actual
"leaving" flow is three steps, in order:

```sh
securegit key remove-recipient <fingerprint>   # deletes their recipient file
securegit key rotate                            # new RMK, wrapped for whoever's left
securegit reencrypt                             # re-writes tracked files under the new generation
```

Step 1 deletes their file, so step 2's wrap loop (`readdir(.securegit/
recipients/)`) never iterates over them — they simply don't receive the
new generation's key. There's no active "kick them out" mechanism; it's
that the guest list for the *next* key doesn't include them.

**What this does and doesn't undo:**
- Everything committed under generation ≤3 stays readable to them forever
  — they already had that key, and cryptography can't retroactively
  un-decrypt something. (Their old recipient file is even still sitting
  in git history, so they can `git log`/checkout an old commit and
  re-derive it if they ever lost it.)
- Everything written under generation 4+ (after `reencrypt`) is unreadable
  to them.

That's the "forward-acting, not retroactive" caveat referenced in the
[README](README.md#why-this-matters). Full "leaving" flow and the
recovery-code caveats: [specs/securegit/09-rotation-recovery.md](specs/securegit/09-rotation-recovery.md).

### The ACL question — there isn't one

**There is no owner role, and no ACL, inside securegit's key model at
all.** It's purely capability-based: whoever currently holds a key that
unwraps the *current* generation — your local passphrase, or any
recipient's private key — can do **everything**: add a recipient, remove
a recipient, rotate, reencrypt. `cmdKeyRotate`/`cmdKeyRemoveRecipient`
check only "is this session unlocked against the current generation,"
never "is this identity special."

So concretely: **any recipient can remove any other recipient (including
whoever originally set the repo up) and rotate** — securegit itself won't
stop them. `key rotate --confirm-recipients <n>` is a *safety* gate
(forces you to type the current recipient count so you notice if someone
was added/removed since you last looked), not a permission gate.

The actual access control comes from *outside* this key model entirely:
- **Git's own push access** — you need write access to the repo to commit
  a `remove-recipient`/rotation at all.
- **Code review** — a recipient change is an ordinary, attributed commit
  (`addedBy` records which identity did it); `verify --access` and
  `key list-recipients` make "who can read this" answerable from history,
  not from memory.

This is a deliberate design choice — [specs/securegit/08-multi-recipient.md](specs/securegit/08-multi-recipient.md):
"no key server, because a key server is a party that can be compelled and
an availability dependency." It's also exactly the gap
[T5 in 16-adversarial-integrity.md](specs/securegit/16-adversarial-integrity.md)
is about: a hostile collaborator with ordinary push access can add
themselves as a recipient the same legitimate way anyone else would — the
only defense is human review of that commit, never an in-band ACL. The
chaos sandbox's `pr-gated` orchestrator
([specs/chaotests/03-orchestrator.md](specs/chaotests/03-orchestrator.md))
is built around exactly this: it never tries to judge whether a recipient
*should* be added — it just refuses to auto-merge *any* recipient-file
change, full stop, forcing a human to look.
