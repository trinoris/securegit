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

## Weak point: "review the attributed history" assumes the attribution is real. It isn't, today.

The answer above leans on git history being trustworthy: "a recipient
change is an ordinary, attributed commit... answerable from history, not
from memory." That's true only if the attribution itself can't be
forged. Right now, it can be, trivially, and this is a genuine,
currently unaddressed gap — documented here rather than silently assumed
away.

### The gap, precisely

Every piece of "who did this" in this project is a plain string, written
by whoever ran the command, from local state they fully control — none
of it is cryptographically proven:

- `GIT_AUTHOR_NAME`/`GIT_COMMITTER_NAME` — set by `git config user.name`.
  No proof required; anyone can type anyone's name.
- `addedBy` in a recipient file — read from the *local* `identity.json`
  at the moment `add-recipient` runs. `identity.json` is itself
  self-generated and self-declared; nothing else in the system vouches
  for the fingerprint it claims.

So "the real access control is git push access plus code review" (the
answer above) is only as strong as the history being reviewed actually
says who did what — and today, it's whatever string the pusher felt like
writing.

### Why this is worse than "an external attacker forges a name"

Because access here is symmetric — **any current recipient can do
anything** (see the ACL section above; there is no owner) — this isn't
only a risk from someone *outside* the recipient list. A genuine
malicious insider, someone with real push access, could remove a
*different* recipient, rotate, and have every resulting commit say
whatever name they like: nobody's in particular, or a name chosen
specifically to misdirect whoever investigates later. The cost of this
gap isn't paid at attack time — it's paid at the one moment this
project's entire access-control story depends on: reconstructing what
happened, after something already has.

This came up initially as a narrower question — could an attacker
hijack another collaborator's own `feature/x` branch under the chaos
sandbox's `pr-gated` workflow, since nothing today restricts a branch
name to its "owner"? That's real too, but it turned out to be one
instance of the broader gap above, not a separate one: the sandbox's
review is content-based (it checks *what* changed), and content-based
checks don't get weaker from a hijacked branch — what actually breaks is
attribution, project-wide, not just inside one Docker sandbox.

### The fix, stated plainly, not yet built

Git commit signing (`git commit -S`) cryptographically binds a commit to
a private key, not a string — verifiable offline (`git verify-commit`)
by anyone holding the signer's public key, and **orthogonal to git's own
push transport entirely**: it works identically over `git://`, `https`,
anything, and requires no SSH server, no `authorized_keys`, no change to
how anyone connects. `specs/securegit/08-multi-recipient.md` already
names commit signing as a mitigation for exactly this. Nothing today
enforces or checks it.

Deliberately not started without scoping it first:

- **The simple version** — require every commit reaching `master` to be
  signed by *some* key on a maintained allow-list (a server-side,
  outside-the-repo trust anchor) — gives back real, provable attribution,
  and mirrors "require signed commits" branch protection GitHub/GitLab/
  Bitbucket already offer natively. Most of the value, least the cost.
- **What it doesn't cover on its own**: one allowed signer pushing under
  a *different* branch name (the original hijack question) needs a
  further, trust-on-first-commit "pin this branch to the key that first
  committed to it" step on top — its own honest limits (a squatted branch
  name pins the wrong key from round one) discussed in
  [specs/chaotests/03-orchestrator.md](specs/chaotests/03-orchestrator.md).
- **securegit's existing identity keys can't do this.** `identity.ts`'s
  X25519 keypairs are Diffie-Hellman keys, used only for wrapping the
  RMK — they cannot sign. This needs a genuinely separate keypair per
  identity, not a reuse of what already exists.

Tracked here as an open, documented gap.
