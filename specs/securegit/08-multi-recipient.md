# 08. Multi-Recipient Sharing

## Overview

Getting the repository master key onto a second workstation, or into a
colleague's hands, without a server that holds plaintext keys and without
sending a secret over a channel either of you would rather not trust.

**Status: MOSTLY IMPLEMENTED.** `src/identity.ts`, `src/recipients.ts`, and
the join-flow CLI (`identity init`/`show`, `key add-recipient`/
`remove-recipient`, and `unlock`'s recipient-file bootstrap path) are all
built and tested, including two end-to-end proofs that a second identity can
join and decrypt with zero shared secrets ever leaving the repository — one
CLI-level (two identities against one shared working directory) and one
against a real clone/push/pull in `src/git.integration.test.ts`, which also
surfaced a genuine ordering constraint (F21 below). `key rotate`/`reencrypt`
([09](09-rotation-recovery.md)), `verify --access` and `key list-recipients`
([10](10-cli-contract.md), [13](13-verify.md)) are all built now too — a
removed recipient's warning is enforced, not just accurate, and both
`verify --access` and `key list-recipients` report exactly who can read
what. See "What this pass actually built" below. **Not yet built:**
"Commit signing" below — a real, currently open gap (every attribution
claim in this document is presently a self-reported string, not a proof)
specified but not implemented.

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
  "wrapped":     { "provider": "passphrase-file", "payload": { … } },
  "signingKey":  "ssh-ed25519 AAAA…"    ← optional, see "Commit signing" below
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
  "signingKey": "ssh-ed25519 AAAA…",
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
`signingKey`, when present, is equally non-secret — a public key, same as the
wrap `publicKey` above it — see "Commit signing" below for what it's for.

## Flows

### Joining

```
  new machine                          existing machine
  ───────────                          ────────────────
  git clone …
  securegit identity init
  securegit identity show   ──pubkey──▶
                                        securegit key add-recipient \
                                            SGPUB1… --label laptop
                                        git commit .securegit/recipients
                                        git push
  git pull                        ← must come before `install`; see below
  securegit install
  securegit unlock              ← finds its own fingerprint, unwraps every
  git rm --cached -r -q .         generation it was given, writes a session
  git checkout HEAD -- .
```

Not `git checkout --force .` — confirmed in [07](07-unlock-session.md) and
[15](15-failure-modes.md) that Git's stat-cache skips rewriting a path whose
worktree content already matches the index, `--force` or not, so `smudge`
never reruns on an already-checked-out ciphertext file. `git rm --cached`
first, then a real re-checkout from `HEAD`, is what actually works.

**`install` has to come after that `git pull`, not before it — confirmed
against a real clone in `src/git.integration.test.ts`.** `git pull`, even a
plain fast-forward with no conflicts, runs `clean` as a safety check on
tracked files to confirm the worktree hasn't been locally modified before
touching anything — on *every* tracked path it's about to leave alone, not
just the ones in the incoming diff. If the filter is already attached and
the new machine is (as it always is, at this point) locked, that `clean`
call fails closed exactly as designed ([07](07-unlock-session.md)) and
aborts the whole pull — including the recipient file the new machine needs
in order to ever stop being locked. There is no ordering of `install` and
`unlock` alone that avoids this; the fix is that the very first `git pull`
on a brand-new clone has to happen before `install` ever attaches the
filter at all, exactly like a keyless clone that never runs `install`
([15](15-failure-modes.md), F4).

`unlock` on a machine with no keyring looks for `.securegit/recipients/<own
fingerprint>.json`, unwraps each generation it was given with the identity
key, and writes a session — not a persisted local keyring; see "What this
pass actually built" below for why a session is what's actually built.
From then on the identity key is only needed when a new generation is
added and the session has expired.

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
2. **Commit signing — see below.** `addedBy` records which identity's
   *self-reported* fingerprint performed the add, and `verify --access`
   surfaces it — but nothing before this spec's "Commit signing" section
   made that claim provable rather than typed. Left inaccurate in earlier
   drafts of this document, corrected here: attribution is only as strong
   as its weakest link, and a plain `git config user.name`/self-declared
   `addedBy` isn't a signature.
3. Not doing: a web of trust, or a signature chain over recipient files. It
   would be real work, and the fingerprint-over-a-second-channel step it
   replaces takes ten seconds.

`verify` ([13](13-verify.md)) reports the current recipient list with
fingerprints and the commit that added each, so "who can read this repository"
is answerable from the history rather than from memory — **provably**, once
commit signing (below) is in place; self-reported until then.

## Commit signing — closing the attribution gap

**Status: IMPLEMENTED.** Every attribution claim described above and in
[13](13-verify.md) — `addedBy`, `git blame`, `git log`'s author field — was,
before this section was built, a plain string written by whoever ran the
command, from local state they fully control. Nothing proved it. This
section specifies the fix, and it is now built: `src/identity.ts`'s
detect-or-generate signing keypair, `src/recipients.ts`'s optional
`signingKey` field, `src/cli.ts`'s `identity init`/`key add-recipient`
wiring, and `src/verify.ts`'s `commit-signed-by-recipient` check (see
"What this pass actually built" below for exactly what that check does and
doesn't cover).

### Why this is a separate keypair, not the existing one

`identity.ts`'s X25519 keypair exists for one job: Diffie-Hellman key
agreement, to wrap an RMK ([05](05-key-hierarchy.md)). X25519 keys cannot
sign — that needs a different algorithm (Ed25519/EdDSA). Signing is
therefore a **second, optional keypair** per identity, recorded alongside
the existing one:

```
~/.securegit/identity.json
{
  … everything above, unchanged …
  "signingKey": "ssh-ed25519 AAAA…"   ← the *public* half only; the private
                                         half is whatever local file git's
                                         own `user.signingkey` already
                                         points at — securegit stores a
                                         reference, not a second copy
}
```

Deliberately **not** an SSH *transport* credential — this key is never
presented to any server for authentication, never used to open a
connection, and works identically regardless of whether the remote is
`git://`, `https://`, or anything else. `ssh-ed25519` here names the key
*encoding* git's own commit-signing feature borrows (`git config
gpg.format ssh`), not a relationship to git's SSH transport protocol.

### `identity init`'s new default behaviour

No new flag needed for the safe half of this — detecting an *existing*
signing key is read-only and happens automatically:

```
securegit identity init [--label <label>]
  → (as today) generates the X25519 wrap keypair
  → checks `git config --get user.signingkey` locally
      found it   → records that public key's reference in identity.json,
                    no prompt — reading and remembering a public key that
                    already exists is not a new secret coming into being
      not found  → prints: "No signing key found. Generate one with
                    `identity init --generate-signing-key`, or set one with
                    `git config user.signingkey <path>` and re-run." Does
                    *not* generate one silently — creating new key
                    material always needs an explicit ask, same principle
                    `init`/`install` already follow elsewhere in this CLI.
```

`--generate-signing-key` generates a fresh Ed25519 SSH-format keypair
(`ssh-keygen`-equivalent) when none exists; a no-op with a note if one is
already recorded, never a silent overwrite.

`key add-recipient` gains an optional `--signing-key <ssh-public-key>`,
recorded in the recipient file the same way the existing public key is —
also optional, also detected-not-forced, so a recipient added before this
existed, or one who never sets up signing, simply has no `signingKey`
field and is treated exactly as today (see "What this checks" below for
what that means for enforcement).

### What this checks — and, precisely, what it doesn't

**The rule:** every commit reaching a protected place must be signed, and
by a fingerprint already on the recipient list. Both halves matter —
"signed by *someone*" is not the check; GitHub's own native "require
signed commits" already proves that much and doesn't need securegit's
help. The half only securegit can check is whether the signer is someone
*this repository's own trust model* already recognises, which no
platform's generic signed-commit requirement knows how to ask.

This single rule is deliberately general, not attack-specific — it
doesn't need to know what T1/T3/T4/T5 look like individually. A signer
who was never added as a recipient can't produce a valid signature under
any registered key, so a hostile commit is filtered out by *identity*,
regardless of which of the catalogued attacks (or an uncatalogued future
one) it happens to be. See
[16-adversarial-integrity.md](16-adversarial-integrity.md) for how this
changes that catalogue's own table.

**Where enforcement can and can't happen — the same split as everywhere
else in this project:**
- *Detection* (`securegit verify`, [13](13-verify.md)) can run in every
  repository, by default, no flag — reporting is free and needs no
  server.
- *Blocking* an unsigned or wrong-signer commit before it lands still
  needs something a client can't opt out of: a self-hosted `pre-receive`
  hook, a platform's required status check, or (self-hosted, no server
  auth changes needed) the chaos sandbox's orchestrator review
  ([03-orchestrator.md](../chaotests/03-orchestrator.md)). A client-side
  check alone is the same "convenience, not defense" limit
  [16](16-adversarial-integrity.md)'s T1 section already states for
  `pre-push` hooks — a hostile pusher can simply not run it.

**Two cases this rule must not silently break:**
- **A repository with 0 or 1 recipients checks nothing.** There is no one
  else to impersonate — the rule only starts meaning anything once a
  second party has access at all. A brand-new `securegit init` with no
  recipients added yet (this project's own Quickstart) is unaffected.
- **History predating this feature is never retroactively judged.**
  Exactly like GitHub's "require signed commits" only applies to commits
  made after it's turned on, this only ever evaluates *new* commits going
  forward — an orchestrator review only ever looks at what's being
  proposed now, never re-validates what's already in `master`'s history.
  The base `verify` check is scoped the same way, for the same reason
  [13](13-verify.md)'s own `L6` finding ("plaintext committed before
  adoption") is a `--history`-only, non-blocking finding, not something
  the everyday check treats as a failure — an old repository adopting
  this does not need to retroactively sign years of prior commits.

## What this pass actually built

`src/identity.ts` exports `generateX25519KeyPair()`, `encodePublicKey`/
`decodePublicKey`, `identityFingerprint`, `createIdentity`/`unlockIdentity`,
and `identityPath`/`writeIdentityFile`/`readIdentityFile`.

- **Raw 32-byte keys via JWK export, not DER parsing.** Node's
  `generateKeyPairSync('x25519')` returns `KeyObject`s; the cleanest way to
  get the raw key bytes this spec's encoding needs is `.export({format:
  'jwk'})`, which for an OKP key gives `{x: base64url pubkey, d: base64url
  privkey}` directly — no manual ASN.1/DER stripping. `x25519SharedSecret`
  (also in `identity.ts`) reconstructs a `KeyObject` the same way in
  reverse — `createPublicKey`/`createPrivateKey` with `{format: 'jwk', key:
  {kty: 'OKP', crv: 'X25519', x, d}}` — and is the one function
  `recipients.ts` actually calls for the `X25519(ephPriv, recipientPub)` step
  below; `identity.test.ts`'s real ECDH round-trip proved the primitive
  before `recipients.ts` ever depended on it.
- **The encoding checksum and the fingerprint are different hashes,
  deliberately.** The spec doesn't give the checksum an exact formula
  ("4-byte checksum"); this pass chose plain `SHA-256(pubkey)[0:4]` —
  un-namespaced, unlike the fingerprint's `SHA-256("securegit/identity/v1" ‖
  pubkey)[0:8]`. Collapsing them to the same hash would mean a corrupted
  key's checksum could coincidentally read back as *some* valid-looking
  fingerprint; keeping them in separate domains rules that out, and it's
  cheap to assert directly (`identity.test.ts` checks the encoded string
  never contains the fingerprint).
- **`IdentityFile.wrapped` carries `state` explicitly, not just `payload`.**
  The spec's JSON example shows only `{"provider": ..., "payload": {...}}`,
  eliding the provider's own state (e.g. `PassphraseFileProvider`'s scrypt
  salt and cost parameters) that `unwrap` needs. `keyring.ts`'s
  `WrappedKeySlot` already persists `state` alongside `payload` for the same
  reason; `IdentityFile.wrapped` follows the same shape.
- **Identity wrapping reuses the `KeyProvider` port with a fixed sentinel
  context** — `{repoId: 'identity', generation: 0}` — rather than a
  parallel, identity-specific wrapping interface. An identity isn't scoped
  to any one repository or generation the way an RMK is, but the port's own
  `init()` doc comment already anticipated this ("called once when a
  repository *or identity* is created"), and reusing it means
  `PassphraseFileProvider` — and any future hardware provider behind
  [06](06-key-provider-port.md) — protects an identity's private key with
  exactly the machinery that already protects a repository's master key,
  with no new code path to audit.
- **`decodePublicKey`'s checksum check is a plain `Buffer#equals()`, not
  `equalCt`.** The checksum is derived from the public key alone — already
  public, sent in the clear — so a timing side-channel on this comparison
  reveals nothing an attacker couldn't already compute directly from the
  encoded string. `src/package.test.ts` (T11/T16) allowlists this the same
  way it already allowlists `envelope.ts`'s `looksLikeEnvelope` magic-byte
  check.

`src/recipients.ts` exports `wrapForRecipient`/`unwrapForRecipient` (the
per-generation construction in "Wrapping" above, exactly as specified —
fresh ephemeral keypair, zero nonce, the AAD binding), `wrapAllGenerations`
(the `add-recipient` primitive), `unlockFromRecipientFile` (the `unlock`
bootstrap primitive), and the recipient file's own path/read/write
functions.

- **`WrappedGeneration` carries `fingerprint` explicitly, unlike the spec's
  illustrated `{"ephemeral": …, "payload": …}`.** The AAD binds
  `repoId ‖ generation ‖ fingerprint`, and the *unwrapper* needs the expected
  fingerprint to reconstruct that AAD before they've recovered the key it
  would otherwise come from — a chicken-and-egg problem the spec's elided
  example doesn't surface. Same class of correction as
  `IdentityFile.wrapped.state` above: the illustrative JSON was incomplete,
  not wrong in spirit.
- **The payload is `ciphertext ‖ authTag` as one hex string, not a
  `{nonce, ciphertext, authTag}` object like `PassphraseFileProvider`'s.**
  The nonce needs no field at all — it's always the fixed 12 zero bytes the
  spec specifies, safe only because a fresh ephemeral keypair means
  `wrapKey` is used for exactly one message. Splitting the payload back into
  ciphertext and tag on unwrap is a fixed-offset slice
  (`crypto.ts`'s `TAG_LEN`), not parsing.
- **`wrapAllGenerations` takes `keyIds` as a separate argument from `keys:
  KeySource`, rather than calling `keys.available()` internally.** In
  practice a caller always passes `keys.available()` for both — the split
  exists so a caller can wrap a *subset* of generations later (a plausible
  future need this pass didn't want to foreclose) without an API change, and
  so the function has no way to silently wrap more than the caller asked
  for. An unparseable or unheld `keyId` is skipped, not an error — see the
  doc comment for why that's not actually reachable in the common case.
- **Recipient files get no `0600` restriction, unlike the keyring or an
  identity file.** They hold nothing secret — an ephemeral public key and a
  ciphertext only the intended recipient can open — and the spec is explicit
  that they're meant to be committed and tracked, so ordinary
  umask-governed permissions are correct, not an oversight.

`src/cli.ts` now wires all of the above into `identity init`/`show`, `key
add-recipient`/`remove-recipient`, and a second path inside `unlock`.

- **`unlock` bootstraps a *session*, not a persisted local keyring.** The
  join flow in this spec's own diagram ends with "writes a local keyring" —
  what's actually built writes a session (`writeSession`, the same tail
  `unlock`'s ordinary path already uses) and stops there. Persisting a real
  `keyring.json` from a bootstrap means wrapping every recovered generation
  for a brand-new local provider, and `keyring.ts` has no primitive for
  that shape *wired to this flow* yet — `createKeyring` only ever creates a
  fresh generation 1, `rotateKeyring` only ever adds one new generation on
  top of an existing file. This spec previously guessed `key add-provider`
  would supply the missing primitive as a side effect of getting built —
  wrong guess, corrected now that it exists (06-key-provider-port.md):
  `addProvider()` only ever *appends* a provider to generations an
  *existing* `KeyringFile` already has, which a recipient-only join has
  none of. The primitive this actually needs already exists elsewhere —
  `keyringFromRecoveredGenerations()`, built for `key import-recovery`,
  which genuinely does "wrap N already-known generations for a provider
  that never wrapped any of them before" — but nothing calls it from this
  join flow. A session is enough for day-to-day use; re-running `unlock`
  once a session expires is a small, honest cost until that wiring exists.
- **`identity init`'s `--label` has no default.** The spec's example labels
  (`laptop`, `desktop`, `ci-build`) are purely descriptive text a human
  chose; inventing one (hostname, a UUID) would be more likely to mislead
  than help, so an unlabelled identity just has an empty label.
- **`key add-recipient`'s `addedBy` is best-effort, not required.** It's
  populated from the caller's own `~/.securegit/identity.json` fingerprint
  when one exists, and left blank otherwise — the person adding a recipient
  may only have ordinary passphrase-based keyring access themselves, having
  never run `identity init`. Leaving it blank is honest; refusing to add a
  recipient without an identity of your own would not be.
- **`key remove-recipient` now records the removal, not just the file
  deletion.** Deleting the recipient file leaves no trace that the
  fingerprint ever had access at all — a gap `verify --access`'s "removed
  recipients" section ([13](13-verify.md)) needs closed. Before unlinking,
  it reads the file and appends `{fingerprint, label, removedAt, removedBy,
  generations}` — the generations that file covered, captured before it's
  gone — to a committed `.securegit/removed-recipients.json`, mirroring
  `recovery.ts`'s recovery log in shape. Never the still-wrapped keys, which
  cease to exist once the file itself is deleted.
- **`key remove-recipient` does not refuse removing the last recipient, on
  purpose, reconsidered and confirmed rather than left as an unexamined
  default.** The case for building a hard refusal was revisited directly:
  would it actually protect anyone? Removing a recipient never touches the
  local keyring, so whoever runs `remove-recipient` almost always still has
  their own passphrase access afterward regardless of how many recipients
  remain — a hard refusal wouldn't be protecting *them*. And the real risk
  a check like this would exist to catch — losing all access to the
  repository — is already caught, more precisely, by the single-point-of-
  failure advisory `verify`/`status` already carry (exactly one holder of
  the current generation, no recovery export on record): that's keyed on
  *holders*, not recipient count, and stays a warning rather than a block,
  because "you're now the only one with access" is not, by itself, a
  mistake — plenty of solo or small-team repositories have zero recipients
  at all. A hard refusal here would block a legitimate, ordinary operation
  (revoking a departing contractor who happened to be the last recipient
  on record) to guard against a risk it's the wrong proxy for. v1's
  primary access path is always the local passphrase-wrapped keyring; a
  recipient is supplementary sharing on top of it, not a replacement for
  it — that assumption was the original reason this was deferred, and it
  turned out to be the right one, not just a placeholder pending
  hardware-only recipient setups.
- **Two end-to-end proofs, not one.** `src/cli.test.ts` drives two `CliIO`
  instances — two different `home`s (so two different identities, keyrings
  and sessions) — against one shared `dir`, which faithfully models "the
  same repository, two machines" for everything `identity`/`key
  add-recipient`/`unlock` touch, without the cost of a real clone.
  `src/git.integration.test.ts` then proves the same flow against an actual
  bare remote, `git clone`, `git push` and `git pull` — and finding a real
  bug is exactly why both exist: the CLI-level test alone would never have
  caught F21 below, because it never drives a real `git pull` at all.
- **F21, found while building the real-clone proof: a locked repository can
  fail to `git pull` at all, once the filter is attached.** `git pull` can
  run `clean` as a pre-merge safety check on tracked paths — including ones
  the incoming change never touches — to confirm the worktree hasn't been
  locally modified, and `clean` fails closed when locked
  ([07](07-unlock-session.md)). Whether it actually does is Git's own call —
  a stat-cache short-circuit can skip a path it doesn't believe changed, the
  same mechanism as F16 ([15](15-failure-modes.md)) — but a *fresh clone*
  reliably lands in the racy window where Git can't trust the cache and must
  re-check, which is exactly the case this join flow cares about. For a
  brand-new recipient this is a genuine chicken-and-egg problem: their first
  `git pull` is what delivers the recipient file that would let them unlock,
  but if `install` has already attached the filter, that same pull aborts
  locked before the file ever
  arrives. The fix is ordering, not code: the join flow
  ("Flows" above) now runs a brand-new machine's first `git pull` *before*
  `install`, identical in shape to why a keyless clone that never runs
  `install` still works at all ([15](15-failure-modes.md), F4). See
  [02](02-git-integration.md) for the general statement of the mechanism —
  this is not specific to multi-recipient joining, it would bite anyone who
  attaches the filter before their first pull for any reason.

### Commit signing

`src/identity.ts` gained `signingKeyPath`, `gitConfigGet` (reads git config
scoped to an explicit `home`, not the running process's real `$HOME`),
`detectLocalSigningKey`, `generateSigningKeyPair`, and
`signingKeyFingerprint`. `src/recipients.ts`'s `RecipientFile` gained the
optional `signingKey` field this section specifies. `src/cli.ts` wires
`identity init`'s detect-or-generate flow (`--generate-signing-key`,
detection always wins over the flag) and `key add-recipient
--signing-key`. `src/verify.ts` gained the `commit-signed-by-recipient`
check.

- **Three real bugs found via TDD, each caught by a failing test before
  being trusted, not by inspection.**
  1. `generateSigningKeyPair` originally used `execFile('ssh-keygen', ...)`,
     which never closes a child's stdin — `ssh-keygen`'s interactive
     "Overwrite (y/n)?" prompt (when a key already exists at the target
     path) then hangs forever rather than failing. Fixed by switching to
     `spawn` with `stdio: ['ignore', 'pipe', 'pipe']`, which maps stdin to
     a real EOF.
  2. `signingKeyFingerprint`'s base64 validation trusted
     `Buffer.from(field, 'base64')` to throw on malformed input — it
     doesn't; Node decodes leniently and silently drops invalid characters
     instead of erroring. Fixed with an explicit `/^[A-Za-z0-9+/]+=*$/`
     regex check before decoding.
  3. `gitConfigGet` read `process.env` unmodified, so `detectLocalSigningKey`
     would silently read the real developer machine's global git config
     instead of an explicitly-injected `home` (test isolation, or any
     legitimately-different-home caller). Fixed by threading `home` through
     to an explicit `env: { ...process.env, HOME: home }`.
- **`verify.ts`'s `commit-signed-by-recipient` resolves `HEAD`'s signer via
  `git -c gpg.ssh.allowedSignersFile=/dev/null log -1 --format=%GF HEAD`.**
  Confirmed empirically before writing this: git refuses to attempt SSH
  signature parsing *at all* without `gpg.ssh.allowedSignersFile` pointing
  at an existing file, even an empty one — but `%GF` (the signer's real
  fingerprint) resolves correctly from the commit's own embedded signature
  regardless of whether that key is actually listed in the file (only
  `%G?`, which this check never reads, changes from `G` to `U`). `/dev/null`
  unlocks parsing; the recipient-list comparison against `%GF` *is* the
  trust decision, not the allowed-signers file.
- **Two no-op tiers, not one, keep this from ever punishing an
  unadopted repository:** 0–1 recipients (no one else to impersonate) and
  2+ recipients with zero registered signing keys (nobody has adopted
  signing yet — enforcing against an empty allow-list would fail every
  commit forever, indistinguishable from "hasn't turned this on").
- **Only ever resolves `HEAD`, deliberately — proven, not just claimed, by
  a regression test that commits twice unsigned, then signs only the
  amended tip and asserts the check still passes.** A broader
  per-commit-range check (every commit unique to a *proposed* ref, not a
  single already-landed `HEAD`) is a merge reviewer's job, not this one's —
  built separately in the chaos sandbox's orchestrator
  (`chaos/actors/driver.mjs`'s `allCommitsSignedByRecipient()`, see
  [03-orchestrator.md](../chaotests/03-orchestrator.md) point 5) rather than
  here, since a real self-hosted deployment or CI-side required check plays
  that role, not `securegit verify` itself.
- **The fingerprint comparison must be constant-time, caught by this
  project's own existing hygiene test, not written correctly the first
  time.** The initial `commitSignedByRecipientCheck` compared fingerprints
  with a raw `===`, which `src/package.test.ts`'s
  `no production file compares a fingerprint with a raw === or !==` test
  exists specifically to forbid — fixed with `crypto.ts`'s `equalCt`,
  the same pattern `keyring.ts` already uses for its own fingerprint check.
- **`accessReport()`'s `AccessRecipient` gained a computed
  `signingFingerprint: string | null`** (`null` when absent or malformed),
  so a consumer — `key list-recipients --json`, and the chaos orchestrator
  above — gets a recipient's registered fingerprint without reimplementing
  OpenSSH fingerprint hashing itself.

## Test Cases

| Test | Test File | Fixture | Status |
|------|-----------|---------|--------|
| Wrap/unwrap round-trips for a recipient | `src/recipients.test.ts` | `identities/` | ✅ |
| A different identity cannot unwrap | `src/recipients.test.ts` | `identities/` | ✅ |
| Wrapping bound to `repoId` fails elsewhere | `src/recipients.test.ts` | — | ✅ |
| Wrapping bound to `generation` fails on another generation | `src/recipients.test.ts` | — | ✅ |
| Wrapping bound to `fingerprint` fails if the fingerprint is wrong | `src/recipients.test.ts` | — | ✅ |
| Two wraps for one recipient use different ephemeral keys | `src/recipients.test.ts` | — | ✅ |
| `unlockFromRecipientFile` recovers every generation it holds; `current()` is the highest | `src/recipients.test.ts` | — | ✅ |
| `unlockFromRecipientFile` with the wrong identity unlocks nothing, without throwing | `src/recipients.test.ts` | — | ✅ |
| Recipient file round-trips through disk with ordinary (non-`0600`) permissions | `src/recipients.test.ts` | — | ✅ |
| Public key encoding round-trips | `src/identity.test.ts` | — | ✅ |
| A one-character corruption fails the checksum | `src/identity.test.ts` | — | ✅ |
| Fingerprint is derived from the public key, not the file | `src/identity.test.ts` | — | ✅ |
| Identity private key round-trips through a real `KeyProvider` | `src/identity.test.ts` | — | ✅ |
| Identity file round-trips through disk, mode `0600` | `src/identity.test.ts` | — | ✅ |
| `add-recipient` wraps every existing generation | `src/recipients.test.ts` | — | ✅ |
| `unlock` bootstraps a session from a recipient file alone (CLI-level) | `src/cli.test.ts` | — | ✅ |
| `unlock` bootstraps across a real clone (real `git`, not just two `home`s) | `src/git.integration.test.ts` | `repo-protected/` | ✅ |
| End-to-end join on a second identity, then decrypt (CLI-level) | `src/cli.test.ts` | — | ✅ |
| End-to-end join across a real clone | `src/git.integration.test.ts` | `identities/` | ✅ |
| F21: a locked repository with the filter attached cannot `git pull` | `src/git.integration.test.ts` | — | ✅ |
| `remove-recipient` deletes the file and warns about history | `src/cli.test.ts` | — | ✅ |
| `remove-recipient` records the removal in the committed removed-recipients log | `src/cli.test.ts`, `src/recipients.test.ts` | — | ✅ |
| Removed recipient can still read pre-rotation blobs | `src/git.integration.test.ts` | `identities/` | ✅ |
| Removed recipient cannot read post-rotation blobs | `src/git.integration.test.ts` | `identities/` | ✅ |
| Recipient files are never filtered | `src/install.test.ts` | — | ✅ |
| Removing the last recipient is refused | `src/recipients.test.ts` | — | N/A — deliberately not built; see "What this pass actually built" above for why a hard refusal was reconsidered and rejected, not just deferred |
| `identity init` detects an existing local `user.signingkey` and records it, no prompt | `src/identity.test.ts`, `src/cli.test.ts` | — | ✅ |
| `identity init` does not silently generate a signing key when none is found | `src/cli.test.ts` | — | ✅ |
| `identity init --generate-signing-key` creates one only when none is already recorded | `src/cli.test.ts` | — | ✅ |
| `key add-recipient --signing-key` records the recipient's signing public key | `src/cli.test.ts`, `src/recipients.test.ts` | — | ✅ |
| `verify` reports an unsigned/wrong-signer commit only once 2+ recipients exist; a no-op at 0–1 | `src/verify.test.ts` | — | ✅ |
| `verify`'s signing check never evaluates history predating adoption (base form, not `--history`) | `src/verify.test.ts` | — | ✅ |
| Fingerprint comparison in the signing check is constant-time, not a raw `===` | `src/package.test.ts` (repo-wide static check), `src/verify.test.ts` | — | ✅ |
| `accessReport()` computes a recipient's `signingFingerprint`, `null` when absent or malformed | `src/verify.test.ts` | — | ✅ |
| Orchestrator: every commit unique to a proposed ref must be signed by a recipient, checked against the base tip's own recipient list, not the merge result's | `chaos/actors/driver.mjs` | — | ✅ built, confirmed by direct local plumbing test (no Docker chaos run yet exercises a real rejection — see [03-orchestrator.md](../chaotests/03-orchestrator.md)'s own honest scoping note) |

## Relationship to Other Specs

- [05](05-key-hierarchy.md) — what is being wrapped, and the generation model
- [06](06-key-provider-port.md) — what protects the identity private key
- [07](07-unlock-session.md) — machine identities for CI
- [09](09-rotation-recovery.md) — why removal requires rotation
- [16](16-adversarial-integrity.md) — a hostile `add-recipient` commit,
  and why "commit signing" now closes it structurally rather than only
  making it reviewable
- [13](13-verify.md) — where the signing check surfaces as a check/finding
- [../chaotests/03-orchestrator.md](../chaotests/03-orchestrator.md) — the
  chaos sandbox's orchestrator, the first place this check is meant to
  actually run
