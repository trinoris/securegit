# 06. Key Provider Port

## Overview

The repository master key has to be protected by *something* the workstation
has and the cloud does not. That something differs per user and per machine —
passphrase today, a TPM on the desktop, a smartcard for the person who travels.
This is the interface that keeps that choice out of the crypto core.

**Status: IMPLEMENTED — the port and one provider.** `src/provider.ts` (the
`KeyProvider` interface) and `PassphraseFileProvider` are both built and
tested. `passphrase-file` remains the only v1 implementation; hardware
providers (`tpm2`, `piv`, `os-keychain`) sit behind this same port,
unimplemented, by design — see [00](00-test-plan.md)'s "Deliberately not
phased" note.

`src/provider.conformance.test.ts` is the contract suite this document
promises: `describe.each` over a `{ name, makeProvider }` registration list
(today, one row — `passphrase-file`), so every case below runs once per
registered provider rather than once for `PassphraseFileProvider`
specifically. Adding a second real provider means adding a row, not a new
test file. The "never receives a path or file content" row is proved
behaviourally, not just by the TypeScript types: a small recording wrapper
intercepts every argument actually passed to `init`/`wrap`/`unwrap` across a
full cycle and asserts none of it — recursively, skipping `Buffer`s, which
are the key material itself — carries a key matching `path`, `content` or
`plaintext`. `src/provider.test.ts` keeps everything specific to
`PassphraseFileProvider` (its scrypt parameters, its exact error strings);
the split mirrors `src/vectors.test.ts` vs. `src/envelope.test.ts` from
[03](03-determinism.md)/[04](04-envelope-format.md) — one file proves the
implementation, the other proves the contract every implementation shares.

## Core Principle

> A provider wraps and unwraps a 32-byte key. It never sees a plaintext file, a
> DEK, or a path. If a provider's implementation is wrong, the blast radius is
> the master key's confidentiality — not the correctness of every blob in the
> repository.

## Port

```typescript
export interface KeyProvider {
  /** Stable identifier recorded in the keyring: "passphrase-file", "tpm2", … */
  readonly id: string;

  /** Human-facing description for `securegit status`. Never includes secrets. */
  describe(): ProviderInfo;

  /** Is this provider usable on this machine right now? Must not prompt. */
  available(): Promise<boolean>;

  /** Called once when a repository or identity is created. */
  init(ctx: ProviderContext): Promise<ProviderState>;

  wrap(key: Buffer, ctx: ProviderContext): Promise<WrappedKey>;

  /** Throws UnlockRequired if the operator did not authorise. */
  unwrap(wrapped: WrappedKey, ctx: ProviderContext): Promise<Buffer>;
}

export interface ProviderContext {
  /** Bound into the AAD so a wrapped key cannot be moved between repos. */
  readonly repoId: string;
  readonly generation: number;
  /** Provider-specific state persisted in the keyring (salts, handles, slots). */
  readonly state: ProviderState;
  /** How the caller may reach the operator. `false` inside a Git filter. */
  readonly interactive: boolean;
}

export interface WrappedKey {
  provider: string;
  /** Opaque to everything above this port. */
  payload: Record<string, string>;
}

export interface ProviderInfo {
  id: string;
  label: string;
  /** Can the party operating this provider be compelled to produce the key? */
  custodial: boolean;
  requiresHardware: boolean;
}
```

`payload` being opaque is deliberate. A TPM stores a sealed blob and a PCR
policy; a smartcard stores a slot reference and an ephemeral public key; the
passphrase provider stores scrypt parameters, a salt and an AES-GCM ciphertext.
Nothing above the port may inspect those fields, so adding a provider changes no
existing code.

## Implementations

| Provider | `custodial` | Status | Notes |
|---|---|---|---|
| `passphrase-file` | no | **v1** | scrypt → KEK → AES-256-GCM. Works everywhere, including WSL and CI. |
| `os-keychain` | no | designed | DPAPI / macOS Keychain / libsecret. Better UX; no keychain under WSL, so it always needs a fallback. |
| `tpm2` | no | designed | Seals the RMK to PCRs. Machine-bound: a re-imaged laptop loses it, so it is never the only path. |
| `piv` | no | designed | YubiKey / smartcard. Portable, hardware-bound, matches the threat model best. |
| `recovery-code` | no | built, but not a `KeyProvider` | Not interactive; used by `import-recovery` ([09](09-rotation-recovery.md)). As built, this is *not* a `KeyProvider` implementation behind this port — `src/recovery.ts` derives its wrap key directly from the code via HKDF and does its own AES-256-GCM wrap/unwrap, bypassing `provider.ts` entirely. The RMKs it recovers are then handed to an ordinary `PassphraseFileProvider` (via `keyringFromRecoveredGenerations`) to become the new local keyring's actual provider. The reason: this port's `init`/`wrap`/`unwrap` shape is built around one *persistent* secret per generation (a passphrase, a TPM binding); a recovery code instead needs to decrypt *every* generation at once under one code, which doesn't fit that per-generation shape without distortion. |
| `kms` | **yes** | designed | Deliberate escrow only. See below. |

## `custodial` is the field that matters

[01](01-threat-model.md) sets the test: *if this party is compelled, can they
produce the key?* A provider that answers yes is `custodial: true`, and:

- it may never be the **only** unwrap path for a repository;
- `securegit status` prints it in the clear, as an escrow path, with the party
  named;
- `securegit verify` reports a repository whose every path is custodial as a
  finding, because that repository has re-created the property the tool exists
  to remove.

This is not an argument against KMS. An organisation that wants a break-glass
path administered by its cloud account is making a reasonable trade. It just has
to be a visible trade rather than an accident of configuration.

## The `passphrase-file` provider

```
   passphrase ──scrypt(N=2^16, r=8, p=1, salt=16B)──▶ 32-byte KEK
                                                       │
   RMK ──── AES-256-GCM(KEK, nonce=12B random) ────────▶ wrapped
                                                aad = "securegit/keywrap/v1"
                                                    ‖ repoId ‖ generation
```

- **Randomness is correct here.** The wrapped key lives in `~/.securegit`, never
  in a Git blob, so [03](03-determinism.md) does not apply. A fresh nonce per
  wrap is what we want.
- **`N = 2^16`** costs about 64 MiB and a few hundred milliseconds — tuned for a
  once-per-session unlock, not a per-file operation. Parameters are stored in
  the keyring so they can be raised later without breaking existing keyrings; a
  keyring wrapped at `2^16` is re-wrapped at the new cost on the next successful
  unlock.
- **The AAD binds `repoId` and `generation`**, so a wrapped key copied into
  another repository's keyring — or wrapped again under a fresh salt for the
  same repository and generation — fails to unwrap under the wrong copy rather
  than silently decrypting into garbage. `unwrap` reports every failure mode
  (wrong passphrase, wrong `repoId`, wrong `generation`, malformed payload) as
  the same `ProviderError`, deliberately: distinguishing them in the message
  would tell an attacker which guess was closer.
- **Passphrase strength is the whole security of this provider** against an
  adversary holding the file (A4 in [01](01-threat-model.md)). `key init` refuses
  a passphrase under 12 characters and reports an estimate; it does not enforce
  composition rules, which produce worse passphrases.

## Multiple providers per repository

The keyring stores a list of wrapped copies of each generation, one per
provider. Unlock tries providers in order of `available()`, preferring
non-interactive ones.

```json
{
  "generation": 3,
  "fingerprint": "a1b2c3d4e5f60718",
  "createdAt": "2026-09-01T10:04:11.000Z",
  "wrapped": [
    { "provider": "passphrase-file", "state": { "…": "…" }, "payload": { "…": "…" } },
    { "provider": "piv",             "state": { "…": "…" }, "payload": { "…": "…" } }
  ]
}
```

Each slot carries **`state`** alongside `payload`: a provider's `wrap`/`unwrap`
need whatever `init` produced for that generation (the scrypt salt and cost,
for `passphrase-file`) even though `payload` alone is what is secret. Splitting
them keeps `payload` — the only field an audit of "what is encrypted" needs to
reason about — free of parameters that are public by nature.

`unlockKeyring` (`src/keyring.ts`) tries every slot of every generation against
whatever providers the caller has, in the order the generations were created,
and keeps whichever succeed:

```typescript
for (const gen of file.generations) {
  for (const slot of gen.wrapped) {
    const provider = byId.get(slot.provider);
    if (!provider) continue;
    try {
      const rmk = await provider.unwrap(slot, { …, state: slot.state });
      // fingerprint check, then held.set(keyId, rmk); break
    } catch { continue; } // try the next slot, or the next generation
  }
}
```

A provider that fails on one slot — wrong passphrase, wrong machine — does not
stop the loop. This is what makes "unlock via provider A if it works, else
provider B" and "unlock only the generations a late-joining recipient can
reach" ([08](08-multi-recipient.md)) the same code path rather than two.

Adding a provider requires an unlock through an existing one — `keyring.ts` has
no special case for it: an added provider is just another `wrap()` call for
the current generation, appended to that generation's `wrapped` list.
Removing the last non-custodial provider is refused. Recipients ([08](08-multi-recipient.md)) are
a *different* mechanism — they wrap for other people, and live in the repository
rather than the keyring — but they follow the same rule: a repository must
always have at least one non-custodial way back in.

## Test Cases

| Test | Test File | Fixture | Status |
|------|-----------|---------|--------|
| Conformance suite passes for every provider | `src/provider.conformance.test.ts` | — | ✅ |
| `wrap` then `unwrap` returns the identical key | `src/provider.conformance.test.ts` | — | ✅ |
| `unwrap` with the wrong `repoId` fails | `src/provider.conformance.test.ts` | — | ✅ |
| `unwrap` with the wrong `generation` fails | `src/provider.conformance.test.ts` | — | ✅ |
| Two `wrap` calls on one key produce different payloads | `src/provider.test.ts` | — | ✅ |
| Wrong passphrase fails with a distinguishable error, not a crash | `src/provider.test.ts` | — | ✅ |
| scrypt parameters round-trip through the keyring | `src/keyring.test.ts` | — | ✅ |
| Raised scrypt parameters re-wrap on next unlock | `src/keyring.test.ts` | — | 🔲 |
| `available()` never prompts | `src/provider.conformance.test.ts` | — | ✅ |
| Passphrase under 12 characters is refused at `init` | `src/provider.test.ts` | — | ✅ |
| Removing the last non-custodial provider is refused | `src/keyring.test.ts` | — | 🔲 |
| A custodial-only repository is a `verify` finding | `src/verify.test.ts` | — | ✅ |
| Provider never receives a path or file content | `src/provider.conformance.test.ts` | — | ✅ |

## Relationship to Other Specs

- [01](01-threat-model.md) — the compulsion test behind `custodial`
- [05](05-key-hierarchy.md) — what is being wrapped
- [07](07-unlock-session.md) — `interactive: false` inside a filter
- [08](08-multi-recipient.md) — the other way a key is wrapped
- [09](09-rotation-recovery.md) — the `recovery-code` provider
