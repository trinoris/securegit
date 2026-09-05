import type { KeyProvider, ProviderState, WrappedKey } from './provider.js';
export declare class IdentityError extends Error {
    readonly code = "IDENTITY";
    constructor(message: string);
}
export declare const IDENTITY_PUBKEY_LEN = 32;
export interface X25519KeyPair {
    publicKey: Buffer;
    privateKey: Buffer;
}
/** A fresh X25519 keypair, as raw 32-byte values (not DER/PEM). */
export declare function generateX25519KeyPair(): X25519KeyPair;
/**
 * X25519(own.privateKey, peerPublicKey) — the shared secret `recipients.ts`
 * derives a wrap key from. Takes the *full* own keypair, not just the
 * private half: reconstructing a Node private KeyObject from raw JWK fields
 * requires the public half (`x`) alongside `d`, per the JWK spec.
 */
export declare function x25519SharedSecret(own: X25519KeyPair, peerPublicKey: Buffer): Buffer;
/** Exported so `recovery.ts` shares this codec rather than duplicating it. */
export declare function crockfordEncode(bytes: Buffer): string;
export declare function crockfordDecode(text: string): Buffer;
/** `SGPUB1<Crockford base32 of the 32 key bytes + a 4-byte checksum>`. */
export declare function encodePublicKey(pubkey: Buffer): string;
/** Reverses `encodePublicKey`, verifying the checksum before returning the raw key. */
export declare function decodePublicKey(encoded: string): Buffer;
/** `SHA-256("securegit/identity/v1" ‖ pubkey)[0..8]`, as 16 hex characters. */
export declare function identityFingerprint(pubkey: Buffer): string;
export interface IdentityFile {
    version: 1;
    fingerprint: string;
    publicKey: string;
    label: string;
    wrapped: {
        provider: string;
        state: ProviderState;
        payload: WrappedKey['payload'];
    };
    /**
     * An OpenSSH-format public key line (`ssh-ed25519 AAAA… [comment]`), used
     * only for git commit signing ([08](../specs/securegit/08-multi-recipient.md),
     * "Commit signing") — a second, optional keypair, never this identity's
     * X25519 keypair (which cannot sign; different algorithm). Absent until
     * `identity init` detects or generates one.
     */
    signingKey?: string;
}
/** Generates a keypair and wraps the private half. Does not write to disk. */
export declare function createIdentity(label: string, provider: KeyProvider): Promise<{
    file: IdentityFile;
    keyPair: X25519KeyPair;
}>;
/** The identity's private key, or `null` if no given provider can unwrap it — never throws. */
export declare function unlockIdentity(file: IdentityFile, providers: KeyProvider[]): Promise<Buffer | null>;
export declare function identityPath(home: string): string;
/** Atomic (temp + rename) write, mode 0600 — the same discipline as `keyring.ts`'s master key. */
export declare function writeIdentityFile(path: string, file: IdentityFile): Promise<void>;
export declare function readIdentityFile(path: string): Promise<IdentityFile>;
/**
 * Resolves a raw `user.signingkey` config value to the actual public key
 * line, without touching the filesystem or git itself — split out from
 * `detectLocalSigningKey()` below purely so the three shapes git accepts
 * (inline `key::…`, `~`-relative path, plain path) are each testable
 * directly, no real git repo or `$HOME` needed.
 *
 * `null` in, `null` out: no key configured, nothing to resolve.
 * A configured-but-unreadable path also resolves to `null`, not a throw —
 * `identity init` treats "found a reference but couldn't read it" the same
 * as "found nothing": either way, there is no key to record yet, and the
 * reason (a stale config entry, a moved file) belongs in a warning the
 * caller prints, not an exception this pure function raises.
 */
export declare function resolveSigningKeyRef(value: string | null, home: string, readFileImpl?: (path: string) => Promise<string>): Promise<string | null>;
/**
 * Whatever `git commit -S` would already sign with in `repoDir`, right
 * now — reads the *effective* `user.signingkey` (local overrides global
 * overrides system, same as git's own resolution), resolved to the actual
 * public key content via `resolveSigningKeyRef()`. Read-only: this never
 * writes anything, generates anything, or prompts — see `identity init`'s
 * own contract for why detecting an existing key is unconditional but
 * recording/generating one is not.
 */
export declare function detectLocalSigningKey(repoDir: string, home: string): Promise<string | null>;
/**
 * Generates a fresh Ed25519 SSH-format signing keypair at `path` (and
 * `path.pub`) via the real `ssh-keygen` binary — deliberately not
 * hand-rolled: the OpenSSH private-key file format is a specific,
 * non-trivial on-disk encoding, and generating a *signing* key by
 * reimplementing that format is exactly the kind of unforced complexity
 * this package avoids elsewhere too. No passphrase (`-N ''`) — this key
 * signs commits, it never wraps an RMK, so it doesn't carry the same
 * stakes as the identity/keyring material a `KeyProvider` protects
 * elsewhere in this codebase.  Refuses (does not overwrite) if a key
 * already exists at `path` — `identity init --generate-signing-key`'s own
 * contract is "only when none is already recorded", enforced by the
 * caller checking `identity.json` first, and `ssh-keygen` itself refusing
 * an existing file first is a second, independent backstop against ever
 * clobbering one by accident.
 *
 * Runs via `spawn`, not `execFile` — `execFile` always leaves the child's
 * stdin as an open, never-closed pipe, and `ssh-keygen` asking "Overwrite
 * (y/n)?" on an existing path then blocks on that pipe forever instead of
 * failing (confirmed directly: `execFile` hangs past any reasonable
 * timeout here, `spawn` with stdin explicitly `'ignore'` — mapped to
 * `/dev/null`, real EOF — exits 1 immediately). The "refuses to overwrite"
 * guarantee above depends on this, not just on ssh-keygen's own default
 * behaviour.
 */
export declare function generateSigningKeyPair(path: string): Promise<{
    publicKey: string;
}>;
export declare function signingKeyFingerprint(publicKeyLine: string): string;
//# sourceMappingURL=identity.d.ts.map