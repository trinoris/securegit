export declare const KEY_LEN = 32;
export declare const NONCE_LEN = 12;
export declare const TAG_LEN = 16;
export declare const CONTENT_TAG_LEN = 32;
export declare class CryptoError extends Error {
    readonly code = "CRYPTO";
    constructor(message: string);
}
declare const secretBrand: unique symbol;
/** A Buffer carrying key material. Still a Buffer; redacts when printed. */
export type Secret = Buffer & {
    readonly [secretBrand]?: true;
};
/**
 * Copies `bytes` into a new Buffer and marks it as key material. node:crypto
 * takes it directly, but bare `toString()`, `JSON.stringify` and
 * `util.inspect` all yield "[redacted]" — so an accidental `${key}` prints a
 * marker instead of a secret. `toString('hex')` still works, because
 * serialising a key is something we deliberately do.
 *
 * It copies rather than marking in place for two reasons: marking the caller's
 * buffer would silently change the behaviour of a value they still hold, and a
 * later mutation of the source must not be able to change a derived key.
 */
export declare function secret(bytes: Buffer | Uint8Array): Secret;
export declare function isSecret(value: unknown): boolean;
/**
 * The form of a path that enters a derivation. Windows and POSIX checkouts of
 * the same repository must derive the same key, so separators are folded and
 * the result is compared as raw UTF-8. `null` means "unbound" — the path does
 * not participate at all.
 */
export declare function normalizePath(path: string | null | undefined): string | null;
/** K_tag — the secret behind the content tag. Never leaves the process. */
export declare function deriveTagKey(rmk: Buffer): Secret;
/**
 * HMAC of the plaintext under K_tag. Supplies both the nonce (its first 12
 * bytes) and the DEK salt, which is what makes the scheme deterministic
 * without ever reusing a (key, nonce) pair across distinct plaintexts.
 *
 * Keyed rather than a bare hash: an adversary who guesses a plaintext cannot
 * confirm the guess without K_tag.
 */
export declare function contentTag(tagKey: Buffer, plaintext: Buffer, path: string | null): Buffer;
/** Per-content data encryption key. Derived, never stored — see spec 05. */
export declare function deriveFileKey(rmk: Buffer, tag: Buffer, path: string | null): Secret;
/**
 * Public, truncated one-way function of a master key. Exists so a wrong-key
 * failure is diagnosable ("blob wants 9f0c…, your keyring has a1b2…") rather
 * than an unexplained authentication error.
 */
export declare function keyFingerprint(rmk: Buffer): string;
export interface Sealed {
    ciphertext: Buffer;
    authTag: Buffer;
}
export declare function aeadEncrypt(key: Buffer, nonce: Buffer, plaintext: Buffer, aad: Buffer | null): Sealed;
export declare function aeadDecrypt(key: Buffer, nonce: Buffer, ciphertext: Buffer, authTag: Buffer, aad: Buffer | null): Buffer;
/** Constant-time comparison for anything not already covered by an AEAD tag. */
export declare function equalCt(a: Buffer, b: Buffer): boolean;
export {};
//# sourceMappingURL=crypto.d.ts.map