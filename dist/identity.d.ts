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
//# sourceMappingURL=identity.d.ts.map