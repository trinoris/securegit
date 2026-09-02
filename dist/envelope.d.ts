/** Leading NUL so Git's binary detection skips CRLF conversion on the blob. */
export declare const MAGIC: Buffer<ArrayBuffer>;
export declare const FORMAT_V1 = 1;
export declare const ALG_AES256GCM_CONVERGENT = 1;
export declare const FLAG_BIND_PATH = 1;
/** Content is `[4-byte BE length][real content][zero padding]` — see `padContent`/`unpadContent`. */
export declare const FLAG_PADDED = 2;
export declare const HEADER_FIXED_LEN: number;
export declare const OVERHEAD_MIN: number;
export declare const MAX_KEY_ID_LEN = 64;
export declare const DEFAULT_MAX_BYTES: number;
export declare class EnvelopeError extends Error {
    readonly code = "ENVELOPE";
    constructor(message: string);
}
export interface EnvelopeHeader {
    format: number;
    algorithm: number;
    bindPath: boolean;
    padded: boolean;
    keyId: string;
    tag: Buffer;
    authTag: Buffer;
    ciphertext: Buffer;
    headerLength: number;
}
export interface SealOptions {
    rmk: Buffer;
    /** `<generation>.<fingerprint>` — printable ASCII, 1–64 bytes. */
    keyId: string;
    path: string;
    bindPath?: boolean;
    maxBytes?: number;
    /** Pad content to a multiple of this many bytes before encryption. 0/undefined disables padding. See 14-metadata-leakage.md. */
    padTo?: number;
}
export interface UnsealOptions {
    rmk: Buffer;
    path: string;
    maxBytes?: number;
}
/**
 * Magic check only. It says nothing about authenticity, which is why `clean`
 * must authenticate before treating a buffer as already-encrypted: a plaintext
 * file that begins with the magic would otherwise pass through unencrypted.
 */
export declare function looksLikeEnvelope(buf: Buffer): boolean;
/** Reads every header field. Needs no key, so it works in a keyless clone. */
export declare function parseEnvelope(buf: Buffer): EnvelopeHeader;
/** Plaintext → envelope. Deterministic: same input, same bytes, always. */
export declare function seal(plaintext: Buffer, opts: SealOptions): Buffer;
/**
 * Envelope → plaintext. The caller supplies the master key for the generation
 * named in the envelope's keyId; selecting it is the keyring's job.
 */
export declare function unseal(envelope: Buffer, opts: UnsealOptions): Buffer;
//# sourceMappingURL=envelope.d.ts.map