export declare class LockedError extends Error {
    readonly code = "LOCKED";
    constructor(message: string);
}
export interface KeyGeneration {
    keyId: string;
    rmk: Buffer;
}
/**
 * What the filter needs from the keyring. Injected rather than imported, so
 * the filter's contract — the asymmetry above all — is testable without a
 * real keyring, session cache or key provider. The real keyring implements
 * exactly this shape.
 */
export interface KeySource {
    /** The generation `clean` encrypts under. `null` when locked. */
    current(): KeyGeneration | null;
    /** The master key for one generation, or `null` if this keyring lacks it. */
    find(keyId: string): Buffer | null;
    /** Every keyId currently held, for diagnostics. */
    available(): string[];
}
export interface FilterContext {
    keys: KeySource;
    /** Repository-relative path. Used for key-derivation context and
     *  diagnostics only — the filter never reads this path from disk. */
    path: string;
    bindPath?: boolean;
    maxBytes?: number;
    /** `clean` only — `unseal`/`smudge` never need it, the envelope's own flag says whether to unpad. */
    padTo?: number;
    /** `smudge --strict`: fail instead of passing ciphertext through. */
    strict?: boolean;
    /** Defaults to `console.error`. Never receives plaintext or key material. */
    warn?: (message: string) => void;
    /** `-v`/`--verbose`: one line per invocation, path and generation only. Never receives plaintext or key material. Silent (not even the default `warn` sink) unless set. */
    trace?: (message: string) => void;
}
/**
 * Plaintext or (already-authenticated) ciphertext in, ciphertext out. Always.
 * Without a key this throws rather than ever emitting the input unchanged —
 * the one outcome this tool exists to prevent.
 */
export declare function clean(input: Buffer, ctx: FilterContext): Buffer;
/**
 * Ciphertext in, plaintext out — except when it can't be, in which case it
 * emits the input unchanged rather than blocking the checkout. The one
 * exception is authentication failure: that is corruption or tampering, and
 * emitting those bytes as if they were plaintext would be wrong in a
 * different way, so it throws regardless of `strict`.
 */
export declare function smudge(input: Buffer, ctx: FilterContext): Buffer;
/** Decrypt for display only. Never throws — a bad blob must not stop `git log -p`. */
export declare function textconv(input: Buffer, ctx: FilterContext): Buffer;
//# sourceMappingURL=filter.d.ts.map