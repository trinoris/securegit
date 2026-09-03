import { type Secret } from './crypto.js';
export declare class ProviderError extends Error {
    readonly code = "PROVIDER";
    constructor(message: string);
}
/** Provider-specific state persisted in the keyring — salts, params, handles. */
export type ProviderState = Record<string, string | number>;
export interface ProviderContext {
    /** Bound into the AAD so a wrapped key cannot be moved between repos. */
    readonly repoId: string;
    readonly generation: number;
    readonly state: ProviderState;
    /** How the caller may reach the operator. `false` inside a Git filter. */
    readonly interactive: boolean;
}
export interface WrappedKey {
    provider: string;
    /** Opaque to everything above this port; must be JSON-serialisable. */
    payload: Record<string, string>;
}
export interface ProviderInfo {
    id: string;
    label: string;
    /** Can the party operating this provider be compelled to produce the key? */
    custodial: boolean;
    requiresHardware: boolean;
}
export interface KeyProvider {
    readonly id: string;
    describe(): ProviderInfo;
    /** Is this provider usable on this machine right now? Must not prompt. */
    available(): Promise<boolean>;
    /** Called once when a repository or identity is created. */
    init(ctx: {
        repoId: string;
        generation: number;
    }): Promise<ProviderState>;
    wrap(key: Buffer, ctx: ProviderContext): Promise<WrappedKey>;
    /** Throws ProviderError if the operator did not authorise, or on any mismatch. */
    unwrap(wrapped: WrappedKey, ctx: ProviderContext): Promise<Buffer>;
}
export declare const MIN_PASSPHRASE_LEN = 12;
/** ~64 MiB, a few hundred ms — tuned for a once-per-session unlock. */
export declare const DEFAULT_SCRYPT_N: number;
export interface ScryptCost {
    N: number;
    r: number;
    p: number;
}
/**
 * `RMK` wrapped by a passphrase: scrypt → KEK, AES-256-GCM(KEK, random nonce).
 * Randomness in the nonce is correct here — the wrapped key lives in
 * `~/.securegit`, never in a Git blob, so the determinism constraint that
 * governs the envelope format does not apply.
 */
export declare class PassphraseFileProvider implements KeyProvider {
    readonly id: string;
    private readonly getPassphrase;
    private readonly cost;
    /**
     * `id` defaults to the provider type's own name, matching every existing
     * caller that only ever needs one passphrase-file secret. A second,
     * independent secret on the same keyring (`key add-provider`,
     * 06-key-provider-port.md) needs its own distinct id — `unlockKeyring()`
     * looks providers up by `id`, so two instances sharing one would silently
     * shadow each other during unlock, the same reasoning
     * `rewrapOutdatedGenerations()` already leans on to compare only
     * same-provider slots.
     */
    constructor(getPassphrase: () => Promise<string> | string, cost?: ScryptCost, id?: string);
    describe(): ProviderInfo;
    available(): Promise<boolean>;
    init(ctx: {
        repoId: string;
        generation: number;
    }): Promise<ProviderState>;
    wrap(key: Buffer, ctx: ProviderContext): Promise<WrappedKey>;
    unwrap(wrapped: WrappedKey, ctx: ProviderContext): Promise<Secret>;
    private deriveKek;
}
//# sourceMappingURL=provider.d.ts.map