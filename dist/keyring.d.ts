import { type Secret } from './crypto.js';
import { type KeyProvider, type ProviderState, type WrappedKey } from './provider.js';
import type { KeySource } from './filter.js';
export declare class KeyringError extends Error {
    readonly code = "KEYRING";
    constructor(message: string);
}
export interface WrappedKeySlot {
    provider: string;
    /** The provider's own state for this generation — e.g. a scrypt salt. */
    state: ProviderState;
    payload: WrappedKey['payload'];
}
export interface KeyringGeneration {
    generation: number;
    fingerprint: string;
    createdAt: string;
    wrapped: WrappedKeySlot[];
}
export interface KeyringFile {
    version: 1;
    repoId: string;
    current: number;
    generations: KeyringGeneration[];
}
export declare function keyIdFor(generation: number, fingerprint: string): string;
export declare function parseKeyId(keyId: string): {
    generation: number;
    fingerprint: string;
} | null;
/** Generates generation 1 and wraps it with every given provider. */
export declare function createKeyring(repoId: string, providers: KeyProvider[]): Promise<{
    file: KeyringFile;
    rmk: Secret;
}>;
/**
 * Adds a new generation on top of `file`. Every earlier generation is kept
 * verbatim — rotation changes who can read what is committed *next*, never
 * what already exists.
 */
export declare function rotateKeyring(file: KeyringFile, providers: KeyProvider[]): Promise<{
    file: KeyringFile;
    rmk: Secret;
}>;
export interface RecoveredGeneration {
    generation: number;
    rmk: Buffer;
}
/**
 * Builds a full keyring from already-known generations — e.g. recovered via
 * `recovery.ts`'s `importRecovery`. Unlike `createKeyring` (always a fresh
 * generation 1) or `rotateKeyring` (always exactly one new generation on top
 * of an existing file), this wraps an arbitrary, already-determined set of
 * generations for a brand-new provider, which is what makes a machine that
 * just imported a recovery file "a full holder" — able to rotate, add
 * recipients, and re-export from here on.
 */
export declare function keyringFromRecoveredGenerations(repoId: string, recovered: RecoveredGeneration[], providers: KeyProvider[]): Promise<KeyringFile>;
export interface UnlockOptions {
    /** Never receives plaintext or key material. Defaults to a no-op. */
    warn?: (message: string) => void;
    /**
     * The repository being unlocked, when known. A mismatch here (F19,
     * 15-failure-modes.md) means this keyring file was written for a different
     * repository — a manual copy, a moved directory, the wrong `repoId`
     * resolved — and every provider would fail to unwrap it anyway, since each
     * one binds `repoId` into its wrap AAD. Checking first turns that into one
     * clear message naming both ids, instead of "wrong passphrase" everywhere.
     */
    expectedRepoId?: string;
}
/**
 * Tries every wrapped slot of every generation against the given providers,
 * and returns whatever `filter.ts` needs — nothing more. A provider that
 * fails to unwrap a slot (wrong passphrase, wrong machine) is not an error
 * here: the next slot, or the next generation, may still succeed.
 */
export declare function unlockKeyring(file: KeyringFile, providers: KeyProvider[], opts?: UnlockOptions): Promise<KeySource>;
/**
 * "Parameters are stored in the keyring so they can be raised later without
 * breaking existing keyrings; a keyring wrapped at 2^16 is re-wrapped at
 * the new cost on the next successful unlock" (06-key-provider-port.md).
 * Deliberately separate from `unlockKeyring()` itself, which stays a pure
 * read — every filter-time unwrap (`loadKeys()`'s `SECUREGIT_PASSPHRASE`
 * source included) goes through that same function, and a filter must
 * never write to disk. Only `cmdUnlock`, the one place a real `unlock`
 * happens, calls this, and only after a successful unlock already produced
 * `keys`.
 *
 * Only `passphrase-file` has a cost to raise (`state.N`); slots from any
 * other provider are left untouched — there's nothing generic about "raise
 * the cost" across providers yet, and only one provider exists to prove it
 * against. A generation this unlock didn't actually hold (`keys.find()`
 * returns `null`) is left as-is too — there is no RMK on hand to re-wrap.
 */
export declare function rewrapOutdatedGenerations(file: KeyringFile, providers: KeyProvider[], keys: KeySource): Promise<{
    file: KeyringFile;
    changed: boolean;
}>;
/**
 * `key add-provider` (06-key-provider-port.md): wraps every generation
 * for a new provider, alongside whatever already wraps it. Refuses if
 * `provider.id` already has a slot anywhere in the keyring — `unlockKeyring()`
 * looks providers up by id, so a second provider sharing one would
 * silently shadow the first during unlock rather than genuinely offering
 * an independent way in. Refuses just as hard if `keys` doesn't hold every
 * generation — a partial add would leave the keyring in a state where the
 * new provider unlocks some generations but not others, which is worse
 * than not adding it at all.
 */
export declare function addProvider(file: KeyringFile, provider: KeyProvider, keys: KeySource): Promise<KeyringFile>;
/**
 * `key remove-provider` (06-key-provider-port.md): deletes `id`'s wrapped
 * slot from every generation. Refuses (per-generation) if doing so would
 * leave that generation with no provider at all — the last way to unlock
 * a generation must never be removed — and refuses outright if `id` was
 * never present anywhere in the keyring.
 */
export declare function removeProvider(file: KeyringFile, id: string): KeyringFile;
/**
 * Writes the keyring atomically (temp file + rename, so a crash mid-write
 * cannot leave a half-written file) with mode 0600, creating parent
 * directories as needed.
 */
export declare function writeKeyringFile(path: string, file: KeyringFile): Promise<void>;
export declare function readKeyringFile(path: string): Promise<KeyringFile>;
//# sourceMappingURL=keyring.d.ts.map