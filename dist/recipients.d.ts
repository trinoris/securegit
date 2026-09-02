import { type X25519KeyPair } from './identity.js';
import type { KeySource } from './filter.js';
export declare class RecipientError extends Error {
    readonly code = "RECIPIENT";
    constructor(message: string);
}
/**
 * One recipient's wrapping of one generation's master key. Carries
 * `fingerprint` explicitly — the spec's illustrative JSON elides it, but the
 * unwrapper needs the expected fingerprint to reconstruct the AAD *before*
 * it has recovered the key, so it cannot be left implicit the way
 * `IdentityFile.wrapped.state` was the only other such correction.
 */
export interface WrappedGeneration {
    fingerprint: string;
    /** The fresh per-wrap ephemeral X25519 public key, hex-encoded. */
    ephemeral: string;
    /** `ciphertext ‖ authTag`, hex-encoded. The nonce is always 12 zero bytes — safe here because `wrapKey` is used for exactly one message (see `wrapForRecipient`). */
    payload: string;
}
export interface WrapForRecipientOptions {
    recipientPublicKey: Buffer;
    repoId: string;
    generation: number;
    fingerprint: string;
    rmk: Buffer;
}
/**
 * Wraps `rmk` for one recipient, one generation. A fresh ephemeral X25519
 * keypair every call — this is what makes the zero nonce below safe: each
 * `wrapKey` is derived from a shared secret nobody else will ever derive
 * again, so it is used for exactly one AEAD message, and a random nonce
 * would add a field without adding security.
 */
export declare function wrapForRecipient(opts: WrapForRecipientOptions): WrappedGeneration;
export interface UnwrapForRecipientOptions {
    /** The recipient's own full identity keypair — the public half is needed to reconstruct their private KeyObject. */
    identityKeyPair: X25519KeyPair;
    wrapped: WrappedGeneration;
    repoId: string;
    generation: number;
    fingerprint: string;
}
/** Throws `RecipientError` on any mismatch — wrong identity, repoId, generation, fingerprint, or a corrupted payload. */
export declare function unwrapForRecipient(opts: UnwrapForRecipientOptions): Buffer;
/**
 * Wraps every `keyId` the caller's `keys` actually holds — the primitive
 * behind `key add-recipient`, which shares every existing generation with a
 * new recipient in one commit. A `keyId` the caller doesn't hold, or one
 * that doesn't parse, is silently skipped rather than failing the whole
 * operation: `keyIds` is typically `keys.available()` from the same
 * `KeySource`, so in practice nothing is ever actually skipped.
 */
export declare function wrapAllGenerations(keys: KeySource, keyIds: string[], recipientPublicKey: Buffer, repoId: string): Record<string, WrappedGeneration>;
export interface RecipientFile {
    version: 1;
    fingerprint: string;
    publicKey: string;
    label: string;
    addedAt: string;
    addedBy: string;
    /** Keyed by generation number as a string ("1", "2", ...). */
    keys: Record<string, WrappedGeneration>;
}
/**
 * Bootstraps a `KeySource` from a recipient file alone — what `unlock` uses
 * on a machine with no keyring yet. Never throws: a generation this
 * identity can't unwrap (wrong identity entirely, or a `keys` entry it was
 * never given) is simply absent from the result, exactly like
 * `keyring.ts`'s `unlockKeyring`. `current()` is the highest generation
 * number actually recovered — the file has no separate "current" pointer of
 * its own the way a keyring does, and a recipient who joined before the
 * latest rotation naturally caps out below it.
 */
export declare function unlockFromRecipientFile(file: RecipientFile, identityKeyPair: X25519KeyPair, repoId: string): KeySource;
export declare function recipientsDir(repoDir: string): string;
export declare function recipientPath(repoDir: string, fingerprint: string): string;
/**
 * Atomic (temp + rename) write, ordinary permissions — unlike the keyring
 * or an identity file, a recipient file holds nothing secret (an ephemeral
 * public key and a ciphertext only the intended recipient can open) and is
 * meant to be committed and tracked, so it gets no `0600` restriction.
 */
export declare function writeRecipientFile(path: string, file: RecipientFile): Promise<void>;
export declare function readRecipientFile(path: string): Promise<RecipientFile>;
/**
 * `key remove-recipient` deletes the recipient file outright — there is no
 * tombstone left behind, so nothing on disk records that this fingerprint
 * ever had access at all. This log is that record: committed, alongside the
 * recovery log it mirrors in shape, so `verify --access` can report a
 * removed recipient and the generations they can still read (removal does
 * not revoke access already shared — only `key rotate` + `reencrypt` do,
 * see 09-rotation-recovery.md) without needing to walk Git history for a
 * deleted file.
 */
export interface RemovedRecipientLogEntry {
    fingerprint: string;
    label: string;
    removedAt: string;
    /** The remover's own identity fingerprint, or "" if they have none locally. */
    removedBy: string;
    /** Which generations this recipient's file covered at the moment of removal. */
    generations: number[];
}
export declare function removedRecipientsLogPath(repoDir: string): string;
export declare function readRemovedRecipientsLog(path: string): Promise<RemovedRecipientLogEntry[]>;
/** Records that a recipient was removed — never their wrapped keys, which cease to exist once the file itself is deleted. */
export declare function appendRemovedRecipientLogEntry(path: string, entry: RemovedRecipientLogEntry): Promise<RemovedRecipientLogEntry[]>;
//# sourceMappingURL=recipients.d.ts.map