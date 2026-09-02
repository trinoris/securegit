export declare class RecoveryError extends Error {
    readonly code = "RECOVERY";
    constructor(message: string);
}
export declare const RECOVERY_CODE_LEN = 32;
/** A fresh 256-bit recovery code. */
export declare function generateRecoveryCode(): Buffer;
/** Crockford-encodes `code ‖ checksum(code)`, grouped in 4s for a card. */
export declare function formatRecoveryCode(code: Buffer): string;
/**
 * Reverses `formatRecoveryCode`. This code is meant to be read off a
 * printed card, possibly under stress — so hyphens and whitespace are
 * ignored, case doesn't matter, and `O`/`I`/`L` are folded to `0`/`1`/`1`
 * before decoding, the transcription confusions the spec calls out
 * explicitly. The checksum, not strict formatting, is what actually catches
 * a mistake.
 */
export declare function parseRecoveryCode(input: string): Buffer;
export interface RecoveryGenerationEntry {
    nonce: string;
    ciphertext: string;
    authTag: string;
}
export interface RecoveryFile {
    version: 1;
    repoId: string;
    format: number;
    /** Keyed by generation number as a string ("1", "2", ...). */
    generations: Record<string, RecoveryGenerationEntry>;
}
export interface ExportRecoveryOptions {
    repoId: string;
    generations: {
        generation: number;
        rmk: Buffer;
    }[];
}
/**
 * Generates a fresh code and encrypts every given generation's RMK under a
 * key derived from it. Each generation gets its own random nonce — unlike
 * `recipients.ts`'s zero-nonce wrap, every generation here is encrypted
 * under the *same* wrap key (derived once from the code, not per-wrap from
 * a fresh ephemeral secret), so nonce reuse would be a real risk without one.
 */
export declare function exportRecovery(opts: ExportRecoveryOptions): {
    code: Buffer;
    file: RecoveryFile;
};
/**
 * Decrypts every generation in `file` under `code`. Fails closed and all at
 * once: unlike a recipient (who may legitimately hold only some
 * generations), one code either decrypts the whole file or none of it, so
 * a wrong code or a `repoId` mismatch is an error, not a silently empty
 * result.
 */
export declare function importRecovery(file: RecoveryFile, code: Buffer, expectedRepoId: string): {
    generation: number;
    rmk: Buffer;
}[];
export declare function recoveryFilePath(repoDir: string, filename: string): string;
/**
 * Ordinary permissions, no atomic temp+rename: unlike the keyring or an
 * identity file, this is written once to a fresh path the caller chose, not
 * repeatedly overwritten in place, and it holds nothing secret — the file
 * alone decrypts nothing without the code.
 */
export declare function writeRecoveryFile(path: string, file: RecoveryFile): Promise<void>;
export declare function readRecoveryFile(path: string): Promise<RecoveryFile>;
export interface RecoveryLogEntry {
    exportId: string;
    timestamp: string;
    /** The exporter's own identity fingerprint, or "" if they have none locally. */
    exportedBy: string;
    /** Which generations this export covers — public metadata, never the code or file content. */
    generations: number[];
}
export declare function recoveryLogPath(repoDir: string): string;
export declare function generateExportId(): string;
export declare function readRecoveryLog(path: string): Promise<RecoveryLogEntry[]>;
/** Records that an export happened — never the code, never the file's content. */
export declare function appendRecoveryLogEntry(path: string, entry: RecoveryLogEntry): Promise<RecoveryLogEntry[]>;
//# sourceMappingURL=recovery.d.ts.map