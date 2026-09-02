import { LockedError, type KeySource } from './filter.js';
export { LockedError };
export declare class MergeError extends Error {
    readonly code = "MERGE";
    constructor(message: string);
}
export interface MergeOptions {
    keys: KeySource;
    /** Repository-relative path — %P. Used for key derivation and diagnostics only. */
    path: string;
    bindPath?: boolean;
    /** Conflict marker length — %L. Git's own default is 7. */
    markerSize?: number;
    base: Buffer;
    ours: Buffer;
    theirs: Buffer;
}
export interface MergeResult {
    /** false when conflict markers remain in the result. */
    clean: boolean;
    /** Ciphertext — what the driver writes back to %A. Never plaintext. */
    output: Buffer;
}
export declare function merge(opts: MergeOptions): Promise<MergeResult>;
//# sourceMappingURL=merge.d.ts.map