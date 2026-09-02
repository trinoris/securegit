export declare class InstallError extends Error {
    readonly code = "INSTALL";
    constructor(message: string);
}
export interface InstallOptions {
    repoDir: string;
    /** Command used in the filter lines. Defaults to "securegit". */
    bin?: string;
    /** Use the long-running `filter.securegit.process` form instead of clean/smudge. */
    process?: boolean;
    required?: boolean;
    /** Overwrite pre-existing filter/diff config this tool did not write. */
    force?: boolean;
}
/**
 * Writes the filter and diff configuration. Refuses to overwrite an existing
 * identity key (clean/smudge/process/textconv) whose value does not look like
 * something securegit itself would have written — for any bin path this call
 * uses — because that value names an executable, and silently replacing it is
 * exactly the risk in specs/securegit/16-adversarial-integrity.md, T10.
 */
export declare function install(opts: InstallOptions): Promise<void>;
export declare const EXCLUSION_LINE = ".securegit/** -filter -diff -text";
/** Exported so `verify.ts` (T12) can check for the same shapes on disk. */
export declare const RESIDUE_SUFFIXES: string[];
/** The path vim actually gives a swap file: dot-prefixed basename, `.sw?`. */
export declare function swapPattern(pattern: string): string;
export interface ProtectOptions {
    /** Also write `.gitignore` entries for editor/merge residue. Default true. */
    residuePatterns?: boolean;
}
/**
 * Protects one or more path patterns: writes them into `.gitattributes` with
 * the filter, diff driver and `-text`, keeping the `.securegit/**` exclusion
 * last, and (by default) adds `.gitignore` entries for the plaintext residue
 * ordinary tooling leaves beside a protected file.
 */
export declare function protect(repoDir: string, patterns: string[], opts?: ProtectOptions): Promise<void>;
//# sourceMappingURL=install.d.ts.map