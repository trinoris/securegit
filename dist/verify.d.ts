import type { KeyProvider } from './provider.js';
export declare const EXIT_VERIFY_OK = 0;
export declare const EXIT_VERIFY_MISCONFIGURED = 2;
export declare const EXIT_VERIFY_LEAK = 5;
export type CheckId = 'repo-initialised' | 'keyring-present' | 'filter-configured' | 'filter-required' | 'diff-driver-configured' | 'textconv-cache-disabled' | 'attributes-present' | 'metadata-exclusion' | 'no-conflicting-attributes' | 'key-material-outside-worktree' | 'non-custodial-unwrap-path';
export interface CheckResult {
    id: CheckId;
    label: string;
    ok: boolean;
    detail?: string;
}
export type FindingKind = 'leak' | 'advice';
export interface Finding {
    kind: FindingKind;
    path: string;
    detail: string;
}
export interface VerifyReport {
    checks: CheckResult[];
    findings: Finding[];
}
export interface VerifyOptions {
    repoDir: string;
    home: string;
    env?: {
        XDG_RUNTIME_DIR?: string | undefined;
    };
    /** Used only to look up each wrapped provider's `custodial` flag (L10) — no key is unwrapped. */
    providers?: KeyProvider[];
}
/** Leak beats misconfiguration beats advice: a live plaintext exposure is always the loudest thing to report. */
export declare function verifyExitCode(report: VerifyReport): number;
/** Filename patterns that suggest a file is sensitive, whether protected or not. */
export declare const NAME_HEURISTICS: RegExp[];
/** High-confidence content patterns — deliberately narrow, to keep false positives rare. */
export declare const CONTENT_HEURISTICS: RegExp[];
export declare function verify(opts: VerifyOptions): Promise<VerifyReport>;
//# sourceMappingURL=verify.d.ts.map