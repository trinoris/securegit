import type { KeyProvider } from './provider.js';
import { type RemovedRecipientLogEntry } from './recipients.js';
import { type RecoveryLogEntry } from './recovery.js';
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
export type FindingKind = 'leak' | 'advice' | 'residue';
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
/**
 * Leak beats misconfiguration beats advice: a live plaintext exposure is
 * always the loudest thing to report. A residue finding (T12) is plaintext
 * sitting on disk rather than committed — real, but not the same severity as
 * a committed leak — so it joins failed checks at the misconfigured tier.
 */
export declare function verifyExitCode(report: VerifyReport): number;
/** Filename patterns that suggest a file is sensitive, whether protected or not. */
export declare const NAME_HEURISTICS: RegExp[];
/** High-confidence content patterns — deliberately narrow, to keep false positives rare. */
export declare const CONTENT_HEURISTICS: RegExp[];
/** Exported for `cli.ts`'s `reencrypt`, which needs the same "which tracked paths are protected" scan. */
export declare function listTrackedPaths(repoDir: string): Promise<string[]>;
/** `path: attribute: value` per requested attribute, parsed into a map. Exported for `cli.ts`'s `reencrypt`. */
export declare function checkAttr(repoDir: string, path: string): Promise<Record<string, string>>;
/** The index's copy of a tracked path — what would be committed right now. Exported for `cli.ts`'s `reencrypt`. */
export declare function readIndexBlob(repoDir: string, path: string): Promise<Buffer>;
export declare function verify(opts: VerifyOptions): Promise<VerifyReport>;
export interface AccessRecipient {
    fingerprint: string;
    label: string;
    addedAt: string;
    addedBy: string;
    /** Sorted ascending. Not necessarily contiguous — a recipient can predate a rotation, join after one, or both. */
    generations: number[];
}
export interface AccessProvider {
    id: string;
    /** Every generation across the whole keyring this provider can unwrap, sorted ascending. */
    generations: number[];
}
export interface AccessReport {
    recipients: AccessRecipient[];
    providers: AccessProvider[];
    recoveryExports: RecoveryLogEntry[];
    removedRecipients: RemovedRecipientLogEntry[];
}
/**
 * "Who can read this repository, now and previously" — recipients, the
 * providers wrapping the keyring, and the two append-only logs
 * (`recovery-log.json`, `removed-recipients.json`). Like `verify()`, this
 * unwraps no key and touches no session: recipient files, the keyring's
 * `provider` field on each wrapped slot, and both logs are all public even
 * in a locked repository or on a machine with no keyring of its own.
 */
export declare function accessReport(opts: VerifyOptions): Promise<AccessReport>;
export interface HistoryFinding {
    path: string;
    firstSha: string;
    firstDate: string;
    firstSubject: string;
    lastSha: string;
    lastDate: string;
    lastSubject: string;
    /** How many walked commits had plaintext at this path — not necessarily contiguous. */
    commitCount: number;
    /** Local branches whose tip can reach the *last* offending commit. */
    reachableFrom: string[];
}
export interface HistoryReport {
    commitsWalked: number;
    findings: HistoryFinding[];
    textconvNotesRef: {
        present: boolean;
        count: number;
    };
}
export interface HistoryOptions {
    repoDir: string;
    /**
     * Fires once per *unique* blob OID whose content was actually read — never
     * for a repeat encounter of a blob already in the cache. Exists so the
     * OID-deduplication this scan depends on for real-repository performance
     * (unwalked, this is thousands of commits mostly re-touching the same
     * unchanged blobs) is something a test can observe directly, not just
     * assert about in prose.
     */
    onBlobExamined?: (blobSha: string) => void;
}
/** Exported for `cli.ts`'s `verify --history` output. */
export declare const TEXTCONV_NOTES_REF = "refs/notes/textconv/securegit";
/**
 * Walks every reachable commit (`git rev-list --all`), resolving
 * `filter=securegit` protection as it stood *at that commit* — a path
 * protected today may not have been then, and reporting it as a leak either
 * way would be wrong in one direction or the other. Every blob is read at
 * most once regardless of how many commits reference it unchanged, via a
 * plain `Map` keyed by blob SHA — content is content-addressed, so the same
 * SHA always means the same bytes.
 *
 * CI-tier speed, not pre-commit: a repository of any real size means
 * hundreds to thousands of `git` subprocess invocations. See "Use as a
 * hook" in 13-verify.md.
 */
export declare function historyReport(opts: HistoryOptions): Promise<HistoryReport>;
export interface MetadataObservable {
    code: string;
    observable: string;
    /** Whether this repository currently has anything to observe here — false only for M11 with no recipients. */
    applies: boolean;
    note: string;
}
export interface MetadataReport {
    observables: MetadataObservable[];
}
/**
 * A static list, not a live audit: every M-code the spec catalogues, with
 * the two that respond to local config (`padTo`, `bindPath`) reflecting
 * their actual current mitigation state, and M11 (recipient metadata)
 * reporting whether it applies at all — every other observable is
 * unconditional (inherent to committing to a Git repository), so
 * `applies` is always `true` for them, and mitigation is always "no" per
 * the spec's own table.
 */
export declare function metadataReport(opts: {
    repoDir: string;
}): Promise<MetadataReport>;
//# sourceMappingURL=verify.d.ts.map