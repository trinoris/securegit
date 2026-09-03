import type { KeySource } from './filter.js';
export declare const DEFAULT_TTL_SECONDS: number;
export declare const MAX_TTL_SECONDS: number;
/** $XDG_RUNTIME_DIR when set (tmpfs, gone at logout); otherwise ~/.securegit/session. */
export declare function resolveSessionPath(repoId: string, env: {
    XDG_RUNTIME_DIR?: string | undefined;
}, home: string): string;
export interface SessionEntry {
    keyId: string;
    rmk: Buffer;
}
export interface WriteSessionOptions {
    repoId: string;
    path?: string;
    entries: SessionEntry[];
    current: string | null;
    ttlSeconds?: number;
    now?: () => Date;
}
/** Always locked-shaped — a caller never has to null-check the session itself. */
export declare function lockedKeySource(): KeySource;
export declare function writeSession(opts: WriteSessionOptions): Promise<void>;
export interface ReadSessionOptions {
    repoId: string;
    path?: string;
    now?: () => Date;
    /** Never receives key material. Defaults to a no-op. */
    warn?: (message: string) => void;
}
export declare function readSession(opts: ReadSessionOptions): Promise<KeySource>;
export declare function lockSession(opts: {
    repoId: string;
    path?: string;
}): Promise<void>;
export interface SessionKeyOptions {
    repoId: string;
    now?: () => Date;
}
/**
 * Decodes `SECUREGIT_SESSION_KEY` (07-unlock-session.md's "Non-interactive
 * unlock" table, top precedence) — the exact bytes `writeSession()` already
 * writes to a session file, base64-encoded, handed through a child
 * process's environment instead of a file. There is no separate command
 * that produces this value: any caller that already holds a session file
 * can read and re-export its own content as-is.
 *
 * Same fail-closed handling as `readSession()` — malformed, expired, or for
 * the wrong repository is just "locked", never a throw — except there is no
 * permission check to make: unlike a file, there's no stat()/chmod concept
 * for an environment variable, so the environment is already the trust
 * boundary and any syntactically valid, matching, unexpired value is used.
 */
export declare function keySourceFromSessionKey(value: string, opts: SessionKeyOptions): KeySource;
//# sourceMappingURL=session.d.ts.map