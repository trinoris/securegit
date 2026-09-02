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
//# sourceMappingURL=session.d.ts.map