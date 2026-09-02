import { type KeySource } from './filter.js';
export declare class ProcessProtocolError extends Error {
    readonly code = "PROCESS_PROTOCOL";
    constructor(message: string);
}
export interface FilterProcessContext {
    /**
     * Re-invoked before every command, not cached across the process lifetime
     * — this is how session expiry gets re-checked per blob (implementation
     * note 5) without the server needing its own polling or timers. A real
     * caller wires this to `readSession`, which is already cheap (a stat plus
     * a small JSON parse) next to the 40ms Node startup this process exists to
     * avoid paying per file.
     */
    keys: () => Promise<KeySource> | KeySource;
    bindPath: boolean;
    /** `clean` only — see `FilterContext.padTo` in filter.ts. */
    padTo?: number;
    /** Defaults to `envelope.ts`'s `DEFAULT_MAX_BYTES`, exactly like `clean`/`smudge`. */
    maxBytes?: number;
    write: (chunk: Buffer) => void;
    /** Never receives plaintext or key material. */
    warn: (message: string) => void;
}
/**
 * Drives the `filter-process` protocol from raw stdin bytes. Stateful and
 * incremental by necessity: a header, a command, or a blob's content may
 * each arrive split across any number of `push()` calls, and Git may start
 * sending the next command's header before this one has finished writing —
 * so no method here blocks waiting for more data; each either makes
 * progress with what has arrived or returns having changed nothing.
 */
export declare class FilterProcessServer {
    private readonly ctx;
    private readonly reader;
    private state;
    private pendingHeader;
    private contentChunks;
    private contentBytes;
    private contentDiscarding;
    /**
     * Whether `clean` has succeeded at least once this run. Distinguishes "the
     * repository has been locked the whole time" (ordinary per-blob
     * `status=error`, matching `clean`'s own exit-1 case) from "it was
     * unlocked and now the session has expired" (`status=abort` — the one
     * case worth cutting the whole checkout short over, per the error table).
     */
    private everUnlockedForClean;
    constructor(ctx: FilterProcessContext);
    /** Feed raw bytes as they arrive from stdin, in order. */
    push(chunk: Buffer): Promise<void>;
    private pump;
    private handleHandshake;
    /**
     * `clean` and `smudge` only. `delay` is deliberately not advertised even
     * if Git offers it — it exists for filters that fetch blobs remotely
     * (Git LFS), and we have nothing to fetch; advertising it would add a
     * queue and a second state machine for no benefit.
     */
    private handleCapabilities;
    /**
     * Pulls content packets one at a time rather than reading the whole list
     * at once, so an oversized blob can be rejected as soon as the running
     * total crosses the limit — discarding each further packet immediately —
     * instead of buffering it whole first and finding out only afterward.
     * Returns `false` ("more data needed, call again") until this content
     * list's terminating flush has arrived.
     */
    private drainContent;
    private handleCommand;
    private writeStatus;
    private writeSuccess;
}
/**
 * Installs a guard on a writable stream's `write` so only bytes passed
 * through the returned `write` function ever reach it — a stray
 * `console.log` (which ultimately calls `process.stdout.write`) anywhere in
 * this process is a protocol violation that would otherwise corrupt
 * whichever blob is mid-flight, silently. `restore()` puts the original back;
 * callers should install this before reading any stdin and restore it only
 * on exit.
 */
export declare function installStdoutGuard(target: NodeJS.WritableStream): {
    write: (chunk: Buffer) => void;
    restore: () => void;
};
//# sourceMappingURL=process.d.ts.map