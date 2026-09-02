export declare const EXIT_OK = 0;
export declare const EXIT_LOCKED = 1;
export declare const EXIT_MISCONFIGURED = 2;
export declare const EXIT_CRYPTO = 3;
export declare const EXIT_USAGE = 4;
export declare const EXIT_LEAK = 5;
export interface CliIO {
    /** Command and its arguments — NOT including "node" or the script path. */
    argv: string[];
    cwd: string;
    env: NodeJS.ProcessEnv;
    /** File content for clean/smudge/encrypt/decrypt/inspect; whole-buffer. */
    stdin: Buffer;
    /** Equivalent of os.homedir(), injected so tests never touch the real one. */
    home: string;
    /** The content channel. Only clean/smudge/textconv/encrypt/decrypt write here. */
    stdout: (chunk: Buffer) => void;
    /** Every diagnostic, prompt and warning. Never receives plaintext or key material. */
    stderr: (message: string) => void;
    now?: () => Date;
}
/**
 * `filter-process`'s IO is shaped for a long-running stream, not the
 * single-shot request/response every other command uses (`CliIO`'s `stdin`
 * is a whole already-read `Buffer`, and `runCli` returns exactly once) — so
 * it gets its own entrypoint rather than a case in `runCli`'s switch. Real
 * wiring is in `bin/securegit.ts`, which intercepts `filter-process` before
 * ever calling `runCli`.
 */
export interface FilterProcessIO {
    cwd: string;
    env: NodeJS.ProcessEnv;
    home: string;
    /**
     * Registers the handler that receives each raw chunk read from stdin. May
     * return a promise — a real Node stream ignores it, but `runFilterProcess`
     * chains on it internally to serialize chunk processing (below), and a
     * test harness can await it too.
     */
    onData: (handler: (chunk: Buffer) => void | Promise<void>) => void;
    /** Registers the handler invoked once stdin ends (Git closed the pipe). */
    onEnd: (handler: () => void) => void;
    /** Already guarded — see `installStdoutGuard` in `process.ts`. */
    write: (chunk: Buffer) => void;
    stderr: (message: string) => void;
    now?: () => Date;
}
export declare function runFilterProcess(io: FilterProcessIO): Promise<number>;
export declare function runCli(io: CliIO): Promise<number>;
//# sourceMappingURL=cli.d.ts.map