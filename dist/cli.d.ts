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
export declare function runCli(io: CliIO): Promise<number>;
//# sourceMappingURL=cli.d.ts.map