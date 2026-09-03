export declare class ConfigError extends Error {
    readonly code = "CONFIG";
    constructor(message: string);
}
export interface RepoConfig {
    version: 1;
    repoId: string;
    bindPath: boolean;
    /** Pad protected content to a multiple of this many bytes. 0 disables padding. See 14-metadata-leakage.md. */
    padTo: number;
}
export declare function configPath(repoDir: string): string;
/** `~/.securegit/repos/<repoId>/keyring.json` — scoped so repos never collide. */
export declare function resolveKeyringPath(repoId: string, home: string): string;
export declare function generateRepoId(): string;
export interface InitConfigOptions {
    bindPath?: boolean;
    padTo?: number;
    /**
     * When given, refuses (rather than silently allowing) a repository whose
     * keyring would resolve inside its own working tree — 05-key-hierarchy.md:
     * nothing unwrapped ever belongs in the repo, and a keyring nested inside
     * it is one `git add -A` away from being committed. Optional so existing
     * callers that don't pass `home` at all (most of `src/config.test.ts`)
     * keep working unchanged; `cli.ts`'s `cmdInit` always passes it.
     */
    home?: string;
}
export declare function initConfig(repoDir: string, opts?: InitConfigOptions): Promise<RepoConfig>;
export declare function readConfig(repoDir: string): Promise<RepoConfig>;
//# sourceMappingURL=config.d.ts.map