// The repository's own public config: .securegit/config.json.
//
// Unlike the keyring or the session cache, this file is meant to be
// committed — it holds the repoId and bindPath, nothing secret. A clone with
// no key yet must still be able to read it to find out which keyring it
// needs.
// See specs/securegit/02-git-integration.md and 05-key-hierarchy.md.
import { mkdir, readFile, stat, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
export class ConfigError extends Error {
    code = 'CONFIG';
    constructor(message) {
        super(message);
        this.name = 'ConfigError';
    }
}
export function configPath(repoDir) {
    return join(repoDir, '.securegit', 'config.json');
}
/** `~/.securegit/repos/<repoId>/keyring.json` — scoped so repos never collide. */
export function resolveKeyringPath(repoId, home) {
    return join(home, '.securegit', 'repos', repoId, 'keyring.json');
}
export function generateRepoId() {
    return randomBytes(16).toString('hex');
}
async function isGitRepo(repoDir) {
    try {
        // A worktree's `.git` is a file (`gitdir: …`), not a directory — either
        // counts, since both mean "this is a real Git checkout".
        await stat(join(repoDir, '.git'));
        return true;
    }
    catch {
        return false;
    }
}
export async function initConfig(repoDir, opts = {}) {
    if (!(await isGitRepo(repoDir))) {
        throw new ConfigError(`securegit: ${repoDir} is not a Git repository (no .git found)`);
    }
    const padTo = opts.padTo ?? 0;
    if (!Number.isInteger(padTo) || padTo < 0) {
        throw new ConfigError(`securegit: padTo must be a non-negative integer, got ${padTo}`);
    }
    const path = configPath(repoDir);
    try {
        await stat(path);
        throw new ConfigError(`securegit: this repository is already initialised (${path} exists)`);
    }
    catch (e) {
        if (e instanceof ConfigError)
            throw e;
        // ENOENT is the expected case — fall through and create it.
    }
    const config = {
        version: 1,
        repoId: generateRepoId(),
        bindPath: opts.bindPath ?? false,
        padTo,
    };
    await mkdir(join(repoDir, '.securegit'), { recursive: true });
    await writeFile(path, `${JSON.stringify(config, null, 2)}\n`, 'utf8');
    return config;
}
export async function readConfig(repoDir) {
    const path = configPath(repoDir);
    let raw;
    try {
        raw = await readFile(path, 'utf8');
    }
    catch {
        throw new ConfigError(`securegit: no repository configuration found at ${path}\n` +
            `  action: run \`securegit init\` first`);
    }
    try {
        return JSON.parse(raw);
    }
    catch {
        throw new ConfigError(`securegit: ${path} is not valid JSON`);
    }
}
//# sourceMappingURL=config.js.map