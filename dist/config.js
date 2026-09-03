// The repository's own public config: .securegit/config.json.
//
// Unlike the keyring or the session cache, this file is meant to be
// committed — it holds the repoId and bindPath, nothing secret. A clone with
// no key yet must still be able to read it to find out which keyring it
// needs.
// See specs/securegit/02-git-integration.md and 05-key-hierarchy.md.
import { mkdir, readFile, rename, stat, unlink, writeFile } from 'node:fs/promises';
import { join, relative, isAbsolute, resolve } from 'node:path';
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
/** True when `child` is `parent` itself or nested under it. */
function isInside(child, parent) {
    const rel = relative(parent, child);
    return rel === '' || (!rel.startsWith('..') && !isAbsolute(rel));
}
export async function initConfig(repoDir, opts = {}) {
    if (!(await isGitRepo(repoDir))) {
        throw new ConfigError(`securegit: ${repoDir} is not a Git repository (no .git found)`);
    }
    const padTo = opts.padTo ?? 0;
    if (!Number.isInteger(padTo) || padTo < 0) {
        throw new ConfigError(`securegit: padTo must be a non-negative integer, got ${padTo}`);
    }
    if (opts.home !== undefined && isInside(resolve(opts.home, '.securegit'), resolve(repoDir))) {
        throw new ConfigError(`securegit: refusing to initialise — the keyring at ${resolve(opts.home, '.securegit')} ` +
            `would live inside this repository's own working tree (${resolve(repoDir)})\n` +
            `  action: set HOME to a location outside the repository`);
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
    // Atomic (temp file + rename), same discipline as `setBindPath()` and
    // `writeKeyringFile()`: a kill mid-write must leave `config.json` either
    // absent (this repo is still uninitialised, `init` can just be re-run) or
    // fully valid — never present but torn, which would also block a retry
    // (`initConfig()`'s own already-exists guard would refuse a re-run
    // against a file it can't actually read back).
    const tmp = `${path}.tmp-${process.pid}-${randomBytes(4).toString('hex')}`;
    await writeFile(tmp, `${JSON.stringify(config, null, 2)}\n`, 'utf8');
    try {
        await rename(tmp, path);
    }
    catch (e) {
        await unlink(tmp).catch(() => { });
        throw e;
    }
    return config;
}
/**
 * `key rotate --bind-path`'s own primitive (05-key-hierarchy.md: "the
 * supported path" for changing `bindPath` after `init`). Deliberately
 * narrow — flips exactly this one field, leaving `repoId`/`padTo`/`version`
 * untouched — and deliberately *not* used for `padTo`: padding never enters
 * key derivation, so 14-metadata-leakage.md's documented path (hand-edit
 * `config.json`, then `reencrypt`) already covers changing it without
 * needing a dedicated primitive or a new generation. `bindPath` does enter
 * derivation, which is why changing it is paired with a rotation at all —
 * every already-committed blob keeps decrypting under whatever `bindPath`
 * produced it, recorded in its own envelope flags, never read from here.
 * Written atomically (temp file + rename), same discipline as
 * `writeKeyringFile()`.
 */
export async function setBindPath(repoDir, value) {
    const config = await readConfig(repoDir);
    const updated = { ...config, bindPath: value };
    const path = configPath(repoDir);
    const tmp = `${path}.tmp-${process.pid}-${randomBytes(4).toString('hex')}`;
    await writeFile(tmp, `${JSON.stringify(updated, null, 2)}\n`, 'utf8');
    try {
        await rename(tmp, path);
    }
    catch (e) {
        await unlink(tmp).catch(() => { });
        throw e;
    }
    return updated;
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