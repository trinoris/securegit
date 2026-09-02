// The unlock session cache.
//
// Git runs filters non-interactively, so the key has to already be available
// when `clean`/`smudge` start. `unlock` performs the interactive part once and
// caches the result here, for a bounded time.
// See specs/securegit/07-unlock-session.md.
import { mkdir, readFile, rename, stat, unlink, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { homedir } from 'node:os';
import { randomBytes } from 'node:crypto';
import { secret } from './crypto.js';
export const DEFAULT_TTL_SECONDS = 8 * 3600;
export const MAX_TTL_SECONDS = 24 * 3600;
/** $XDG_RUNTIME_DIR when set (tmpfs, gone at logout); otherwise ~/.securegit/session. */
export function resolveSessionPath(repoId, env, home) {
    const xdg = env.XDG_RUNTIME_DIR;
    if (xdg && xdg.length > 0) {
        return join(xdg, 'securegit', `${repoId}.session`);
    }
    return join(home, '.securegit', 'session', `${repoId}.session`);
}
function defaultPath(repoId) {
    return resolveSessionPath(repoId, process.env, homedir());
}
/** Always locked-shaped — a caller never has to null-check the session itself. */
function lockedKeySource() {
    return {
        current: () => null,
        find: () => null,
        available: () => [],
    };
}
function fromSessionFile(file) {
    const held = new Map(Object.entries(file.keys).map(([id, hex]) => [id, secret(Buffer.from(hex, 'hex'))]));
    return {
        current() {
            if (file.current === null)
                return null;
            const rmk = held.get(file.current);
            return rmk ? { keyId: file.current, rmk } : null;
        },
        find(keyId) {
            return held.get(keyId) ?? null;
        },
        available() {
            return [...held.keys()];
        },
    };
}
export async function writeSession(opts) {
    const path = opts.path ?? defaultPath(opts.repoId);
    const now = opts.now ?? (() => new Date());
    const ttl = Math.min(Math.max(opts.ttlSeconds ?? DEFAULT_TTL_SECONDS, 0), MAX_TTL_SECONDS);
    const expiresAt = new Date(now().getTime() + ttl * 1000).toISOString();
    const file = {
        version: 1,
        repoId: opts.repoId,
        expiresAt,
        current: opts.current,
        keys: Object.fromEntries(opts.entries.map((e) => [e.keyId, e.rmk.toString('hex')])),
    };
    const dir = dirname(path);
    await mkdir(dir, { recursive: true, mode: 0o700 });
    const tmp = `${path}.tmp-${process.pid}-${randomBytes(4).toString('hex')}`;
    await writeFile(tmp, JSON.stringify(file), { mode: 0o600 });
    try {
        await rename(tmp, path);
    }
    catch (e) {
        await unlink(tmp).catch(() => { });
        throw e;
    }
}
export async function readSession(opts) {
    const path = opts.path ?? defaultPath(opts.repoId);
    const now = opts.now ?? (() => new Date());
    const warn = opts.warn ?? (() => { });
    let stats;
    try {
        stats = await stat(path);
    }
    catch {
        return lockedKeySource(); // no session: an ordinary locked state, not an error
    }
    if ((stats.mode & 0o077) !== 0) {
        warn(`securegit: discarding session file with unsafe permissions (${(stats.mode & 0o777).toString(8)})\n` +
            `  file:   ${path}\n` +
            `  action: run \`securegit unlock\` again`);
        await unlink(path).catch(() => { });
        return lockedKeySource();
    }
    let file;
    try {
        file = JSON.parse(await readFile(path, 'utf8'));
    }
    catch {
        // Corrupt or unreadable: fail safe without destroying a file that might
        // belong to a newer version of this tool.
        return lockedKeySource();
    }
    if (file.repoId !== opts.repoId) {
        return lockedKeySource();
    }
    if (now().getTime() >= new Date(file.expiresAt).getTime()) {
        await unlink(path).catch(() => { });
        return lockedKeySource();
    }
    return fromSessionFile(file);
}
export async function lockSession(opts) {
    const path = opts.path ?? defaultPath(opts.repoId);
    await unlink(path).catch(() => { });
}
//# sourceMappingURL=session.js.map