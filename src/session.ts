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
import type { KeySource } from './filter.js';

export const DEFAULT_TTL_SECONDS = 8 * 3600;
export const MAX_TTL_SECONDS = 24 * 3600;

/** $XDG_RUNTIME_DIR when set (tmpfs, gone at logout); otherwise ~/.securegit/session. */
export function resolveSessionPath(
  repoId: string,
  env: { XDG_RUNTIME_DIR?: string | undefined },
  home: string,
): string {
  const xdg = env.XDG_RUNTIME_DIR;
  if (xdg && xdg.length > 0) {
    return join(xdg, 'securegit', `${repoId}.session`);
  }
  return join(home, '.securegit', 'session', `${repoId}.session`);
}

function defaultPath(repoId: string): string {
  return resolveSessionPath(repoId, process.env, homedir());
}

export interface SessionEntry {
  keyId: string;
  rmk: Buffer;
}

interface SessionFile {
  version: 1;
  repoId: string;
  expiresAt: string;
  current: string | null;
  keys: Record<string, string>;
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
export function lockedKeySource(): KeySource {
  return {
    current: () => null,
    find: () => null,
    available: () => [],
  };
}

function fromSessionFile(file: SessionFile): KeySource {
  const held = new Map(Object.entries(file.keys).map(([id, hex]) => [id, secret(Buffer.from(hex, 'hex'))]));
  return {
    current(): { keyId: string; rmk: Buffer } | null {
      if (file.current === null) return null;
      const rmk = held.get(file.current);
      return rmk ? { keyId: file.current, rmk } : null;
    },
    find(keyId: string): Buffer | null {
      return held.get(keyId) ?? null;
    },
    available(): string[] {
      return [...held.keys()];
    },
  };
}

export async function writeSession(opts: WriteSessionOptions): Promise<void> {
  const path = opts.path ?? defaultPath(opts.repoId);
  const now = opts.now ?? ((): Date => new Date());
  const ttl = Math.min(Math.max(opts.ttlSeconds ?? DEFAULT_TTL_SECONDS, 0), MAX_TTL_SECONDS);
  const expiresAt = new Date(now().getTime() + ttl * 1000).toISOString();

  const file: SessionFile = {
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
  } catch (e) {
    await unlink(tmp).catch(() => {});
    throw e;
  }
}

export interface ReadSessionOptions {
  repoId: string;
  path?: string;
  now?: () => Date;
  /** Never receives key material. Defaults to a no-op. */
  warn?: (message: string) => void;
}

export async function readSession(opts: ReadSessionOptions): Promise<KeySource> {
  const path = opts.path ?? defaultPath(opts.repoId);
  const now = opts.now ?? ((): Date => new Date());
  const warn = opts.warn ?? ((): void => {});

  let stats;
  try {
    stats = await stat(path);
  } catch {
    return lockedKeySource(); // no session: an ordinary locked state, not an error
  }

  if ((stats.mode & 0o077) !== 0) {
    warn(
      `securegit: discarding session file with unsafe permissions (${(stats.mode & 0o777).toString(8)})\n` +
        `  file:   ${path}\n` +
        `  action: run \`securegit unlock\` again`,
    );
    await unlink(path).catch(() => {});
    return lockedKeySource();
  }

  let file: SessionFile;
  try {
    file = JSON.parse(await readFile(path, 'utf8')) as SessionFile;
  } catch {
    // Corrupt or unreadable: fail safe without destroying a file that might
    // belong to a newer version of this tool.
    return lockedKeySource();
  }

  if (file.repoId !== opts.repoId) {
    return lockedKeySource();
  }

  if (now().getTime() >= new Date(file.expiresAt).getTime()) {
    await unlink(path).catch(() => {});
    return lockedKeySource();
  }

  return fromSessionFile(file);
}

export async function lockSession(opts: { repoId: string; path?: string }): Promise<void> {
  const path = opts.path ?? defaultPath(opts.repoId);
  await unlink(path).catch(() => {});
}

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
export function keySourceFromSessionKey(value: string, opts: SessionKeyOptions): KeySource {
  const now = opts.now ?? ((): Date => new Date());
  let file: SessionFile;
  try {
    file = JSON.parse(Buffer.from(value, 'base64').toString('utf8')) as SessionFile;
  } catch {
    return lockedKeySource();
  }
  if (file.repoId !== opts.repoId) return lockedKeySource();
  if (now().getTime() >= new Date(file.expiresAt).getTime()) return lockedKeySource();
  return fromSessionFile(file);
}
