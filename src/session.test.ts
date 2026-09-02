import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mkdtemp, rm, stat, mkdir, writeFile, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { clean, smudge, LockedError } from './filter.js';
import {
  DEFAULT_TTL_SECONDS,
  MAX_TTL_SECONDS,
  resolveSessionPath,
  writeSession,
  readSession,
  lockSession,
  type SessionEntry,
} from './session.js';

const REPO = 'repo-a';
const KEY_ID = '3.a1b2c3d4e5f60718';
const RMK = Buffer.alloc(32, 0xa5);
const ENTRIES: SessionEntry[] = [{ keyId: KEY_ID, rmk: RMK }];

let dir: string;
let sessionPath: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'securegit-session-'));
  sessionPath = join(dir, 'nested', `${REPO}.session`);
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe('resolveSessionPath()', () => {
  it('prefers $XDG_RUNTIME_DIR when set', () => {
    const path = resolveSessionPath(REPO, { XDG_RUNTIME_DIR: '/run/user/1000' }, '/home/u');
    expect(path).toBe('/run/user/1000/securegit/repo-a.session');
  });

  it('falls back to the home directory when unset', () => {
    const path = resolveSessionPath(REPO, {}, '/home/u');
    expect(path).toBe('/home/u/.securegit/session/repo-a.session');
  });

  it('falls back when $XDG_RUNTIME_DIR is set but empty', () => {
    const path = resolveSessionPath(REPO, { XDG_RUNTIME_DIR: '' }, '/home/u');
    expect(path).toBe('/home/u/.securegit/session/repo-a.session');
  });

  it('is scoped per repository, so two repos never collide', () => {
    const a = resolveSessionPath('repo-a', {}, '/home/u');
    const b = resolveSessionPath('repo-b', {}, '/home/u');
    expect(a).not.toBe(b);
  });
});

describe('writeSession() / readSession()', () => {
  it('round-trips a single generation', async () => {
    await writeSession({ repoId: REPO, path: sessionPath, entries: ENTRIES, current: KEY_ID });
    const keys = await readSession({ repoId: REPO, path: sessionPath });
    expect(keys.current()?.keyId).toBe(KEY_ID);
    expect(keys.current()?.rmk.equals(RMK)).toBe(true);
    expect(keys.find(KEY_ID)?.equals(RMK)).toBe(true);
    expect(keys.available()).toEqual([KEY_ID]);
  });

  it('round-trips multiple generations with a distinct current', async () => {
    const rmk2 = Buffer.alloc(32, 0x33);
    const entries = [ENTRIES[0]!, { keyId: '2.b30f92ac1e7d4405', rmk: rmk2 }];
    await writeSession({ repoId: REPO, path: sessionPath, entries, current: KEY_ID });
    const keys = await readSession({ repoId: REPO, path: sessionPath });
    expect(keys.available().sort()).toEqual(['2.b30f92ac1e7d4405', KEY_ID].sort());
    expect(keys.find('2.b30f92ac1e7d4405')?.equals(rmk2)).toBe(true);
    expect(keys.current()?.keyId).toBe(KEY_ID);
  });

  it('supports a null current — held keys but nothing marked current', async () => {
    await writeSession({ repoId: REPO, path: sessionPath, entries: ENTRIES, current: null });
    const keys = await readSession({ repoId: REPO, path: sessionPath });
    expect(keys.current()).toBeNull();
    expect(keys.find(KEY_ID)?.equals(RMK)).toBe(true);
  });

  it('creates the session file with mode 0600', async () => {
    await writeSession({ repoId: REPO, path: sessionPath, entries: ENTRIES, current: KEY_ID });
    const mode = (await stat(sessionPath)).mode & 0o777;
    expect(mode).toBe(0o600);
  });

  it('creates the containing directory with mode 0700', async () => {
    await writeSession({ repoId: REPO, path: sessionPath, entries: ENTRIES, current: KEY_ID });
    const mode = (await stat(join(dir, 'nested')).then((s) => s.mode & 0o777));
    expect(mode).toBe(0o700);
  });

  it('leaves no stray temp file behind', async () => {
    await writeSession({ repoId: REPO, path: sessionPath, entries: ENTRIES, current: KEY_ID });
    expect(await readdir(join(dir, 'nested'))).toEqual([`${REPO}.session`]);
  });

  it('fully overwrites a previous session for the same repo', async () => {
    await writeSession({ repoId: REPO, path: sessionPath, entries: ENTRIES, current: KEY_ID });
    const rmk2 = Buffer.alloc(32, 0x77);
    await writeSession({
      repoId: REPO,
      path: sessionPath,
      entries: [{ keyId: '9.0000000000000000', rmk: rmk2 }],
      current: '9.0000000000000000',
    });
    const keys = await readSession({ repoId: REPO, path: sessionPath });
    expect(keys.available()).toEqual(['9.0000000000000000']);
  });

  it('reading a session that was never written is treated as locked, not an error', async () => {
    const keys = await readSession({ repoId: REPO, path: sessionPath });
    expect(keys.current()).toBeNull();
    expect(keys.available()).toEqual([]);
    expect(keys.find(KEY_ID)).toBeNull();
  });
});

describe('expiry', () => {
  it('defaults to an 8 hour TTL', () => {
    expect(DEFAULT_TTL_SECONDS).toBe(8 * 3600);
  });

  it('caps the TTL at 24 hours', () => {
    expect(MAX_TTL_SECONDS).toBe(24 * 3600);
  });

  it('clamps a TTL above the cap', async () => {
    const base = new Date('2026-09-01T10:00:00.000Z');
    await writeSession({
      repoId: REPO, path: sessionPath, entries: ENTRIES, current: KEY_ID,
      ttlSeconds: 999 * 3600, now: () => base,
    });
    // Just under the cap: still unlocked.
    const justBefore = new Date(base.getTime() + MAX_TTL_SECONDS * 1000 - 1000);
    expect((await readSession({ repoId: REPO, path: sessionPath, now: () => justBefore })).current()).not.toBeNull();
    // Just past the (clamped) cap: expired.
    const justAfter = new Date(base.getTime() + MAX_TTL_SECONDS * 1000 + 1000);
    expect((await readSession({ repoId: REPO, path: sessionPath, now: () => justAfter })).current()).toBeNull();
  });

  it('is usable right up to expiry and locked immediately after', async () => {
    const base = new Date('2026-09-01T10:00:00.000Z');
    await writeSession({
      repoId: REPO, path: sessionPath, entries: ENTRIES, current: KEY_ID,
      ttlSeconds: 3600, now: () => base,
    });
    const before = new Date(base.getTime() + 3600 * 1000 - 1);
    const after = new Date(base.getTime() + 3600 * 1000 + 1);
    expect((await readSession({ repoId: REPO, path: sessionPath, now: () => before })).current()).not.toBeNull();
    expect((await readSession({ repoId: REPO, path: sessionPath, now: () => after })).current()).toBeNull();
  });

  it('unlinks an expired session rather than leaving it on disk', async () => {
    const base = new Date('2026-09-01T10:00:00.000Z');
    await writeSession({
      repoId: REPO, path: sessionPath, entries: ENTRIES, current: KEY_ID,
      ttlSeconds: 60, now: () => base,
    });
    const later = new Date(base.getTime() + 3600 * 1000);
    await readSession({ repoId: REPO, path: sessionPath, now: () => later });
    await expect(stat(sessionPath)).rejects.toThrow();
  });
});

describe('permission hardening', () => {
  it('a session file with mode 0644 is deleted rather than trusted', async () => {
    await writeSession({ repoId: REPO, path: sessionPath, entries: ENTRIES, current: KEY_ID });
    const { chmod } = await import('node:fs/promises');
    await chmod(sessionPath, 0o644);

    const keys = await readSession({ repoId: REPO, path: sessionPath });
    expect(keys.current()).toBeNull();
    await expect(stat(sessionPath)).rejects.toThrow();
  });

  it('warns when discarding a loosely-permissioned session file', async () => {
    const { chmod } = await import('node:fs/promises');
    await writeSession({ repoId: REPO, path: sessionPath, entries: ENTRIES, current: KEY_ID });
    await chmod(sessionPath, 0o666);
    const warn = vi.fn();
    await readSession({ repoId: REPO, path: sessionPath, warn });
    expect(warn).toHaveBeenCalled();
  });

  it('a correctly-permissioned 0600 file is trusted', async () => {
    await writeSession({ repoId: REPO, path: sessionPath, entries: ENTRIES, current: KEY_ID });
    const keys = await readSession({ repoId: REPO, path: sessionPath });
    expect(keys.current()).not.toBeNull();
  });
});

describe('malformed session data', () => {
  it('a session file that is not valid JSON is treated as locked, not an error', async () => {
    await mkdir(join(dir, 'nested'), { recursive: true });
    await writeFile(sessionPath, 'not json at all', { mode: 0o600 });
    const keys = await readSession({ repoId: REPO, path: sessionPath });
    expect(keys.current()).toBeNull();
    expect(keys.available()).toEqual([]);
  });

  it('a session file for a different repoId is treated as locked', async () => {
    await writeSession({ repoId: 'some-other-repo', path: sessionPath, entries: ENTRIES, current: KEY_ID });
    const keys = await readSession({ repoId: REPO, path: sessionPath });
    expect(keys.current()).toBeNull();
  });
});

describe('lockSession()', () => {
  it('removes an existing session file', async () => {
    await writeSession({ repoId: REPO, path: sessionPath, entries: ENTRIES, current: KEY_ID });
    await lockSession({ repoId: REPO, path: sessionPath });
    await expect(stat(sessionPath)).rejects.toThrow();
  });

  it('is a no-op when no session exists', async () => {
    await expect(lockSession({ repoId: REPO, path: sessionPath })).resolves.not.toThrow();
  });

  it('locking then reading is indistinguishable from never having unlocked', async () => {
    await writeSession({ repoId: REPO, path: sessionPath, entries: ENTRIES, current: KEY_ID });
    await lockSession({ repoId: REPO, path: sessionPath });
    const keys = await readSession({ repoId: REPO, path: sessionPath });
    expect(keys.current()).toBeNull();
    expect(keys.available()).toEqual([]);
  });
});

describe('bridges to filter.ts\'s KeySource contract', () => {
  it('clean/smudge round-trip through a real session', async () => {
    await writeSession({ repoId: REPO, path: sessionPath, entries: ENTRIES, current: KEY_ID });
    const keys = await readSession({ repoId: REPO, path: sessionPath });
    const pt = Buffer.from('{"timeout":30}\n');
    const path = 'config/production.json';
    const out = clean(pt, { keys, path });
    expect(smudge(out, { keys, path }).equals(pt)).toBe(true);
  });

  it('clean fails closed once the session has expired', async () => {
    const base = new Date('2026-09-01T10:00:00.000Z');
    await writeSession({
      repoId: REPO, path: sessionPath, entries: ENTRIES, current: KEY_ID,
      ttlSeconds: 60, now: () => base,
    });
    const later = new Date(base.getTime() + 3600 * 1000);
    const keys = await readSession({ repoId: REPO, path: sessionPath, now: () => later });
    expect(() => clean(Buffer.from('x'), { keys, path: 'a.env' })).toThrow(LockedError);
  });
});
