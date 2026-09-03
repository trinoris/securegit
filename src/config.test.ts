import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, rm, mkdir, stat, readFile, writeFile, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  ConfigError,
  configPath,
  resolveKeyringPath,
  generateRepoId,
  initConfig,
  readConfig,
  setBindPath,
} from './config.js';

let dir: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'securegit-config-'));
  await mkdir(join(dir, '.git'));
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe('configPath()', () => {
  it('is .securegit/config.json under the repo root', () => {
    expect(configPath('/repo')).toBe(join('/repo', '.securegit', 'config.json'));
  });
});

describe('resolveKeyringPath()', () => {
  it('is scoped by repoId under the home directory', () => {
    expect(resolveKeyringPath('abc123', '/home/u')).toBe(
      join('/home/u', '.securegit', 'repos', 'abc123', 'keyring.json'),
    );
  });

  it('two repos never collide', () => {
    expect(resolveKeyringPath('a', '/home/u')).not.toBe(resolveKeyringPath('b', '/home/u'));
  });
});

describe('generateRepoId()', () => {
  it('is 32 lowercase hex characters', () => {
    expect(generateRepoId()).toMatch(/^[0-9a-f]{32}$/);
  });

  it('differs on every call', () => {
    expect(generateRepoId()).not.toBe(generateRepoId());
  });
});

describe('initConfig()', () => {
  it('creates config.json with a generated repoId, bindPath false and padTo 0 by default', async () => {
    const config = await initConfig(dir);
    expect(config.version).toBe(1);
    expect(config.repoId).toMatch(/^[0-9a-f]{32}$/);
    expect(config.bindPath).toBe(false);
    expect(config.padTo).toBe(0);
  });

  it('honours bindPath: true', async () => {
    const config = await initConfig(dir, { bindPath: true });
    expect(config.bindPath).toBe(true);
  });

  it('honours padTo', async () => {
    const config = await initConfig(dir, { padTo: 4096 });
    expect(config.padTo).toBe(4096);
  });

  it('rejects a negative padTo', async () => {
    await expect(initConfig(dir, { padTo: -1 })).rejects.toThrow(ConfigError);
  });

  it('rejects a non-integer padTo', async () => {
    await expect(initConfig(dir, { padTo: 1.5 })).rejects.toThrow(ConfigError);
  });

  it('writes exactly what readConfig() then reads back', async () => {
    const written = await initConfig(dir);
    expect(await readConfig(dir)).toEqual(written);
  });

  it('gives two repositories different repoIds', async () => {
    const other = await mkdtemp(join(tmpdir(), 'securegit-config-'));
    await mkdir(join(other, '.git'));
    try {
      const a = await initConfig(dir);
      const b = await initConfig(other);
      expect(a.repoId).not.toBe(b.repoId);
    } finally {
      await rm(other, { recursive: true, force: true });
    }
  });

  it('refuses to run outside a git repository', async () => {
    const notGit = await mkdtemp(join(tmpdir(), 'securegit-config-'));
    try {
      await expect(initConfig(notGit)).rejects.toBeInstanceOf(ConfigError);
    } finally {
      await rm(notGit, { recursive: true, force: true });
    }
  });

  it('accepts a worktree-style .git file, not only a .git directory', async () => {
    const worktree = await mkdtemp(join(tmpdir(), 'securegit-config-'));
    try {
      await writeFile(join(worktree, '.git'), 'gitdir: /elsewhere/.git/worktrees/x\n', 'utf8');
      await expect(initConfig(worktree)).resolves.toBeDefined();
    } finally {
      await rm(worktree, { recursive: true, force: true });
    }
  });

  it('refuses when the keyring would resolve inside the repository working tree', async () => {
    const home = join(dir, 'fake-home'); // home nested inside the repo itself
    await expect(initConfig(dir, { home })).rejects.toBeInstanceOf(ConfigError);
  });

  it('refuses when home is the repository itself', async () => {
    await expect(initConfig(dir, { home: dir })).rejects.toBeInstanceOf(ConfigError);
  });

  it('proceeds normally when home is outside the repository', async () => {
    const home = await mkdtemp(join(tmpdir(), 'securegit-config-home-'));
    try {
      await expect(initConfig(dir, { home })).resolves.toBeDefined();
    } finally {
      await rm(home, { recursive: true, force: true });
    }
  });

  it('skips the check entirely when home is not given', async () => {
    // Existing callers that never pass `home` keep working unchanged.
    await expect(initConfig(dir)).resolves.toBeDefined();
  });

  it('refuses to run twice, and leaves the original config untouched', async () => {
    const first = await initConfig(dir);
    await expect(initConfig(dir)).rejects.toBeInstanceOf(ConfigError);
    expect(await readConfig(dir)).toEqual(first);
  });

  it('the config file has no special permission restriction — it is meant to be committed', async () => {
    await initConfig(dir);
    const mode = (await stat(configPath(dir))).mode & 0o777;
    expect(mode & 0o044).not.toBe(0); // group/other can at least read it
  });

  it('produces content that is plain, readable JSON', async () => {
    await initConfig(dir);
    const raw = await readFile(configPath(dir), 'utf8');
    expect(() => JSON.parse(raw)).not.toThrow();
    expect(raw).toContain('"repoId"');
  });
});

describe('the session cache and keyring are never written inside the repository', () => {
  it("resolveKeyringPath() resolves under home, never under the repository's own directory", async () => {
    const config = await initConfig(dir);
    const home = await mkdtemp(join(tmpdir(), 'securegit-config-home-'));
    try {
      const keyringPath = resolveKeyringPath(config.repoId, home);
      expect(keyringPath.startsWith(dir)).toBe(false);
      expect(keyringPath.startsWith(home)).toBe(true);
    } finally {
      await rm(home, { recursive: true, force: true });
    }
  });

  it('initConfig() writes nothing under the repository but .securegit/config.json', async () => {
    await initConfig(dir);
    expect((await readdir(dir)).sort()).toEqual(['.git', '.securegit']);
    expect(await readdir(join(dir, '.securegit'))).toEqual(['config.json']);
  });
});

describe('readConfig()', () => {
  it('throws a clear ConfigError when no config exists', async () => {
    await expect(readConfig(dir)).rejects.toBeInstanceOf(ConfigError);
    await expect(readConfig(dir)).rejects.toThrow(/securegit init/);
  });

  it('throws ConfigError on malformed JSON rather than a raw parse error', async () => {
    await mkdir(join(dir, '.securegit'), { recursive: true });
    await writeFile(configPath(dir), 'not json', 'utf8');
    await expect(readConfig(dir)).rejects.toBeInstanceOf(ConfigError);
  });
});

// `key rotate --bind-path`'s own primitive (05-key-hierarchy.md: "the
// supported path" for changing bindPath after init, since it enters key
// derivation and every already-rotated generation must keep decrypting
// under whatever setting produced it — recorded per envelope, never read
// from here). padTo needs no equivalent: it never enters derivation, so
// 14-metadata-leakage.md's own documented path (hand-edit config.json,
// then `reencrypt`) already covers it without a dedicated primitive.
describe('setBindPath()', () => {
  it('flips bindPath, leaving repoId/padTo/version untouched', async () => {
    const before = await initConfig(dir, { padTo: 256 });
    const updated = await setBindPath(dir, true);
    expect(updated.bindPath).toBe(true);
    expect(updated.repoId).toBe(before.repoId);
    expect(updated.padTo).toBe(before.padTo);
    expect(updated.version).toBe(before.version);
  });

  it('persists — readConfig() reflects it afterward', async () => {
    await initConfig(dir);
    await setBindPath(dir, true);
    expect((await readConfig(dir)).bindPath).toBe(true);
  });

  it('can flip back to false', async () => {
    await initConfig(dir, { bindPath: true });
    const updated = await setBindPath(dir, false);
    expect(updated.bindPath).toBe(false);
    expect((await readConfig(dir)).bindPath).toBe(false);
  });

  it('throws ConfigError when the repository was never initialised', async () => {
    await expect(setBindPath(dir, true)).rejects.toBeInstanceOf(ConfigError);
  });

  it('leaves no stray temp file behind', async () => {
    await initConfig(dir);
    await setBindPath(dir, true);
    expect(await readdir(join(dir, '.securegit'))).toEqual(['config.json']);
  });
});
