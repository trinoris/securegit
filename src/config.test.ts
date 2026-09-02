import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, rm, mkdir, stat, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  ConfigError,
  configPath,
  resolveKeyringPath,
  generateRepoId,
  initConfig,
  readConfig,
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
  it('creates config.json with a generated repoId and bindPath false by default', async () => {
    const config = await initConfig(dir);
    expect(config.version).toBe(1);
    expect(config.repoId).toMatch(/^[0-9a-f]{32}$/);
    expect(config.bindPath).toBe(false);
  });

  it('honours bindPath: true', async () => {
    const config = await initConfig(dir, { bindPath: true });
    expect(config.bindPath).toBe(true);
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
