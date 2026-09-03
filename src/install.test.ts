import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { execFile as execFileCb } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, rm, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  InstallError,
  install,
  protect,
  unprotect,
  swapPattern,
  EXCLUSION_LINE,
} from './install.js';

const execFile = promisify(execFileCb);

async function git(repoDir: string, args: string[]): Promise<string> {
  const { stdout } = await execFile('git', args, { cwd: repoDir });
  return stdout.replace(/\n$/, '');
}

async function configGet(repoDir: string, key: string): Promise<string | null> {
  try {
    return await git(repoDir, ['config', '--local', '--get', key]);
  } catch (e) {
    if ((e as { code?: number }).code === 1) return null;
    throw e;
  }
}

async function snapshot(repoDir: string, keys: string[]): Promise<Record<string, string | null>> {
  const out: Record<string, string | null> = {};
  for (const k of keys) out[k] = await configGet(repoDir, k);
  return out;
}

const ALL_KEYS = [
  'filter.securegit.clean',
  'filter.securegit.smudge',
  'filter.securegit.process',
  'filter.securegit.required',
  'diff.securegit.textconv',
  'diff.securegit.cachetextconv',
  'merge.securegit.name',
  'merge.securegit.driver',
];

let dir: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'securegit-install-'));
  await execFile('git', ['init', '--quiet'], { cwd: dir });
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe('install()', () => {
  it('writes the clean/smudge/required/diff/merge configuration', async () => {
    await install({ repoDir: dir });
    expect(await snapshot(dir, ALL_KEYS)).toEqual({
      'filter.securegit.clean': 'securegit clean -- %f',
      'filter.securegit.smudge': 'securegit smudge -- %f',
      'filter.securegit.process': null,
      'filter.securegit.required': 'true',
      'diff.securegit.textconv': 'securegit textconv --',
      'diff.securegit.cachetextconv': 'false',
      'merge.securegit.name': 'securegit encrypted three-way merge',
      'merge.securegit.driver': 'securegit merge -- %O %A %B %L %P',
    });
  });

  it('writes the process form instead when requested', async () => {
    await install({ repoDir: dir, process: true });
    expect(await snapshot(dir, ALL_KEYS)).toEqual({
      'filter.securegit.clean': null,
      'filter.securegit.smudge': null,
      'filter.securegit.process': 'securegit filter-process',
      'filter.securegit.required': 'true',
      'diff.securegit.textconv': 'securegit textconv --',
      'diff.securegit.cachetextconv': 'false',
      'merge.securegit.name': 'securegit encrypted three-way merge',
      'merge.securegit.driver': 'securegit merge -- %O %A %B %L %P',
    });
  });

  it('honours required: false', async () => {
    await install({ repoDir: dir, required: false });
    expect(await configGet(dir, 'filter.securegit.required')).toBe('false');
  });

  it('uses a custom bin in every command line', async () => {
    await install({ repoDir: dir, bin: '/opt/securegit/bin/securegit' });
    expect(await configGet(dir, 'filter.securegit.clean')).toBe(
      '/opt/securegit/bin/securegit clean -- %f',
    );
    expect(await configGet(dir, 'diff.securegit.textconv')).toBe(
      '/opt/securegit/bin/securegit textconv --',
    );
    expect(await configGet(dir, 'merge.securegit.driver')).toBe(
      '/opt/securegit/bin/securegit merge -- %O %A %B %L %P',
    );
  });

  it('is idempotent — a second run changes nothing', async () => {
    await install({ repoDir: dir });
    const before = await snapshot(dir, ALL_KEYS);
    await install({ repoDir: dir });
    expect(await snapshot(dir, ALL_KEYS)).toEqual(before);
  });

  it('switching to --process removes the clean/smudge entries', async () => {
    await install({ repoDir: dir });
    await install({ repoDir: dir, process: true });
    expect(await configGet(dir, 'filter.securegit.clean')).toBeNull();
    expect(await configGet(dir, 'filter.securegit.smudge')).toBeNull();
    expect(await configGet(dir, 'filter.securegit.process')).toBe('securegit filter-process');
  });

  it('switching back from --process removes the process entry', async () => {
    await install({ repoDir: dir, process: true });
    await install({ repoDir: dir });
    expect(await configGet(dir, 'filter.securegit.process')).toBeNull();
    expect(await configGet(dir, 'filter.securegit.clean')).toBe('securegit clean -- %f');
  });

  it('leaves unrelated git config untouched', async () => {
    await git(dir, ['config', '--local', 'user.name', 'Test User']);
    await install({ repoDir: dir });
    expect(await configGet(dir, 'user.name')).toBe('Test User');
  });

  it('refuses to run outside a git repository', async () => {
    const bare = await mkdtemp(join(tmpdir(), 'securegit-notgit-'));
    try {
      await expect(install({ repoDir: bare })).rejects.toThrow();
    } finally {
      await rm(bare, { recursive: true, force: true });
    }
  });

  it('never writes its filter/diff/merge configuration into any tracked, committed file', async () => {
    // `install()` only ever writes local (`.git/config`) scope — never
    // committed, by construction, since `.git` itself can never be tracked
    // inside its own working tree. This proves that end to end: everything
    // install/protect touch or could touch gets committed, then every
    // committed blob is checked for the literal command strings install()
    // writes to git config.
    await install({ repoDir: dir });
    await protect(dir, ['config/production.json']);
    await writeFile(join(dir, 'README.md'), '# example repo\n', 'utf8');
    await git(dir, ['add', '-A']);
    await git(dir, [
      '-c',
      'user.name=Test',
      '-c',
      'user.email=test@example.com',
      'commit',
      '--quiet',
      '-m',
      'init',
    ]);

    const tracked = (await git(dir, ['ls-files'])).split('\n').filter(Boolean);
    expect(tracked.length).toBeGreaterThan(0);
    for (const path of tracked) {
      const content = (await execFile('git', ['show', `HEAD:${path}`], { cwd: dir })).stdout;
      expect(content).not.toContain('filter.securegit');
      expect(content).not.toContain('securegit clean');
      expect(content).not.toContain('securegit smudge');
    }
  });

  describe('foreign configuration (T10)', () => {
    it('refuses to overwrite a filter.securegit.clean it did not write', async () => {
      await git(dir, ['config', '--local', 'filter.securegit.clean', 'some-other-tool --encrypt']);
      await expect(install({ repoDir: dir })).rejects.toBeInstanceOf(InstallError);
      // and it must not have touched it
      expect(await configGet(dir, 'filter.securegit.clean')).toBe('some-other-tool --encrypt');
    });

    it("names the conflicting key and its value in the error", async () => {
      await git(dir, ['config', '--local', 'filter.securegit.clean', 'some-other-tool --encrypt']);
      try {
        await install({ repoDir: dir });
        expect.unreachable('should have thrown');
      } catch (e) {
        const message = (e as Error).message;
        expect(message).toContain('filter.securegit.clean');
        expect(message).toContain('some-other-tool --encrypt');
      }
    });

    it('refuses to overwrite a foreign diff.securegit.textconv', async () => {
      await git(dir, ['config', '--local', 'diff.securegit.textconv', 'cat']);
      await expect(install({ repoDir: dir })).rejects.toBeInstanceOf(InstallError);
    });

    it('refuses to overwrite a foreign merge.securegit.driver', async () => {
      await git(dir, ['config', '--local', 'merge.securegit.driver', 'some-other-tool merge']);
      await expect(install({ repoDir: dir })).rejects.toBeInstanceOf(InstallError);
      expect(await configGet(dir, 'merge.securegit.driver')).toBe('some-other-tool merge');
    });

    it('does not treat its own other-form value as foreign', async () => {
      // A repo already configured for --process is not "foreign" to a
      // plain install — it is the same tool, the other supported form.
      await install({ repoDir: dir, process: true });
      await expect(install({ repoDir: dir })).resolves.not.toThrow();
    });

    it('force overwrites a foreign entry', async () => {
      await git(dir, ['config', '--local', 'filter.securegit.clean', 'some-other-tool --encrypt']);
      await install({ repoDir: dir, force: true });
      expect(await configGet(dir, 'filter.securegit.clean')).toBe('securegit clean -- %f');
    });
  });
});

describe('protect()', () => {
  const gitattributesPath = (): string => join(dir, '.gitattributes');
  const readAttrs = async (): Promise<string> => readFile(gitattributesPath(), 'utf8');

  it('refuses an empty pattern list', async () => {
    await expect(protect(dir, [])).rejects.toBeInstanceOf(InstallError);
  });

  it('creates .gitattributes with the pattern line and the exclusion last', async () => {
    await protect(dir, ['.env']);
    const lines = (await readAttrs()).trimEnd().split('\n');
    expect(lines).toEqual(['.env filter=securegit diff=securegit merge=securegit -text', EXCLUSION_LINE]);
  });

  it('writes the exact documented line format', async () => {
    await protect(dir, ['*.secret']);
    expect(await readAttrs()).toContain('*.secret filter=securegit diff=securegit merge=securegit -text\n');
  });

  it('appends a new pattern to an existing file, exclusion still last', async () => {
    await protect(dir, ['.env']);
    await protect(dir, ['*.secret']);
    const lines = (await readAttrs()).trimEnd().split('\n');
    expect(lines).toEqual([
      '.env filter=securegit diff=securegit merge=securegit -text',
      '*.secret filter=securegit diff=securegit merge=securegit -text',
      EXCLUSION_LINE,
    ]);
  });

  it('is idempotent — protecting the same pattern twice does not duplicate it', async () => {
    await protect(dir, ['.env']);
    await protect(dir, ['.env']);
    const lines = (await readAttrs()).trimEnd().split('\n');
    expect(lines.filter((l) => l.startsWith('.env '))).toHaveLength(1);
  });

  it('preserves unrelated existing lines and comments', async () => {
    await writeFile(gitattributesPath(), '# managed elsewhere\n*.png binary\n', 'utf8');
    await protect(dir, ['.env']);
    const content = await readAttrs();
    expect(content).toContain('# managed elsewhere');
    expect(content).toContain('*.png binary');
    expect(content).toContain('.env filter=securegit diff=securegit merge=securegit -text');
  });

  it('moves a stray exclusion line back to the end', async () => {
    await writeFile(gitattributesPath(), `${EXCLUSION_LINE}\n*.png binary\n`, 'utf8');
    await protect(dir, ['.env']);
    const lines = (await readAttrs()).trimEnd().split('\n');
    expect(lines[lines.length - 1]).toBe(EXCLUSION_LINE);
    expect(lines.filter((l) => l === EXCLUSION_LINE)).toHaveLength(1);
  });

  it('accepts multiple patterns in one call', async () => {
    await protect(dir, ['.env', '*.secret', 'config/production.*']);
    const content = await readAttrs();
    expect(content).toContain('.env filter=securegit diff=securegit merge=securegit -text');
    expect(content).toContain('*.secret filter=securegit diff=securegit merge=securegit -text');
    expect(content).toContain('config/production.* filter=securegit diff=securegit merge=securegit -text');
  });

  it('recipient files are never filtered, even under a catch-all protect pattern', async () => {
    // The exclusion line is written last (asserted above), which is what
    // makes it win over even the broadest possible pattern — proved here
    // against real git attribute resolution, not just the file's line order.
    await protect(dir, ['**']);
    const check = await git(dir, [
      'check-attr',
      'filter',
      '--',
      '.securegit/recipients/deadbeef.json',
    ]);
    expect(check).toContain('filter: unset');
  });

  describe('residue .gitignore entries (T12)', () => {
    const gitignorePath = (): string => join(dir, '.gitignore');
    const readIgnore = async (): Promise<string> =>
      readFile(gitignorePath(), 'utf8').catch(() => '');

    it('writes the five suffix forms plus the swap-file form', async () => {
      await protect(dir, ['.env']);
      const content = await readIgnore();
      for (const line of ['.env~', '.env.orig', '.env.rej', '.env.bak', '.env.save', '..env.sw?']) {
        expect(content).toContain(`${line}\n`);
      }
    });

    it('is idempotent', async () => {
      await protect(dir, ['.env']);
      await protect(dir, ['.env']);
      const lines = (await readIgnore()).trimEnd().split('\n');
      expect(lines.filter((l) => l === '.env~')).toHaveLength(1);
    });

    it('preserves existing .gitignore content', async () => {
      await writeFile(gitignorePath(), 'node_modules/\n', 'utf8');
      await protect(dir, ['.env']);
      const content = await readIgnore();
      expect(content).toContain('node_modules/');
      expect(content).toContain('.env~');
    });

    it('can be disabled', async () => {
      await protect(dir, ['.env'], { residuePatterns: false });
      const content = await readIgnore();
      expect(content).not.toContain('.env~');
    });
  });
});

describe('unprotect()', () => {
  const gitattributesPath = (): string => join(dir, '.gitattributes');
  const readAttrs = async (): Promise<string> => readFile(gitattributesPath(), 'utf8');
  const gitignorePath = (): string => join(dir, '.gitignore');
  const readIgnore = async (): Promise<string> => readFile(gitignorePath(), 'utf8').catch(() => '');

  it('refuses an empty pattern list', async () => {
    await expect(unprotect(dir, [])).rejects.toBeInstanceOf(InstallError);
  });

  it('removes the pattern line, keeping the exclusion line', async () => {
    await protect(dir, ['.env']);
    await unprotect(dir, ['.env']);
    const lines = (await readAttrs()).trimEnd().split('\n');
    expect(lines).toEqual([EXCLUSION_LINE]);
  });

  it('removes only the named pattern, leaving the others intact', async () => {
    await protect(dir, ['.env', '*.secret']);
    await unprotect(dir, ['.env']);
    const content = await readAttrs();
    expect(content).not.toContain('.env filter=securegit');
    expect(content).toContain('*.secret filter=securegit');
  });

  it('accepts multiple patterns in one call', async () => {
    await protect(dir, ['.env', '*.secret', 'config/production.*']);
    await unprotect(dir, ['.env', '*.secret']);
    const content = await readAttrs();
    expect(content).not.toContain('.env filter=securegit');
    expect(content).not.toContain('*.secret filter=securegit');
    expect(content).toContain('config/production.* filter=securegit');
  });

  it('is a silent no-op for a pattern that was never protected', async () => {
    await protect(dir, ['.env']);
    await unprotect(dir, ['*.never-protected']);
    const content = await readAttrs();
    expect(content).toContain('.env filter=securegit');
  });

  it('does not touch .gitignore residue entries — harmless once unprotected, and removing them could unhide real residue', async () => {
    await protect(dir, ['.env']);
    await unprotect(dir, ['.env']);
    const content = await readIgnore();
    expect(content).toContain('.env~');
  });

  it('leaves .gitattributes empty (aside from nothing, since the exclusion survives) when nothing was ever protected', async () => {
    await expect(readAttrs()).rejects.toThrow(); // no .gitattributes exists yet
    await unprotect(dir, ['.env']); // no-op, must not throw
    await expect(readAttrs()).rejects.toThrow(); // still doesn't exist
  });
});

describe('swapPattern()', () => {
  it('prefixes the basename with a dot and appends .sw?', () => {
    expect(swapPattern('app.env')).toBe('.app.env.sw?');
  });

  it('keeps the directory and only touches the basename', () => {
    expect(swapPattern('config/production.json')).toBe('config/.production.json.sw?');
  });

  it('double-dots a dotfile, matching real vim behaviour', () => {
    // Vim really does prepend an extra dot for a name that already starts
    // with one — this looks odd and is correct.
    expect(swapPattern('.env')).toBe('..env.sw?');
  });
});
