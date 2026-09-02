import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execFile as execFileCb, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, rm, mkdir, writeFile, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { MAGIC } from './envelope.js';

const execFileP = promisify(execFileCb);

const REPO_ROOT = join(import.meta.dirname, '..');
const BIN = join(REPO_ROOT, 'dist', 'bin', 'securegit.js');
const FILTER_BIN = `node "${BIN}"`;
const PASSPHRASE = 'correct horse battery staple';
const PROTECTED_PATH = 'config/production.json';
const PLAINTEXT = Buffer.from('{"password":"hunter2"}\n');

// Proves Phase 1's acceptance criterion for real: a real `git` binary,
// running the real compiled securegit binary as its clean/smudge/textconv
// filter, over a real commit / push / clone / unlock / checkout cycle — not
// the injected-IO cli.ts unit tests, and not a stub filter. Builds once.
beforeAll(async () => {
  await execFileP('npm', ['run', 'build'], { cwd: REPO_ROOT });
}, 60_000);

const GIT_ENV = (home: string): NodeJS.ProcessEnv => ({
  PATH: process.env.PATH,
  HOME: home,
  GIT_AUTHOR_NAME: 'Test',
  GIT_AUTHOR_EMAIL: 'test@example.com',
  GIT_COMMITTER_NAME: 'Test',
  GIT_COMMITTER_EMAIL: 'test@example.com',
});

/**
 * `git diff` spawns our `textconv` command, which inherits whatever stdin
 * `git` itself was given. Node's `execFile` leaves a child's stdin as an
 * open, never-closed pipe by default — harmless for most git subcommands,
 * but `textconv` blocks reading it to EOF for content that never arrives.
 * Every spawned git process gets its stdin explicitly closed for exactly
 * this reason, not only the ones that obviously need it.
 */
async function spawnCapture(
  cmd: string,
  args: string[],
  opts: { cwd: string; env: NodeJS.ProcessEnv },
): Promise<{ stdout: Buffer; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { cwd: opts.cwd, env: opts.env });
    const outChunks: Buffer[] = [];
    const errChunks: Buffer[] = [];
    child.stdout.on('data', (c: Buffer) => outChunks.push(c));
    child.stderr.on('data', (c: Buffer) => errChunks.push(c));
    child.on('error', reject);
    child.on('close', (code: number) => {
      const stderr = Buffer.concat(errChunks).toString('utf8');
      if (code === 0) resolve({ stdout: Buffer.concat(outChunks), stderr });
      else reject(new Error(`${cmd} ${args.join(' ')} exited ${code}: ${stderr}`));
    });
    child.stdin.end();
  });
}

async function git(repoDir: string, home: string, args: string[]): Promise<string> {
  const { stdout } = await spawnCapture('git', args, { cwd: repoDir, env: GIT_ENV(home) });
  return stdout.toString('utf8').replace(/\n$/, '');
}

async function gitBuffer(repoDir: string, home: string, args: string[]): Promise<Buffer> {
  const { stdout } = await spawnCapture('git', args, { cwd: repoDir, env: GIT_ENV(home) });
  return stdout;
}

async function securegit(repoDir: string, home: string, args: string[]): Promise<void> {
  await spawnCapture('node', [BIN, ...args], {
    cwd: repoDir,
    env: { PATH: process.env.PATH, HOME: home, SECUREGIT_PASSPHRASE: PASSPHRASE },
  });
}

async function initRepo(repoDir: string, home: string): Promise<void> {
  await git(repoDir, home, ['init', '--quiet', '-b', 'main']); // don't inherit the host's default branch name
  await git(repoDir, home, ['config', 'user.name', 'Test']);
  await git(repoDir, home, ['config', 'user.email', 'test@example.com']);
  await securegit(repoDir, home, ['init']);
  await securegit(repoDir, home, ['install', '--bin', FILTER_BIN]);
  await securegit(repoDir, home, ['protect', PROTECTED_PATH]);
  await securegit(repoDir, home, ['unlock']);
}

let dir: string;
let home: string;

describe('a real Git repository with a real securegit filter', () => {
  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), 'securegit-git-repo-'));
    home = await mkdtemp(join(tmpdir(), 'securegit-git-home-'));
    await initRepo(dir, home);

    await mkdir(join(dir, 'config'), { recursive: true });
    await writeFile(join(dir, PROTECTED_PATH), PLAINTEXT);
    // -A, not just the protected path: .gitattributes/.gitignore/.securegit
    // are securegit's own tracked files and must be committed too.
    await git(dir, home, ['add', '-A']);
    await git(dir, home, ['commit', '--quiet', '-m', 'add production config']);
  }, 30_000);

  afterAll(async () => {
    await rm(dir, { recursive: true, force: true });
    await rm(home, { recursive: true, force: true });
  });

  it('git status is clean immediately after commit — the property the whole design exists for', async () => {
    expect(await git(dir, home, ['status', '--porcelain'])).toBe('');
  });

  it('the committed blob is ciphertext, not plaintext', async () => {
    const blob = await gitBuffer(dir, home, ['cat-file', '-p', `HEAD:${PROTECTED_PATH}`]);
    expect(blob.subarray(0, MAGIC.length).equals(MAGIC)).toBe(true);
    expect(blob.includes(Buffer.from('hunter2'))).toBe(false);
  });

  it('the worktree file itself reads back as plaintext', async () => {
    expect((await readFile(join(dir, PROTECTED_PATH))).equals(PLAINTEXT)).toBe(true);
  });

  it('re-adding the unchanged file produces no new blob and no dirty status', async () => {
    const before = await git(dir, home, ['rev-parse', `HEAD:${PROTECTED_PATH}`]);
    await git(dir, home, ['add', PROTECTED_PATH]);
    expect(await git(dir, home, ['status', '--porcelain'])).toBe('');
    expect(await git(dir, home, ['rev-parse', `HEAD:${PROTECTED_PATH}`])).toBe(before);
  });

  it('git diff shows a real plaintext hunk via textconv', async () => {
    await writeFile(join(dir, PROTECTED_PATH), Buffer.from('{"password":"hunter3"}\n'));
    const diff = await git(dir, home, ['diff', PROTECTED_PATH]);
    expect(diff).toContain('-{"password":"hunter2"}');
    expect(diff).toContain('+{"password":"hunter3"}');
    await git(dir, home, ['checkout', '--', PROTECTED_PATH]); // restore
  });

  it('git stash / stash pop leaves a clean tree and correct plaintext', async () => {
    await writeFile(join(dir, PROTECTED_PATH), Buffer.from('{"password":"temporary-edit"}\n'));
    await git(dir, home, ['stash']);
    expect(await git(dir, home, ['status', '--porcelain'])).toBe('');
    expect((await readFile(join(dir, PROTECTED_PATH))).equals(PLAINTEXT)).toBe(true);

    await git(dir, home, ['stash', 'pop']);
    expect((await readFile(join(dir, PROTECTED_PATH))).toString('utf8')).toContain('temporary-edit');
    await git(dir, home, ['checkout', '--', PROTECTED_PATH]); // restore
    expect(await git(dir, home, ['status', '--porcelain'])).toBe('');
  });

  it('switching branches and back leaves a clean tree', async () => {
    await git(dir, home, ['checkout', '--quiet', '-b', 'feature']);
    expect(await git(dir, home, ['status', '--porcelain'])).toBe('');
    await git(dir, home, ['checkout', '--quiet', 'main']);
    expect(await git(dir, home, ['status', '--porcelain'])).toBe('');
    expect((await readFile(join(dir, PROTECTED_PATH))).equals(PLAINTEXT)).toBe(true);
  });

  it('F16: locked, re-adding an unmodified protected file is a silent no-op, not a locked error', async () => {
    // `clean` itself always fails closed when locked ([07](07-unlock-session.md),
    // filter.test.ts) — there is no passthrough case inside it. This works
    // anyway because Git never calls the filter at all here: a path whose
    // worktree content still matches what the index already records is
    // skipped by `add`'s own stat-cache short-circuit, the same class of
    // optimization behind why `checkout --force` doesn't re-run `smudge`
    // (15-failure-modes.md). Touching the file first (same content, new
    // mtime) forces Git to re-invoke the filter, which then correctly fails
    // closed.
    await securegit(dir, home, ['lock']);
    try {
      await git(dir, home, ['add', PROTECTED_PATH]);
      expect(await git(dir, home, ['status', '--porcelain'])).toBe('');

      // Rewriting the same bytes still bumps mtime, forcing Git to actually
      // re-evaluate the path instead of trusting its stat cache — and locked
      // correctly fails that.
      await writeFile(join(dir, PROTECTED_PATH), PLAINTEXT);
      await expect(git(dir, home, ['add', PROTECTED_PATH])).rejects.toThrow(/locked/);
    } finally {
      await securegit(dir, home, ['unlock']); // leave state clean for the tests below
      await git(dir, home, ['checkout', '--', PROTECTED_PATH]); // discard the failed add attempt's fallout, if any
    }
    expect(await git(dir, home, ['status', '--porcelain'])).toBe('');
  });

  describe('a clone of the repository', () => {
    let bareDir: string;
    let cloneDir: string;

    beforeAll(async () => {
      bareDir = await mkdtemp(join(tmpdir(), 'securegit-git-bare-'));
      await rm(bareDir, { recursive: true, force: true }); // git init --bare wants it absent
      await git(dir, home, ['init', '--quiet', '--bare', bareDir]);
      await git(dir, home, ['remote', 'add', 'origin', bareDir]);
      await git(dir, home, ['push', '--quiet', 'origin', 'main']);

      cloneDir = await mkdtemp(join(tmpdir(), 'securegit-git-clone-'));
      await rm(cloneDir, { recursive: true, force: true });
      await git(dir, home, ['clone', '--quiet', '--branch', 'main', bareDir, cloneDir]);
    }, 30_000);

    afterAll(async () => {
      await rm(bareDir, { recursive: true, force: true });
      await rm(cloneDir, { recursive: true, force: true });
    });

    it('checks out as ciphertext before `install` has ever run there', async () => {
      const content = await readFile(join(cloneDir, PROTECTED_PATH));
      expect(content.subarray(0, MAGIC.length).equals(MAGIC)).toBe(true);
      expect(content.includes(Buffer.from('hunter2'))).toBe(false);
    });

    it('`install` + `unlock` + re-checkout restores the real plaintext', async () => {
      // Same `home`: this models a second checkout by someone who already
      // holds the keyring, not a brand-new recipient (that path is spec 08,
      // not yet built).
      //
      // Git will NOT rerun smudge on its own here. The clone already has a
      // worktree file whose content matches what the index expects (the
      // ciphertext blob, checked out before `install` ever ran), so both
      // `git checkout --force .` and even the lower-level
      // `git checkout-index --force --all` skip rewriting it entirely
      // ("Updated 0 paths") -- git's stat-cache optimization assumes an
      // unchanged path needs no filter re-run, regardless of --force. The
      // file has to be removed first so git has no choice but to
      // re-materialize it from the index, which is what actually reruns
      // smudge. This is standard advice for git-crypt/git-lfs style tools
      // too, not a securegit-specific quirk.
      await securegit(cloneDir, home, ['install', '--bin', FILTER_BIN]);
      await securegit(cloneDir, home, ['unlock']);
      await rm(join(cloneDir, PROTECTED_PATH));
      await git(cloneDir, home, ['checkout', '--quiet', '--', '.']);

      const content = await readFile(join(cloneDir, PROTECTED_PATH));
      expect(content.equals(PLAINTEXT)).toBe(true);
      expect(await git(cloneDir, home, ['status', '--porcelain'])).toBe('');
    });
  });
});
