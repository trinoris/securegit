import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execFile as execFileCb, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, rm, mkdir, writeFile, readFile, utimes, readdir } from 'node:fs/promises';
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

  it('git log -p shows plaintext across commits, via textconv, never the envelope', async () => {
    const log = await git(dir, home, ['log', '-p', '--', PROTECTED_PATH]);
    expect(log).toContain('hunter2');
    expect(log).not.toContain('SECUREGIT'); // the envelope's magic marker — never shown
  });

  it('textconv never writes to the object database', async () => {
    const before = await git(dir, home, ['count-objects']);
    await git(dir, home, ['log', '-p', '--', PROTECTED_PATH]); // invokes textconv once per commit touching the path
    const after = await git(dir, home, ['count-objects']);
    expect(after).toBe(before);
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

      // An explicit future mtime, not a same-content rewrite: some
      // filesystems have coarse (1s) mtime resolution, and a rewrite that
      // happens to land in the same tick wouldn't actually change what Git's
      // stat cache sees, making this assertion flaky for the wrong reason.
      const future = new Date(Date.now() + 60_000);
      await utimes(join(dir, PROTECTED_PATH), future, future);
      await expect(git(dir, home, ['add', PROTECTED_PATH])).rejects.toThrow(/locked/);
    } finally {
      await securegit(dir, home, ['unlock']); // leave state clean for the tests below
      await git(dir, home, ['checkout', '--', PROTECTED_PATH]); // discard the failed add attempt's fallout, if any
    }
    expect(await git(dir, home, ['status', '--porcelain'])).toBe('');
  });

  it('F1: a filter failure aborts `git add`, leaves the index unchanged, and writes nothing to the object database', async () => {
    // `clean`'s only failure mode is `LockedError` ([07](07-unlock-session.md))
    // — there is no other way for the filter to exit non-zero — so proving
    // this for the locked case proves it for every failure path there is.
    const beforeIndexSha = await git(dir, home, ['rev-parse', `:${PROTECTED_PATH}`]);
    const objectsBefore = await git(dir, home, ['count-objects']);

    await writeFile(join(dir, PROTECTED_PATH), Buffer.from('{"password":"never-should-be-committed"}\n'));
    const future = new Date(Date.now() + 120_000);
    await utimes(join(dir, PROTECTED_PATH), future, future); // force git to re-invoke the filter, not skip via its stat cache

    await securegit(dir, home, ['lock']);
    try {
      await expect(git(dir, home, ['add', PROTECTED_PATH])).rejects.toThrow(/locked/);
      // the index still points at the old (ciphertext) blob — nothing staged
      expect(await git(dir, home, ['rev-parse', `:${PROTECTED_PATH}`])).toBe(beforeIndexSha);
      // and no object of any kind was written trying — the filter throws
      // before `add` ever reaches its own hash-object step
      expect(await git(dir, home, ['count-objects'])).toBe(objectsBefore);
    } finally {
      await securegit(dir, home, ['unlock']);
      await git(dir, home, ['checkout', '--', PROTECTED_PATH]); // discard the failed attempt's worktree edit
    }
    expect(await git(dir, home, ['status', '--porcelain'])).toBe('');
  });

  describe('merging a protected file through a real `git merge`', () => {
    // diff3 needs an unchanged line of context between two edits to treat
    // them as independent hunks (src/merge.test.ts) — a single-line JSON
    // body can't demonstrate a non-overlapping merge at all.
    const BASE = '{\n  "a": 1,\n  "x": true,\n  "y": true,\n  "b": 2\n}\n';

    async function branchFrom(from: string, name: string): Promise<void> {
      await git(dir, home, ['checkout', '--quiet', from]);
      await git(dir, home, ['checkout', '--quiet', '-b', name]);
    }

    async function commitContent(branch: string, content: string): Promise<void> {
      await writeFile(join(dir, PROTECTED_PATH), content);
      await git(dir, home, ['commit', '--quiet', '-am', `update on ${branch}`]);
    }

    it('resolves a non-overlapping merge cleanly, decrypted in the worktree, ciphertext in the object database', async () => {
      const originalMainHead = await git(dir, home, ['rev-parse', 'main']);
      try {
        await branchFrom('main', 'merge-base');
        await commitContent('merge-base', BASE);

        await branchFrom('merge-base', 'merge-ours');
        await commitContent('merge-ours', BASE.replace('"a": 1', '"a": 10'));

        await branchFrom('merge-base', 'merge-theirs');
        await commitContent('merge-theirs', BASE.replace('"b": 2', '"b": 20'));

        await git(dir, home, ['checkout', '--quiet', 'merge-ours']);
        await git(dir, home, ['merge', '--quiet', '--no-edit', 'merge-theirs']);

        expect(await git(dir, home, ['status', '--porcelain'])).toBe('');
        expect(await readFile(join(dir, PROTECTED_PATH), 'utf8')).toBe(
          '{\n  "a": 10,\n  "x": true,\n  "y": true,\n  "b": 20\n}\n',
        );

        const committed = await gitBuffer(dir, home, ['cat-file', '-p', `HEAD:${PROTECTED_PATH}`]);
        expect(committed.subarray(0, MAGIC.length).equals(MAGIC)).toBe(true);
        expect(committed.includes(Buffer.from('"a": 10'))).toBe(false);
      } finally {
        await git(dir, home, ['checkout', '--quiet', 'main']);
        await git(dir, home, ['branch', '-D', 'merge-base', 'merge-ours', 'merge-theirs']);
      }
      // The merge happened on throwaway branches — main, and every test
      // after this one, must see exactly the state that existed before it.
      expect(await git(dir, home, ['rev-parse', 'main'])).toBe(originalMainHead);
      expect(await git(dir, home, ['status', '--porcelain'])).toBe('');
      expect((await readFile(join(dir, PROTECTED_PATH))).equals(PLAINTEXT)).toBe(true);
    });

    it('a real conflict leaves plaintext markers in the worktree and exits nonzero', async () => {
      const originalMainHead = await git(dir, home, ['rev-parse', 'main']);
      try {
        await branchFrom('main', 'conflict-base');
        await commitContent('conflict-base', BASE);

        await branchFrom('conflict-base', 'conflict-ours');
        await commitContent('conflict-ours', BASE.replace('"a": 1', '"a": 10'));

        await branchFrom('conflict-base', 'conflict-theirs');
        await commitContent('conflict-theirs', BASE.replace('"a": 1', '"a": 999'));

        await git(dir, home, ['checkout', '--quiet', 'conflict-ours']);
        await expect(
          git(dir, home, ['merge', '--quiet', '--no-edit', 'conflict-theirs']),
        ).rejects.toThrow();

        const worktree = await readFile(join(dir, PROTECTED_PATH), 'utf8');
        expect(worktree).toContain('<<<<<<<');
        expect(worktree).toContain('=======');
        expect(worktree).toContain('>>>>>>>');
        expect((await git(dir, home, ['status', '--porcelain'])).length).toBeGreaterThan(0);

        await git(dir, home, ['merge', '--abort']);
      } finally {
        await git(dir, home, ['checkout', '--quiet', 'main']);
        await git(dir, home, ['branch', '-D', 'conflict-base', 'conflict-ours', 'conflict-theirs']);
      }
      expect(await git(dir, home, ['rev-parse', 'main'])).toBe(originalMainHead);
      expect(await git(dir, home, ['status', '--porcelain'])).toBe('');
      expect((await readFile(join(dir, PROTECTED_PATH))).equals(PLAINTEXT)).toBe(true);
    });
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
      // holds the keyring — a brand-new recipient with no keyring at all is
      // the next describe block below.
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

    it('the pushed pack on the bare remote contains no plaintext byte from the protected file', async () => {
      // A repo this small may not pack on push at all (git can decide loose
      // objects suffice) — force a real pack so this actually exercises the
      // packed representation, not just loose objects (already covered by
      // "`.git/objects` contains no plaintext after `add`+`commit`",
      // 01-threat-model.md).
      await git(bareDir, home, ['repack', '-a', '-d', '-q']);
      const packDir = join(bareDir, 'objects', 'pack');
      const packFiles = (await readdir(packDir)).filter((f) => f.endsWith('.pack'));
      expect(packFiles.length).toBeGreaterThan(0);
      for (const f of packFiles) {
        const raw = await readFile(join(packDir, f));
        expect(raw.includes(Buffer.from('hunter2'))).toBe(false);
      }
    });

    it('a bundle of the repository decrypts to nothing without the key', async () => {
      const bundleTmpDir = await mkdtemp(join(tmpdir(), 'securegit-git-bundle-'));
      const bundlePath = join(bundleTmpDir, 'repo.bundle');
      const bundleCloneDir = await mkdtemp(join(tmpdir(), 'securegit-git-bundle-clone-'));
      await rm(bundleCloneDir, { recursive: true, force: true });
      try {
        await git(dir, home, ['bundle', 'create', bundlePath, '--all']);
        // The bundle file itself, raw, carries no plaintext byte either.
        expect((await readFile(bundlePath)).includes(Buffer.from('hunter2'))).toBe(false);

        // And checking it out, without ever running `unlock`, yields ciphertext.
        await git(dir, home, ['clone', '--quiet', '--branch', 'main', bundlePath, bundleCloneDir]);
        const content = await readFile(join(bundleCloneDir, PROTECTED_PATH));
        expect(content.subarray(0, MAGIC.length).equals(MAGIC)).toBe(true);
        expect(content.includes(Buffer.from('hunter2'))).toBe(false);
      } finally {
        await rm(bundleTmpDir, { recursive: true, force: true });
        await rm(bundleCloneDir, { recursive: true, force: true });
      }
    });
  });

  describe('a second identity joins via a recipient file, across a real clone', () => {
    let bareDir: string;
    let cloneDir: string;
    let homeB: string;

    beforeAll(async () => {
      // A separate bare remote and clone from the ones above — this test
      // pushes a new commit to `dir`'s history, and must not interfere with
      // (or be interfered with by) the earlier clone describe block.
      bareDir = await mkdtemp(join(tmpdir(), 'securegit-git-bare-recipient-'));
      await rm(bareDir, { recursive: true, force: true });
      await git(dir, home, ['init', '--quiet', '--bare', bareDir]);
      await git(dir, home, ['remote', 'add', 'origin-recipient', bareDir]);
      await git(dir, home, ['push', '--quiet', 'origin-recipient', 'main']);

      cloneDir = await mkdtemp(join(tmpdir(), 'securegit-git-clone-recipient-'));
      await rm(cloneDir, { recursive: true, force: true });
      await git(dir, home, ['clone', '--quiet', '--branch', 'main', bareDir, cloneDir]);

      homeB = await mkdtemp(join(tmpdir(), 'securegit-git-home-b-'));
    }, 30_000);

    afterAll(async () => {
      await rm(bareDir, { recursive: true, force: true });
      await rm(cloneDir, { recursive: true, force: true });
      await rm(homeB, { recursive: true, force: true });
    });

    it('a fresh identity, added as a recipient and pushed, unlocks and decrypts with no local keyring', async () => {
      // "Machine B": a fresh clone and its own identity — no keyring of its
      // own anywhere, and deliberately no `install` yet either. `git pull`
      // is a safety check as much as a fetch: even a plain fast-forward
      // runs `clean` on tracked files to confirm the worktree isn't locally
      // modified before touching anything, and our `clean` fails closed
      // when locked — so if the filter were already attached, this pull
      // would abort with "repository is locked" despite never touching
      // `PROTECTED_PATH`'s content. Deferring `install` until after
      // `unlock` (below) means no filter is attached yet, so this pull
      // can't hit that check at all. This is a genuine ordering constraint
      // for a brand-new recipient, not an artifact of the test.
      await securegit(cloneDir, homeB, ['identity', 'init', '--label', 'machine-b']);
      const identity = JSON.parse(
        await readFile(join(homeB, '.securegit', 'identity.json'), 'utf8'),
      ) as { publicKey: string };

      // "Machine A": the original `dir`, which already holds the repository
      // key, shares access with machine B's public key — pasted out of band
      // in reality; read directly from disk here since that's the part this
      // test isn't exercising.
      await securegit(dir, home, ['key', 'add-recipient', identity.publicKey, '--label', 'machine-b']);
      await git(dir, home, ['add', '.securegit/recipients']);
      await git(dir, home, ['commit', '--quiet', '-m', 'add machine-b as a recipient']);
      await git(dir, home, ['push', '--quiet', 'origin-recipient', 'main']);

      // Machine B pulls the new recipient file — no filter attached yet, so
      // this can't be blocked by being locked.
      await git(cloneDir, homeB, ['pull', '--quiet', 'origin', 'main']);

      // Only now does machine B attach the filter and unlock.
      await securegit(cloneDir, homeB, ['install', '--bin', FILTER_BIN]);
      await securegit(cloneDir, homeB, ['unlock']);

      // Same recovery as the plain-clone case: the checked-out file is still
      // the ciphertext from before `install`/`unlock` ever ran here.
      await rm(join(cloneDir, PROTECTED_PATH));
      await git(cloneDir, homeB, ['checkout', '--quiet', '--', '.']);

      const content = await readFile(join(cloneDir, PROTECTED_PATH));
      expect(content.equals(PLAINTEXT)).toBe(true);
      expect(await git(cloneDir, homeB, ['status', '--porcelain'])).toBe('');
    });

    it('F21: once the filter is attached, a locked repository cannot `git pull` at all', async () => {
      // Continues from the previous test: cloneDir/homeB now has the filter
      // attached and was unlocked. Lock it, push an unrelated change from
      // machine A (touching neither PROTECTED_PATH nor the recipients
      // directory), and confirm the pull itself fails closed rather than
      // silently succeeding or silently skipping the safety check.
      //
      // Found by a flaky run, not by reading the spec: for a trivial
      // fast-forward whose only change is a *new* file, Git's merge does not
      // uniformly re-verify every already-tracked path — the same class of
      // stat-cache/tree-diff skip behind F16 (`add`'s silent no-op), just
      // manifesting inside `merge` instead of `add`/`status`. When the
      // previous test's `checkout` and this pull land close enough in real
      // time, Git trusts PROTECTED_PATH's cached stat entry and never
      // touches it at all — no filter invocation, so no lock check, so the
      // pull silently "succeeds" without ever exercising the thing this test
      // exists to prove. A future mtime (F16's own technique) forces Git to
      // treat the cached entry as stale and actually re-verify the content,
      // which is what makes the filter — and therefore the lock check —
      // run at all.
      const future = new Date(Date.now() + 60_000);
      await utimes(join(cloneDir, PROTECTED_PATH), future, future);

      await securegit(cloneDir, homeB, ['lock']);
      try {
        await writeFile(join(dir, 'unrelated.txt'), 'nothing to do with the protected file\n');
        await git(dir, home, ['add', 'unrelated.txt']);
        await git(dir, home, ['commit', '--quiet', '-m', 'unrelated change']);
        await git(dir, home, ['push', '--quiet', 'origin-recipient', 'main']);

        await expect(git(cloneDir, homeB, ['pull', '--quiet', 'origin', 'main'])).rejects.toThrow(/locked/);
      } finally {
        await securegit(cloneDir, homeB, ['unlock']);
        // Finish the pull now that it's unlocked, so cloneDir/homeB end in a
        // clean, known state regardless of what ran after this test.
        await git(cloneDir, homeB, ['pull', '--quiet', 'origin', 'main']).catch(() => {});
      }
    });
  });
});

// A separate top-level describe, with its own repo/home: proves
// `filter.securegit.process` — one long-running process over pkt-line,
// instead of one `clean`/`smudge` subprocess per blob (11-filter-process.md)
// — is byte-for-byte interchangeable with the clean/smudge form for real
// Git, not just under process.ts's own injected-IO unit tests.
describe('a real Git repository using filter.securegit.process instead of clean/smudge', () => {
  let dir: string;
  let home: string;

  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), 'securegit-git-process-repo-'));
    home = await mkdtemp(join(tmpdir(), 'securegit-git-process-home-'));

    await git(dir, home, ['init', '--quiet', '-b', 'main']);
    await git(dir, home, ['config', 'user.name', 'Test']);
    await git(dir, home, ['config', 'user.email', 'test@example.com']);
    await securegit(dir, home, ['init']);
    await securegit(dir, home, ['install', '--process', '--bin', FILTER_BIN]);
    await securegit(dir, home, ['protect', PROTECTED_PATH]);
    await securegit(dir, home, ['unlock']);

    await mkdir(join(dir, 'config'), { recursive: true });
    await writeFile(join(dir, PROTECTED_PATH), PLAINTEXT);
    await git(dir, home, ['add', '-A']);
    await git(dir, home, ['commit', '--quiet', '-m', 'add production config']);
  }, 30_000);

  afterAll(async () => {
    await rm(dir, { recursive: true, force: true });
    await rm(home, { recursive: true, force: true });
  });

  it('`install --process` wrote the process config, not clean/smudge', async () => {
    await expect(git(dir, home, ['config', '--local', '--get', 'filter.securegit.clean'])).rejects.toThrow();
    expect(await git(dir, home, ['config', '--local', '--get', 'filter.securegit.process'])).toBe(
      `${FILTER_BIN} filter-process`,
    );
  });

  it('git status is clean immediately after commit, exactly like the clean/smudge form', async () => {
    expect(await git(dir, home, ['status', '--porcelain'])).toBe('');
  });

  it('the committed blob is ciphertext, and the worktree file reads back as plaintext', async () => {
    const blob = await gitBuffer(dir, home, ['cat-file', '-p', `HEAD:${PROTECTED_PATH}`]);
    expect(blob.subarray(0, MAGIC.length).equals(MAGIC)).toBe(true);
    expect(blob.includes(Buffer.from('hunter2'))).toBe(false);
    expect((await readFile(join(dir, PROTECTED_PATH))).equals(PLAINTEXT)).toBe(true);
  });

  it('git diff shows a real plaintext hunk — textconv still runs as its own one-shot process', async () => {
    // The process protocol only covers clean/smudge (11-filter-process.md);
    // `diff.securegit.textconv` is untouched by `--process` and still spawns
    // a separate `securegit textconv` per invocation, same as the
    // clean/smudge form.
    await writeFile(join(dir, PROTECTED_PATH), Buffer.from('{"password":"hunter3"}\n'));
    const diff = await git(dir, home, ['diff', PROTECTED_PATH]);
    expect(diff).toContain('-{"password":"hunter2"}');
    expect(diff).toContain('+{"password":"hunter3"}');
    await git(dir, home, ['checkout', '--', PROTECTED_PATH]); // restore
  });

  it('switching branches and back leaves a clean tree, with one process handling every blob', async () => {
    await git(dir, home, ['checkout', '--quiet', '-b', 'feature']);
    expect(await git(dir, home, ['status', '--porcelain'])).toBe('');
    await git(dir, home, ['checkout', '--quiet', 'main']);
    expect(await git(dir, home, ['status', '--porcelain'])).toBe('');
    expect((await readFile(join(dir, PROTECTED_PATH))).equals(PLAINTEXT)).toBe(true);
  });

  it('locked: clean fails closed the same way it does for the clean/smudge form', async () => {
    await securegit(dir, home, ['lock']);
    try {
      const future = new Date(Date.now() + 60_000);
      await utimes(join(dir, PROTECTED_PATH), future, future);
      await expect(git(dir, home, ['add', PROTECTED_PATH])).rejects.toThrow(/locked/);
    } finally {
      await securegit(dir, home, ['unlock']);
      await git(dir, home, ['checkout', '--', PROTECTED_PATH]);
    }
    expect(await git(dir, home, ['status', '--porcelain'])).toBe('');
  });

  describe('a clone, checked out through the process filter', () => {
    let bareDir: string;
    let cloneDir: string;

    beforeAll(async () => {
      bareDir = await mkdtemp(join(tmpdir(), 'securegit-git-process-bare-'));
      await rm(bareDir, { recursive: true, force: true });
      await git(dir, home, ['init', '--quiet', '--bare', bareDir]);
      await git(dir, home, ['remote', 'add', 'origin', bareDir]);
      await git(dir, home, ['push', '--quiet', 'origin', 'main']);

      cloneDir = await mkdtemp(join(tmpdir(), 'securegit-git-process-clone-'));
      await rm(cloneDir, { recursive: true, force: true });
      await git(dir, home, ['clone', '--quiet', '--branch', 'main', bareDir, cloneDir]);
    }, 30_000);

    afterAll(async () => {
      await rm(bareDir, { recursive: true, force: true });
      await rm(cloneDir, { recursive: true, force: true });
    });

    it('`install --process` + `unlock` + re-checkout restores real plaintext via the long-running filter', async () => {
      await securegit(cloneDir, home, ['install', '--process', '--bin', FILTER_BIN]);
      await securegit(cloneDir, home, ['unlock']);
      await rm(join(cloneDir, PROTECTED_PATH));
      await git(cloneDir, home, ['checkout', '--quiet', '--', '.']);

      const content = await readFile(join(cloneDir, PROTECTED_PATH));
      expect(content.equals(PLAINTEXT)).toBe(true);
      expect(await git(cloneDir, home, ['status', '--porcelain'])).toBe('');
    });
  });
});

// A separate top-level describe, with its own repo/home: proves `init
// --pad-to` (14-metadata-leakage.md) against a real commit, not just
// envelope.ts's own injected-buffer unit tests.
describe('a real Git repository with padding enabled (init --pad-to)', () => {
  let dir: string;
  let home: string;
  const PADDED_PATH = 'config/small.json';
  const TINY_PLAINTEXT = Buffer.from('{}\n');

  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), 'securegit-git-pad-repo-'));
    home = await mkdtemp(join(tmpdir(), 'securegit-git-pad-home-'));

    await git(dir, home, ['init', '--quiet', '-b', 'main']);
    await git(dir, home, ['config', 'user.name', 'Test']);
    await git(dir, home, ['config', 'user.email', 'test@example.com']);
    await securegit(dir, home, ['init', '--pad-to', '256']);
    await securegit(dir, home, ['install', '--bin', FILTER_BIN]);
    await securegit(dir, home, ['protect', PADDED_PATH]);
    await securegit(dir, home, ['unlock']);

    await mkdir(join(dir, 'config'), { recursive: true });
    await writeFile(join(dir, PADDED_PATH), TINY_PLAINTEXT);
    await git(dir, home, ['add', '-A']);
    await git(dir, home, ['commit', '--quiet', '-m', 'add tiny config']);
  }, 30_000);

  afterAll(async () => {
    await rm(dir, { recursive: true, force: true });
    await rm(home, { recursive: true, force: true });
  });

  it('commits a padded envelope for a tiny file, and checks out the exact original plaintext', async () => {
    const blob = await gitBuffer(dir, home, ['cat-file', '-p', `HEAD:${PADDED_PATH}`]);
    expect(blob.subarray(0, MAGIC.length).equals(MAGIC)).toBe(true);
    // A 3-byte plaintext padded to 256 bytes, plus envelope overhead, is
    // well over 256 bytes — proof padding actually inflated the ciphertext,
    // not just that the flag got set.
    expect(blob.length).toBeGreaterThan(256);

    const content = await readFile(join(dir, PADDED_PATH));
    expect(content.equals(TINY_PLAINTEXT)).toBe(true);
  });

  it('git status is clean immediately after commit, same as without padding', async () => {
    expect(await git(dir, home, ['status', '--porcelain'])).toBe('');
  });

  it('git diff still shows the real plaintext hunk via textconv', async () => {
    await writeFile(join(dir, PADDED_PATH), Buffer.from('{"changed":true}\n'));
    const diff = await git(dir, home, ['diff', PADDED_PATH]);
    expect(diff).toContain('-{}');
    expect(diff).toContain('+{"changed":true}');
    await git(dir, home, ['checkout', '--', PADDED_PATH]); // restore
  });
});
