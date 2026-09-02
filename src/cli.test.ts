import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { execFile as execFileCb } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, rm, mkdir, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { looksLikeEnvelope, parseEnvelope } from './envelope.js';
import { runCli, type CliIO } from './cli.js';

const execFile = promisify(execFileCb);

let dir: string;
let home: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'securegit-cli-repo-'));
  home = await mkdtemp(join(tmpdir(), 'securegit-cli-home-'));
  await mkdir(join(dir, '.git'));
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
  await rm(home, { recursive: true, force: true });
});

function harness(overrides: Partial<CliIO> = {}) {
  const outChunks: Buffer[] = [];
  const errLines: string[] = [];
  const io: CliIO = {
    argv: [],
    cwd: dir,
    env: { SECUREGIT_PASSPHRASE: 'correct horse battery staple' },
    stdin: Buffer.alloc(0),
    home,
    stdout: (chunk) => outChunks.push(chunk),
    stderr: (message) => errLines.push(message),
    now: () => new Date(),
    ...overrides,
  };
  return {
    io,
    // Each call captures only ITS OWN output — otherwise a later command's
    // assertions would see output concatenated from every earlier command
    // run on the same harness (e.g. `clean`'s ciphertext bleeding into a
    // subsequent `smudge` check).
    run: (argv: string[], io2: Partial<CliIO> = {}) => {
      outChunks.length = 0;
      errLines.length = 0;
      return runCli({ ...io, argv, ...io2 });
    },
    stdoutBuf: () => Buffer.concat(outChunks),
    stdoutText: () => Buffer.concat(outChunks).toString('utf8'),
    stderrText: () => errLines.join('\n'),
    stdoutCalls: () => outChunks.length,
  };
}

describe('init', () => {
  it('succeeds and writes a keyring', async () => {
    const h = harness();
    expect(await h.run(['init'])).toBe(0);
    expect(await readFile(join(dir, '.securegit', 'config.json'), 'utf8')).toContain('repoId');
  });

  it('exits 4 outside a git repository', async () => {
    const notGit = await mkdtemp(join(tmpdir(), 'securegit-cli-notgit-'));
    try {
      const h = harness({ cwd: notGit });
      expect(await h.run(['init'])).toBe(4);
    } finally {
      await rm(notGit, { recursive: true, force: true });
    }
  });

  it('exits 4 the second time, without touching the first config', async () => {
    const h = harness();
    await h.run(['init']);
    const before = await readFile(join(dir, '.securegit', 'config.json'), 'utf8');
    expect(await h.run(['init'])).toBe(4);
    expect(await readFile(join(dir, '.securegit', 'config.json'), 'utf8')).toBe(before);
  });

  it('rejects a passphrase under 12 characters', async () => {
    const h = harness({ env: { SECUREGIT_PASSPHRASE: 'short' } });
    expect(await h.run(['init'])).toBe(4);
  });

  it('honours --bind-path', async () => {
    const h = harness();
    await h.run(['init', '--bind-path']);
    const config = JSON.parse(await readFile(join(dir, '.securegit', 'config.json'), 'utf8'));
    expect(config.bindPath).toBe(true);
  });

  it('writes nothing to stdout', async () => {
    const h = harness();
    await h.run(['init']);
    expect(h.stdoutCalls()).toBe(0);
  });
});

describe('install', () => {
  it('succeeds inside a real git repository', async () => {
    const { execFile } = await import('node:child_process');
    const { promisify } = await import('node:util');
    await promisify(execFile)('git', ['init', '--quiet'], { cwd: dir });
    const h = harness();
    expect(await h.run(['install'])).toBe(0);
  });

  it('exits 2 on a foreign filter config', async () => {
    const { execFile } = await import('node:child_process');
    const { promisify } = await import('node:util');
    const git = promisify(execFile);
    await git('git', ['init', '--quiet'], { cwd: dir });
    await git('git', ['config', '--local', 'filter.securegit.clean', 'some-other-tool'], { cwd: dir });
    const h = harness();
    expect(await h.run(['install'])).toBe(2);
  });

  it('honours --bin, so a filter can point at an unpublished build', async () => {
    const { execFile } = await import('node:child_process');
    const { promisify } = await import('node:util');
    const git = promisify(execFile);
    await git('git', ['init', '--quiet'], { cwd: dir });
    const h = harness();
    expect(await h.run(['install', '--bin', 'node /opt/securegit/dist/bin/securegit.js'])).toBe(0);
    const { stdout } = await git('git', ['config', '--local', '--get', 'filter.securegit.clean'], { cwd: dir });
    expect(stdout.trim()).toBe('node /opt/securegit/dist/bin/securegit.js clean -- %f');
  });
});

describe('protect', () => {
  it('exits 4 with no patterns', async () => {
    const h = harness();
    expect(await h.run(['protect'])).toBe(4);
  });

  it('writes .gitattributes', async () => {
    const h = harness();
    expect(await h.run(['protect', '.env'])).toBe(0);
    const content = await readFile(join(dir, '.gitattributes'), 'utf8');
    expect(content).toContain('.env filter=securegit diff=securegit -text');
  });
});

describe('unlock / lock / status', () => {
  it('status exits 2 before init', async () => {
    const h = harness();
    expect(await h.run(['status'])).toBe(2);
  });

  it('status exits 1 (locked) after init but before unlock', async () => {
    const h = harness();
    await h.run(['init']);
    expect(await h.run(['status'])).toBe(1);
  });

  it('unlock exits 0 with the right passphrase, status then exits 0', async () => {
    const h = harness();
    await h.run(['init']);
    expect(await h.run(['unlock'])).toBe(0);
    expect(await h.run(['status'])).toBe(0);
  });

  it('unlock exits 1 with the wrong passphrase', async () => {
    const h = harness();
    await h.run(['init']);
    expect(await h.run(['unlock'], { env: { SECUREGIT_PASSPHRASE: 'a totally different passphrase' } })).toBe(1);
  });

  it('unlock exits 2 before init', async () => {
    const h = harness();
    expect(await h.run(['unlock'])).toBe(2);
  });

  it('lock returns status to locked', async () => {
    const h = harness();
    await h.run(['init']);
    await h.run(['unlock']);
    expect(await h.run(['status'])).toBe(0);
    expect(await h.run(['lock'])).toBe(0);
    expect(await h.run(['status'])).toBe(1);
  });

  it('none of init/unlock/lock/status ever write to stdout', async () => {
    // Checked after EACH call — the harness clears captured output per
    // command, so only asserting once at the end would silently stop
    // checking every command but the last.
    const h = harness();
    await h.run(['init']);
    expect(h.stdoutCalls()).toBe(0);
    await h.run(['unlock']);
    expect(h.stdoutCalls()).toBe(0);
    await h.run(['status']);
    expect(h.stdoutCalls()).toBe(0);
    await h.run(['lock']);
    expect(h.stdoutCalls()).toBe(0);
  });
});

describe('clean / smudge', () => {
  const PT = Buffer.from('{"timeout":30}\n');
  const PATH = 'config/production.json';

  async function initAndUnlock(h: ReturnType<typeof harness>): Promise<void> {
    await h.run(['init']);
    await h.run(['unlock']);
  }

  it('clean fails with exit 1 while locked', async () => {
    const h = harness();
    await h.run(['init']);
    expect(await h.run(['clean', '--', PATH], { stdin: PT })).toBe(1);
    expect(h.stderrText()).toContain(PATH);
  });

  it('clean encrypts once unlocked', async () => {
    const h = harness();
    await initAndUnlock(h);
    expect(await h.run(['clean', '--', PATH], { stdin: PT })).toBe(0);
    expect(looksLikeEnvelope(h.stdoutBuf())).toBe(true);
  });

  it('clean/smudge round-trip through the real CLI', async () => {
    const h = harness();
    await initAndUnlock(h);
    await h.run(['clean', '--', PATH], { stdin: PT });
    const ciphertext = h.stdoutBuf();
    expect(await h.run(['smudge', '--', PATH], { stdin: ciphertext })).toBe(0);
    expect(h.stdoutBuf().equals(PT)).toBe(true);
  });

  it('smudge passes ciphertext through unchanged while locked, with a warning', async () => {
    const h = harness();
    await initAndUnlock(h);
    await h.run(['clean', '--', PATH], { stdin: PT });
    const ciphertext = h.stdoutBuf();

    await h.run(['lock']); // same repo, now locked
    expect(await h.run(['smudge', '--', PATH], { stdin: ciphertext })).toBe(0);
    expect(h.stdoutBuf().equals(ciphertext)).toBe(true);
    expect(h.stderrText().length).toBeGreaterThan(0);
  });

  it('smudge --strict fails instead of passing through while locked', async () => {
    const h = harness();
    await initAndUnlock(h);
    await h.run(['clean', '--', PATH], { stdin: PT });
    const ciphertext = h.stdoutBuf();

    await h.run(['lock']);
    expect(await h.run(['smudge', '--strict', '--', PATH], { stdin: ciphertext })).toBe(1);
  });

  it('clean/smudge exit 4 when the `--` separator is missing', async () => {
    const h = harness();
    await initAndUnlock(h);
    expect(await h.run(['clean', PATH], { stdin: PT })).toBe(4);
    expect(await h.run(['smudge', PATH], { stdin: PT })).toBe(4);
  });
});

describe('merge', () => {
  const PATH = 'config/production.json';
  // diff3 needs an unchanged line of context between two edits to treat them
  // as independent hunks — see src/merge.test.ts for why.
  const BASE = '{\n  "a": 1,\n  "x": true,\n  "y": true,\n  "b": 2\n}\n';
  const OURS = '{\n  "a": 10,\n  "x": true,\n  "y": true,\n  "b": 2\n}\n';
  const THEIRS = '{\n  "a": 1,\n  "x": true,\n  "y": true,\n  "b": 20\n}\n';
  const OURS_CONFLICT = '{\n  "a": 10,\n  "x": true,\n  "y": true,\n  "b": 2\n}\n';
  const THEIRS_CONFLICT = '{\n  "a": 999,\n  "x": true,\n  "y": true,\n  "b": 2\n}\n';

  async function initAndUnlock(h: ReturnType<typeof harness>): Promise<void> {
    await h.run(['init']);
    await h.run(['unlock']);
  }

  async function encryptToFile(
    h: ReturnType<typeof harness>,
    plaintext: string,
    filePath: string,
  ): Promise<void> {
    await h.run(['clean', '--', PATH], { stdin: Buffer.from(plaintext) });
    await writeFile(filePath, h.stdoutBuf());
  }

  it('resolves a clean merge, writes ciphertext to %A, and exits 0', async () => {
    const h = harness();
    await initAndUnlock(h);

    const baseFile = join(dir, 'O');
    const oursFile = join(dir, 'A');
    const theirsFile = join(dir, 'B');
    await encryptToFile(h, BASE, baseFile);
    await encryptToFile(h, OURS, oursFile);
    await encryptToFile(h, THEIRS, theirsFile);

    expect(await h.run(['merge', '--', baseFile, oursFile, theirsFile, '7', PATH])).toBe(0);

    const merged = await readFile(oursFile);
    expect(looksLikeEnvelope(merged)).toBe(true);
    expect(await h.run(['smudge', '--', PATH], { stdin: merged })).toBe(0);
    expect(h.stdoutText()).toBe('{\n  "a": 10,\n  "x": true,\n  "y": true,\n  "b": 20\n}\n');
  });

  it('exits 1 on a real conflict, still writing ciphertext with plaintext markers underneath', async () => {
    const h = harness();
    await initAndUnlock(h);

    const baseFile = join(dir, 'O');
    const oursFile = join(dir, 'A');
    const theirsFile = join(dir, 'B');
    await encryptToFile(h, BASE, baseFile);
    await encryptToFile(h, OURS_CONFLICT, oursFile);
    await encryptToFile(h, THEIRS_CONFLICT, theirsFile);

    expect(await h.run(['merge', '--', baseFile, oursFile, theirsFile, '7', PATH])).toBe(1);

    const merged = await readFile(oursFile);
    expect(await h.run(['smudge', '--', PATH], { stdin: merged })).toBe(0);
    expect(h.stdoutText()).toContain('<<<<<<<');
  });

  it('exits 4 when an argument is missing', async () => {
    const h = harness();
    await initAndUnlock(h);
    expect(await h.run(['merge', '--', 'a', 'b', 'c'])).toBe(4);
    expect(await h.run(['merge', 'a', 'b', 'c', '7', PATH])).toBe(4);
  });

  it('exits locked when there is no current generation to encrypt the result under', async () => {
    const h = harness();
    await h.run(['init']); // never unlocked

    const baseFile = join(dir, 'O');
    const oursFile = join(dir, 'A');
    const theirsFile = join(dir, 'B');
    await writeFile(baseFile, Buffer.from(BASE));
    await writeFile(oursFile, Buffer.from(OURS));
    await writeFile(theirsFile, Buffer.from(THEIRS));

    expect(await h.run(['merge', '--', baseFile, oursFile, theirsFile, '7', PATH])).toBe(1);
  });
});

describe('verify', () => {
  let realDir: string;

  async function stageContent(repoDir: string, relPath: string, content: Buffer): Promise<void> {
    const tmp = join(tmpdir(), `securegit-cli-verify-blob-${randomBytes(4).toString('hex')}`);
    await writeFile(tmp, content);
    const sha = (await execFile('git', ['hash-object', '-w', tmp], { cwd: repoDir })).stdout.trim();
    await rm(tmp, { force: true });
    await execFile('git', ['update-index', '--add', '--cacheinfo', `100644,${sha},${relPath}`], {
      cwd: repoDir,
    });
  }

  beforeEach(async () => {
    realDir = await mkdtemp(join(tmpdir(), 'securegit-cli-verify-'));
    await execFile('git', ['init', '--quiet'], { cwd: realDir });
    await execFile('git', ['config', 'user.name', 'Test'], { cwd: realDir });
    await execFile('git', ['config', 'user.email', 'test@example.com'], { cwd: realDir });
  });

  afterEach(async () => {
    await rm(realDir, { recursive: true, force: true });
  });

  it('exits misconfigured before `init` has ever run', async () => {
    const h = harness({ cwd: realDir });
    expect(await h.run(['verify'])).toBe(2);
  });

  it('passes a correctly configured repository and never writes to stdout', async () => {
    const h = harness({ cwd: realDir });
    await h.run(['init']);
    await h.run(['unlock']);
    await h.run(['install']);
    await h.run(['protect', 'config/production.json']);
    await execFile('git', ['add', '-A'], { cwd: realDir });
    await execFile('git', ['commit', '--quiet', '-m', 'init'], { cwd: realDir });

    await h.run(['clean', '--', 'config/production.json'], {
      stdin: Buffer.from('{"password":"hunter2"}\n'),
    });
    await stageContent(realDir, 'config/production.json', h.stdoutBuf());
    await execFile('git', ['commit', '--quiet', '-m', 'add config'], { cwd: realDir });

    expect(await h.run(['verify'])).toBe(0);
    expect(h.stdoutCalls()).toBe(0);
  });

  it('exits leaked (5) when a protected path holds plaintext', async () => {
    const h = harness({ cwd: realDir });
    await h.run(['init']);
    await h.run(['protect', 'config/production.json']); // install() never called
    await execFile('git', ['add', '-A'], { cwd: realDir });
    await execFile('git', ['commit', '--quiet', '-m', 'init'], { cwd: realDir });

    await stageContent(realDir, 'config/production.json', Buffer.from('{"password":"hunter2"}\n'));
    await execFile('git', ['commit', '--quiet', '-m', 'oops'], { cwd: realDir });

    expect(await h.run(['verify'])).toBe(5);
  });
});

describe('textconv', () => {
  const PT = Buffer.from('{"timeout":30}\n');
  const PATH = 'config/production.json';

  it('decrypts a file for display, to stdout', async () => {
    const h = harness();
    await h.run(['init']);
    await h.run(['unlock']);
    await h.run(['clean', '--', PATH], { stdin: PT });
    const ciphertext = h.stdoutBuf();

    const filePath = join(dir, 'blob.bin');
    await (await import('node:fs/promises')).writeFile(filePath, ciphertext);

    const h2 = harness();
    await h2.run(['unlock']);
    expect(await h2.run(['textconv', '--', filePath])).toBe(0);
    expect(h2.stdoutBuf().equals(PT)).toBe(true);
  });

  it('never throws — a locked repo yields a placeholder on stdout, exit 0', async () => {
    const h = harness();
    await h.run(['init']);
    await h.run(['unlock']);
    await h.run(['clean', '--', PATH], { stdin: PT });
    const ciphertext = h.stdoutBuf();
    const filePath = join(dir, 'blob.bin');
    await (await import('node:fs/promises')).writeFile(filePath, ciphertext);

    await h.run(['lock']); // same repo, now locked
    expect(await h.run(['textconv', '--', filePath])).toBe(0);
    expect(h.stdoutBuf().toString('utf8')).toContain('securegit');
  });
});

describe('encrypt / decrypt / inspect', () => {
  const PT = Buffer.from('hello from the ad-hoc path\n');

  it('encrypt then decrypt round-trips via stdin/stdout', async () => {
    const h = harness();
    await h.run(['init']);
    await h.run(['unlock']);
    expect(await h.run(['encrypt', '-'], { stdin: PT })).toBe(0);
    const ciphertext = h.stdoutBuf();
    expect(looksLikeEnvelope(ciphertext)).toBe(true);

    const h2 = harness();
    await h2.run(['unlock']);
    expect(await h2.run(['decrypt', '-'], { stdin: ciphertext })).toBe(0);
    expect(h2.stdoutBuf().equals(PT)).toBe(true);
  });

  it('encrypt exits 1 while locked', async () => {
    const h = harness();
    await h.run(['init']); // never unlocked
    expect(await h.run(['encrypt', '-'], { stdin: PT })).toBe(1);
  });

  it('decrypt exits 1 for a generation this keyring does not hold', async () => {
    const a = harness();
    await a.run(['init']);
    await a.run(['unlock']);
    await a.run(['encrypt', '-'], { stdin: PT });
    const ciphertext = a.stdoutBuf();

    // A genuinely different repository: separate working tree, so `init`
    // there generates an unrelated repoId and keyring.
    const otherDir = await mkdtemp(join(tmpdir(), 'securegit-cli-repo-'));
    await mkdir(join(otherDir, '.git'));
    try {
      const b = harness({ cwd: otherDir });
      await b.run(['init']);
      await b.run(['unlock']);
      expect(await b.run(['decrypt', '-'], { stdin: ciphertext })).toBe(1);
    } finally {
      await rm(otherDir, { recursive: true, force: true });
    }
  });

  it('inspect reads the header without needing a key', async () => {
    const h = harness();
    await h.run(['init']);
    await h.run(['unlock']);
    await h.run(['encrypt', '-'], { stdin: PT });
    const ciphertext = h.stdoutBuf();

    const fresh = harness();
    expect(await fresh.run(['inspect', '-'], { stdin: ciphertext })).toBe(0);
    expect(fresh.stderrText()).toContain('keyId');
    expect(fresh.stdoutCalls()).toBe(0);
  });

  it('inspect exits 3 on malformed input', async () => {
    const h = harness();
    expect(await h.run(['inspect', '-'], { stdin: Buffer.from('not an envelope') })).toBe(3);
  });
});

describe('unknown input', () => {
  it('exits 4 with no command', async () => {
    const h = harness();
    expect(await h.run([])).toBe(4);
  });

  it('exits 4 on an unrecognised command', async () => {
    const h = harness();
    expect(await h.run(['bogus'])).toBe(4);
  });
});
