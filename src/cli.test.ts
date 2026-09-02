import { describe, it, expect, beforeAll, beforeEach, afterEach } from 'vitest';
import { execFile as execFileCb } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, rm, mkdir, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { looksLikeEnvelope, parseEnvelope } from './envelope.js';
import { runCli, runFilterProcess, type CliIO, type FilterProcessIO } from './cli.js';
import { encodePacketList, splitContent, PktLineReader } from './pktline.js';

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

  it('padTo is 0 (disabled) by default', async () => {
    const h = harness();
    await h.run(['init']);
    const config = JSON.parse(await readFile(join(dir, '.securegit', 'config.json'), 'utf8'));
    expect(config.padTo).toBe(0);
  });

  it('honours --pad-to', async () => {
    const h = harness();
    await h.run(['init', '--pad-to', '4096']);
    const config = JSON.parse(await readFile(join(dir, '.securegit', 'config.json'), 'utf8'));
    expect(config.padTo).toBe(4096);
  });

  it('rejects a non-numeric --pad-to', async () => {
    const h = harness();
    expect(await h.run(['init', '--pad-to', 'not-a-number'])).toBe(4);
  });

  it('rejects a negative --pad-to', async () => {
    const h = harness();
    expect(await h.run(['init', '--pad-to', '-1'])).toBe(4);
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
    expect(content).toContain('.env filter=securegit diff=securegit merge=securegit -text');
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

describe('identity', () => {
  it('init creates ~/.securegit/identity.json', async () => {
    const h = harness();
    expect(await h.run(['identity', 'init', '--label', 'laptop'])).toBe(0);
    const file = JSON.parse(await readFile(join(home, '.securegit', 'identity.json'), 'utf8'));
    expect(file.label).toBe('laptop');
    expect(file.publicKey.startsWith('SGPUB1')).toBe(true);
  });

  it('init exits usage the second time, without touching the first identity', async () => {
    const h = harness();
    await h.run(['identity', 'init']);
    const before = await readFile(join(home, '.securegit', 'identity.json'), 'utf8');
    expect(await h.run(['identity', 'init'])).toBe(4);
    expect(await readFile(join(home, '.securegit', 'identity.json'), 'utf8')).toBe(before);
  });

  it('show exits misconfigured before init', async () => {
    const h = harness();
    expect(await h.run(['identity', 'show'])).toBe(2);
  });

  it('show prints the fingerprint and public key to stderr, not stdout', async () => {
    const h = harness();
    await h.run(['identity', 'init']);
    expect(await h.run(['identity', 'show'])).toBe(0);
    expect(h.stdoutCalls()).toBe(0);
    expect(h.stderrText()).toContain('SGPUB1');
  });

  it('an unknown identity subcommand exits usage', async () => {
    const h = harness();
    expect(await h.run(['identity', 'bogus'])).toBe(4);
  });
});

describe('key add-recipient / key remove-recipient / unlock via a recipient file', () => {
  const PATH = 'config/production.json';
  const PT = Buffer.from('{"timeout":30}\n');

  it('add-recipient exits locked when the repository is locked', async () => {
    const h = harness();
    await h.run(['init']);
    const other = harness({ home: await mkdtemp(join(tmpdir(), 'securegit-cli-identity-')) });
    await other.run(['identity', 'init']);
    const identity = JSON.parse(
      await readFile(join(other.io.home, '.securegit', 'identity.json'), 'utf8'),
    );
    expect(await h.run(['key', 'add-recipient', identity.publicKey])).toBe(1);
  });

  it('add-recipient exits usage on a malformed public key', async () => {
    const h = harness();
    await h.run(['init']);
    await h.run(['unlock']);
    expect(await h.run(['key', 'add-recipient', 'not-a-public-key'])).toBe(4);
  });

  it('remove-recipient exits usage when the file does not exist', async () => {
    const h = harness();
    expect(await h.run(['key', 'remove-recipient', '0000000000000000'])).toBe(4);
  });

  it('remove-recipient deletes the file', async () => {
    const h = harness();
    await h.run(['init']);
    await h.run(['unlock']);
    const otherHome = await mkdtemp(join(tmpdir(), 'securegit-cli-identity-'));
    const other = harness({ home: otherHome });
    await other.run(['identity', 'init']);
    const identity = JSON.parse(await readFile(join(otherHome, '.securegit', 'identity.json'), 'utf8'));

    await h.run(['key', 'add-recipient', identity.publicKey, '--label', 'laptop']);
    const recipientFile = join(dir, '.securegit', 'recipients', `${identity.fingerprint}.json`);
    await expect(readFile(recipientFile)).resolves.toBeDefined();

    expect(await h.run(['key', 'remove-recipient', identity.fingerprint])).toBe(0);
    await expect(readFile(recipientFile)).rejects.toThrow();
  });

  it('remove-recipient records the removal in the committed removed-recipients log', async () => {
    const h = harness();
    await h.run(['init']);
    await h.run(['unlock']);
    const otherHome = await mkdtemp(join(tmpdir(), 'securegit-cli-identity-'));
    const other = harness({ home: otherHome });
    await other.run(['identity', 'init']);
    const identity = JSON.parse(await readFile(join(otherHome, '.securegit', 'identity.json'), 'utf8'));

    await h.run(['key', 'add-recipient', identity.publicKey, '--label', 'contractor']);
    expect(await h.run(['key', 'remove-recipient', identity.fingerprint])).toBe(0);

    const log = JSON.parse(
      await readFile(join(dir, '.securegit', 'removed-recipients.json'), 'utf8'),
    );
    expect(log).toHaveLength(1);
    expect(log[0].fingerprint).toBe(identity.fingerprint);
    expect(log[0].label).toBe('contractor');
    expect(log[0].generations).toEqual([1]);
    expect(log[0].removedAt).toBeDefined();
    expect(JSON.stringify(log)).not.toContain('payload'); // never the still-wrapped key material
  });

  it('end-to-end: a second identity joins via add-recipient, unlocks, and decrypts', async () => {
    // "Machine A" — already has full repository access.
    const a = harness();
    await a.run(['init']);
    await a.run(['unlock']);

    // "Machine B" — same repository (`dir`), a different home/identity/keyring.
    const bHome = await mkdtemp(join(tmpdir(), 'securegit-cli-identity-'));
    const b = harness({ home: bHome });
    await b.run(['identity', 'init', '--label', 'machine-b']);
    const identity = JSON.parse(await readFile(join(bHome, '.securegit', 'identity.json'), 'utf8'));

    // Machine A shares access with machine B's public key.
    expect(await a.run(['key', 'add-recipient', identity.publicKey, '--label', 'machine-b'])).toBe(0);

    // Machine B has no local keyring at all, but can still unlock.
    expect(await b.run(['unlock'])).toBe(0);
    expect(b.stderrText()).toContain('unlocked via recipient');

    // Machine A encrypts; machine B, unlocked purely via the recipient file, decrypts.
    await a.run(['clean', '--', PATH], { stdin: PT });
    const ciphertext = a.stdoutBuf();
    expect(await b.run(['smudge', '--', PATH], { stdin: ciphertext })).toBe(0);
    expect(b.stdoutBuf().equals(PT)).toBe(true);
  });

  it('unlock exits misconfigured with no keyring and no identity at all', async () => {
    const h = harness();
    await h.run(['init']);
    // Simulate a keyless clone on a machine that has never run `identity init`:
    // delete the keyring this same `init` call just wrote.
    await rm(join(home, '.securegit'), { recursive: true, force: true });
    expect(await h.run(['unlock'])).toBe(2);
    expect(h.stderrText()).toContain('identity init');
  });
});

describe('key export-recovery / key import-recovery', () => {
  it('export-recovery exits usage without --out', async () => {
    const h = harness();
    await h.run(['init']);
    await h.run(['unlock']);
    expect(await h.run(['key', 'export-recovery'])).toBe(4);
  });

  it('export-recovery exits locked when the repository is locked', async () => {
    const h = harness();
    await h.run(['init']); // never unlocked
    expect(await h.run(['key', 'export-recovery', '--out', 'r.json'])).toBe(1);
  });

  it('export-recovery writes a recovery file and prints the code to stderr, not stdout', async () => {
    const h = harness();
    await h.run(['init']);
    await h.run(['unlock']);
    expect(await h.run(['key', 'export-recovery', '--out', 'r.json'])).toBe(0);
    expect(h.stdoutCalls()).toBe(0);

    const file = JSON.parse(await readFile(join(dir, 'r.json'), 'utf8'));
    expect(file.generations['1']).toBeDefined();
    expect(h.stderrText()).toMatch(/[0-9A-Z]{4}-[0-9A-Z]{4}/); // a formatted code group
  });

  it('export-recovery appends to the committed recovery log', async () => {
    const h = harness();
    await h.run(['init']);
    await h.run(['unlock']);
    await h.run(['key', 'export-recovery', '--out', 'r.json']);

    const log = JSON.parse(await readFile(join(dir, '.securegit', 'recovery-log.json'), 'utf8'));
    expect(log).toHaveLength(1);
    expect(log[0].exportId).toBeDefined();
    expect(log[0].timestamp).toBeDefined();
    expect(log[0].generations).toEqual([1]);
    expect(JSON.stringify(log)).not.toMatch(/[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}/); // never the code
  });

  it('import-recovery exits usage without --in', async () => {
    const h = harness();
    await h.run(['init']);
    expect(await h.run(['key', 'import-recovery'])).toBe(4);
  });

  it('import-recovery exits usage when the file does not exist', async () => {
    const h = harness();
    await h.run(['init']);
    expect(await h.run(['key', 'import-recovery', '--in', 'nope.json'])).toBe(4);
  });

  it('import-recovery exits misconfigured when the file belongs to a different repository', async () => {
    const other = harness({ cwd: await mkdtemp(join(tmpdir(), 'securegit-cli-other-repo-')) });
    await mkdir(join(other.io.cwd, '.git'));
    await other.run(['init']);
    await other.run(['unlock']);
    await other.run(['key', 'export-recovery', '--out', 'r.json']);
    const foreignFile = await readFile(join(other.io.cwd, 'r.json'));
    await writeFile(join(dir, 'r.json'), foreignFile);

    const h = harness();
    await h.run(['init']);
    expect(await h.run(['key', 'import-recovery', '--in', 'r.json'])).toBe(2);
  });

  it('import-recovery exits locked with the wrong code', async () => {
    // Two exports, each with its own random code: syntactically valid, but
    // code1 does not decrypt r2.json — a real "wrong code", not a malformed one.
    const h = harness();
    await h.run(['init']);
    await h.run(['unlock']);
    await h.run(['key', 'export-recovery', '--out', 'r1.json']);
    const code1 = h.stderrText().match(/([0-9A-Z]{4}-){10,}[0-9A-Z]{1,4}/)![0];
    await h.run(['key', 'export-recovery', '--out', 'r2.json']);

    const importHome = await mkdtemp(join(tmpdir(), 'securegit-cli-import-home-'));
    const wrong = harness({
      home: importHome,
      env: { SECUREGIT_RECOVERY_CODE: code1, SECUREGIT_PASSPHRASE: 'a fresh local passphrase' },
    });
    expect(await wrong.run(['key', 'import-recovery', '--in', 'r2.json'])).toBe(1);
  });

  it('end-to-end: export, import onto a fresh home, unlock, decrypt, and rotate further', async () => {
    const PATH = 'config/production.json';
    const PT = Buffer.from('{"timeout":30}\n');

    const a = harness();
    await a.run(['init']);
    await a.run(['unlock']);
    await a.run(['clean', '--', PATH], { stdin: PT });
    const ciphertext = a.stdoutBuf();

    await a.run(['key', 'export-recovery', '--out', 'r.json']);
    const codeMatch = a.stderrText().match(/([0-9A-Z]{4}-){10,}[0-9A-Z]{1,4}/);
    expect(codeMatch).not.toBeNull();
    const code = codeMatch![0];

    const bHome = await mkdtemp(join(tmpdir(), 'securegit-cli-import-home-'));
    const b = harness({
      home: bHome,
      env: { SECUREGIT_RECOVERY_CODE: code, SECUREGIT_PASSPHRASE: 'a fresh local passphrase for b' },
    });
    expect(await b.run(['key', 'import-recovery', '--in', 'r.json'])).toBe(0);

    expect(await b.run(['unlock'], { env: { SECUREGIT_PASSPHRASE: 'a fresh local passphrase for b' } })).toBe(0);
    expect(await b.run(['smudge', '--', PATH], { stdin: ciphertext })).toBe(0);
    expect(b.stdoutBuf().equals(PT)).toBe(true);
    // The imported keyring's ability to itself be rotated further is proven
    // at the keyring.ts unit level (keyring.test.ts's
    // "produces a keyring that unlocks and can itself be rotated further");
    // exercising `key rotate` here would need a real git repo, which this
    // fake-`.git` CLI harness doesn't provide (see the `key rotate /
    // reencrypt` describe block below for that setup).
  });

  it('import-recovery falls back to stdin (code then passphrase) with no env vars set', async () => {
    const a = harness();
    await a.run(['init']);
    await a.run(['unlock']);
    await a.run(['key', 'export-recovery', '--out', 'r.json']);
    const codeMatch = a.stderrText().match(/([0-9A-Z]{4}-){10,}[0-9A-Z]{1,4}/);
    const code = codeMatch![0];

    const bHome = await mkdtemp(join(tmpdir(), 'securegit-cli-import-home-'));
    const b = harness({ home: bHome, env: {} });
    expect(
      await b.run(['key', 'import-recovery', '--in', 'r.json'], {
        stdin: Buffer.from(`${code}\na fresh passphrase from stdin\n`),
      }),
    ).toBe(0);
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

  it('clean/smudge round-trip through the real CLI, padded, when the repo was init --pad-to', async () => {
    const h = harness();
    await h.run(['init', '--pad-to', '64']);
    await h.run(['unlock']);
    await h.run(['clean', '--', PATH], { stdin: PT });
    const ciphertext = h.stdoutBuf();
    expect(looksLikeEnvelope(ciphertext)).toBe(true);
    expect(parseEnvelope(ciphertext).padded).toBe(true);

    expect(await h.run(['smudge', '--', PATH], { stdin: ciphertext })).toBe(0);
    expect(h.stdoutBuf().equals(PT)).toBe(true);
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

  describe('--access', () => {
    it('reports "(none)" everywhere for a fresh solo repository, and exits 0', async () => {
      const h = harness({ cwd: realDir });
      await h.run(['init']);
      await h.run(['unlock']);

      expect(await h.run(['verify', '--access'])).toBe(0);
      expect(h.stdoutCalls()).toBe(0);
      const text = h.stderrText();
      expect(text).toContain('recipients');
      expect(text).toContain('providers');
      expect(text).toContain('passphrase-file');
      expect(text).toContain('recovery exports');
      expect(text).toContain('removed recipients');
    });

    it('lists a recipient added via key add-recipient', async () => {
      const h = harness({ cwd: realDir });
      await h.run(['init']);
      await h.run(['unlock']);

      const otherHome = await mkdtemp(join(tmpdir(), 'securegit-cli-access-identity-'));
      const other = harness({ home: otherHome });
      await other.run(['identity', 'init']);
      const identity = JSON.parse(await readFile(join(otherHome, '.securegit', 'identity.json'), 'utf8'));

      await h.run(['key', 'add-recipient', identity.publicKey, '--label', 'laptop']);

      expect(await h.run(['verify', '--access'])).toBe(0);
      const text = h.stderrText();
      expect(text).toContain(identity.fingerprint);
      expect(text).toContain('laptop');
      expect(text).toContain('gen 1');
    });

    it('lists a recovery export, with the non-revocable-access warning', async () => {
      const h = harness({ cwd: realDir });
      await h.run(['init']);
      await h.run(['unlock']);
      await h.run(['key', 'export-recovery', '--out', 'r.json']);

      expect(await h.run(['verify', '--access'])).toBe(0);
      const text = h.stderrText();
      expect(text).toContain('export ');
      expect(text).toContain('covers gen 1');
      expect(text).toMatch(/non-revocable/);
    });

    it('lists a removed recipient, with a note that they can still read what they already held', async () => {
      const h = harness({ cwd: realDir });
      await h.run(['init']);
      await h.run(['unlock']);

      const otherHome = await mkdtemp(join(tmpdir(), 'securegit-cli-access-identity-'));
      const other = harness({ home: otherHome });
      await other.run(['identity', 'init']);
      const identity = JSON.parse(await readFile(join(otherHome, '.securegit', 'identity.json'), 'utf8'));

      await h.run(['key', 'add-recipient', identity.publicKey, '--label', 'contractor']);
      await h.run(['key', 'remove-recipient', identity.fingerprint]);

      expect(await h.run(['verify', '--access'])).toBe(0);
      const text = h.stderrText();
      expect(text).toContain(identity.fingerprint);
      expect(text).toContain('contractor');
      expect(text).toMatch(/can still read/);
    });
  });

  describe('--history', () => {
    it('exits 0 with no plaintext ever committed in history', async () => {
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

      expect(await h.run(['verify', '--history'])).toBe(0);
      expect(h.stdoutCalls()).toBe(0);
      expect(h.stderrText()).toContain('no plaintext found in history');
    });

    it('exits leaked (5) and reports first/last commit for plaintext buried in reachable history', async () => {
      const h = harness({ cwd: realDir });
      await h.run(['init']);
      await h.run(['protect', 'config/production.json']); // install() never called
      await execFile('git', ['add', '-A'], { cwd: realDir });
      await execFile('git', ['commit', '--quiet', '-m', 'init'], { cwd: realDir });

      await stageContent(realDir, 'config/production.json', Buffer.from('{"password":"hunter2"}\n'));
      await execFile('git', ['commit', '--quiet', '-m', 'oops'], { cwd: realDir });

      expect(await h.run(['verify', '--history'])).toBe(5);
      const text = h.stderrText();
      expect(text).toContain('plaintext at config/production.json');
      expect(text).toContain('first:');
      expect(text).toContain('last:');
      expect(text).toMatch(/Rotate the secret/);
    });
  });
});

describe('key rotate / reencrypt', () => {
  // `git status`'s dirty-check has to actually run our filter to know a
  // staged ciphertext blob matches a plaintext worktree file — without a
  // real, invokable binary configured via `install`, it just compares raw
  // bytes and always sees a "modified" file. Building once here and
  // installing with a real `--bin` is what git.integration.test.ts already
  // does for the same reason.
  const REPO_ROOT = join(import.meta.dirname, '..');
  const BIN = join(REPO_ROOT, 'dist', 'bin', 'securegit.js');
  const FILTER_BIN = `node "${BIN}"`;

  beforeAll(async () => {
    await execFile('npm', ['run', 'build'], { cwd: REPO_ROOT });
  }, 60_000);

  const PATH = 'config/production.json';
  const PT1 = Buffer.from('{"password":"hunter2"}\n');

  let realDir: string;
  let realHome: string;

  // No `XDG_RUNTIME_DIR`, deliberately: the injected-IO `h.run(['unlock'])`
  // calls below write a session using the harness's own `env` (which has
  // none either), so a real `git`-spawned filter subprocess has to resolve
  // the same session path — meaning it needs the same minimal env, not
  // whatever the test runner's real environment happens to have.
  function gitEnv(home: string): NodeJS.ProcessEnv {
    return { PATH: process.env.PATH, HOME: home };
  }

  async function realGit(args: string[]): Promise<string> {
    const { stdout } = await execFile('git', args, { cwd: realDir, env: gitEnv(realHome) });
    return stdout.replace(/\n$/, '');
  }

  beforeEach(async () => {
    realDir = await mkdtemp(join(tmpdir(), 'securegit-cli-rotate-'));
    realHome = await mkdtemp(join(tmpdir(), 'securegit-cli-rotate-home-'));
    await execFile('git', ['init', '--quiet'], { cwd: realDir });
    await execFile('git', ['config', 'user.name', 'Test'], { cwd: realDir });
    await execFile('git', ['config', 'user.email', 'test@example.com'], { cwd: realDir });
  });

  afterEach(async () => {
    await rm(realDir, { recursive: true, force: true });
    await rm(realHome, { recursive: true, force: true });
  });

  async function setUp(): Promise<ReturnType<typeof harness>> {
    const h = harness({ cwd: realDir, home: realHome });
    await h.run(['init']);
    await h.run(['unlock']);
    await h.run(['install', '--bin', FILTER_BIN]);
    await h.run(['protect', PATH]);
    await execFile('git', ['add', '-A'], { cwd: realDir, env: gitEnv(realHome) });
    await execFile('git', ['commit', '--quiet', '-m', 'init'], { cwd: realDir, env: gitEnv(realHome) });

    // A real `git add` here, not plumbing — `key rotate`'s dirty-check and
    // `reencrypt` both need the filter genuinely attached and working, so
    // the setup has to be real too, not a shortcut around it.
    await mkdir(join(realDir, 'config'), { recursive: true });
    await writeFile(join(realDir, PATH), PT1);
    await execFile('git', ['add', PATH], { cwd: realDir, env: gitEnv(realHome) });
    await execFile('git', ['commit', '--quiet', '-m', 'add config'], { cwd: realDir, env: gitEnv(realHome) });
    return h;
  }

  describe('key rotate', () => {
    it('refuses --bind-path (not yet implemented)', async () => {
      const h = await setUp();
      expect(await h.run(['key', 'rotate', '--bind-path'])).toBe(4);
    });

    it('refuses a dirty working tree', async () => {
      const h = await setUp();
      await writeFile(join(realDir, 'untracked.txt'), 'dirty\n');
      await execFile('git', ['add', 'untracked.txt'], { cwd: realDir, env: gitEnv(realHome) });
      expect(await h.run(['key', 'rotate'])).toBe(4);
    });

    it('refuses when locked', async () => {
      const h = await setUp();
      await h.run(['lock']);
      expect(await h.run(['key', 'rotate'])).toBe(1);
    });

    it('adds a generation, keeps the old one, and invalidates the session', async () => {
      const h = await setUp();
      expect(await h.run(['key', 'rotate'])).toBe(0);
      expect(await h.run(['status'])).toBe(1); // rotate locks; a fresh unlock is required

      await h.run(['unlock']);
      // The file committed under generation 1 must still decrypt.
      const committed = await execFile('git', ['cat-file', '-p', `HEAD:${PATH}`], {
        cwd: realDir,
        encoding: 'buffer',
        env: gitEnv(realHome),
      });
      expect(await h.run(['smudge', '--', PATH], { stdin: committed.stdout })).toBe(0);
      expect(h.stdoutBuf().equals(PT1)).toBe(true);
    });

    it('wraps the new generation for every existing recipient', async () => {
      const h = await setUp();
      const recipientHome = await mkdtemp(join(tmpdir(), 'securegit-cli-rotate-recipient-'));
      try {
        const recipient = harness({ cwd: realDir, home: recipientHome });
        await recipient.run(['identity', 'init', '--label', 'recipient']);
        const identity = JSON.parse(
          await readFile(join(recipientHome, '.securegit', 'identity.json'), 'utf8'),
        ) as { publicKey: string; fingerprint: string };

        await h.run(['key', 'add-recipient', identity.publicKey, '--label', 'recipient']);
        // `add-recipient` writes the file but deliberately doesn't commit it
        // (its own message says to) — `rotate`'s dirty-tree check would
        // otherwise correctly refuse here, exactly as it should for a real
        // uncommitted change.
        await execFile('git', ['add', '.securegit/recipients'], { cwd: realDir, env: gitEnv(realHome) });
        await execFile('git', ['commit', '--quiet', '-m', 'add recipient'], {
          cwd: realDir,
          env: gitEnv(realHome),
        });

        expect(await h.run(['key', 'rotate'])).toBe(0);

        const recipientFile = JSON.parse(
          await readFile(
            join(realDir, '.securegit', 'recipients', `${identity.fingerprint}.json`),
            'utf8',
          ),
        ) as { keys: Record<string, unknown> };
        expect(Object.keys(recipientFile.keys).sort()).toEqual(['1', '2']);

        // The recipient can unlock and land on the new generation as current.
        expect(await recipient.run(['unlock'])).toBe(0);
        expect(recipient.stderrText()).toContain('generation 2.');
      } finally {
        await rm(recipientHome, { recursive: true, force: true });
      }
    });
  });

  describe('reencrypt', () => {
    it('--dry-run stages nothing', async () => {
      const h = await setUp();
      await h.run(['key', 'rotate']);
      await h.run(['unlock']);

      const before = await realGit(['status', '--porcelain']);
      expect(await h.run(['reencrypt', '--dry-run'])).toBe(0);
      expect(await realGit(['status', '--porcelain'])).toBe(before);
      expect(h.stderrText()).toContain('would change');
    });

    it('moves a protected file to the current generation, staged but not committed', async () => {
      const h = await setUp();
      await h.run(['key', 'rotate']);
      await h.run(['unlock']);

      const beforeHead = await realGit(['rev-parse', `HEAD:${PATH}`]);
      expect(await h.run(['reencrypt'])).toBe(0);

      // History is untouched...
      expect(await realGit(['rev-parse', `HEAD:${PATH}`])).toBe(beforeHead);
      // ...but the index now holds a different (re-encrypted) blob.
      const stagedSha = await realGit(['rev-parse', ':' + PATH]);
      expect(stagedSha).not.toBe(beforeHead);

      const staged = await execFile('git', ['cat-file', '-p', `:${PATH}`], {
        cwd: realDir,
        encoding: 'buffer',
        env: gitEnv(realHome),
      });
      expect(await h.run(['smudge', '--', PATH], { stdin: staged.stdout })).toBe(0);
      expect(h.stdoutBuf().equals(PT1)).toBe(true);
    });

    it('is a no-op the second time, once everything is already current', async () => {
      const h = await setUp();
      await h.run(['key', 'rotate']);
      await h.run(['unlock']);
      await h.run(['reencrypt']);

      const stagedSha = await realGit(['rev-parse', ':' + PATH]);
      expect(await h.run(['reencrypt'])).toBe(0);
      expect(h.stderrText()).toContain('already current');
      expect(await realGit(['rev-parse', ':' + PATH])).toBe(stagedSha);
    });

    it('exits locked when the repository is locked', async () => {
      const h = await setUp();
      await h.run(['lock']);
      expect(await h.run(['reencrypt'])).toBe(1);
    });
  });
});

describe('runFilterProcess()', () => {
  const PATH = 'config/production.json';
  const PT = Buffer.from('{"timeout":30}\n');

  function handshakeRequest(): Buffer {
    return encodePacketList([Buffer.from('git-filter-client\n'), Buffer.from('version=2\n')]);
  }
  function capabilitiesRequest(): Buffer {
    return encodePacketList([Buffer.from('capability=clean\n'), Buffer.from('capability=smudge\n')]);
  }
  function commandRequest(command: string, pathname: string, content: Buffer): Buffer {
    return Buffer.concat([
      encodePacketList([Buffer.from(`command=${command}\n`), Buffer.from(`pathname=${pathname}\n`)]),
      encodePacketList(splitContent(content)),
    ]);
  }
  function readAllLists(buf: Buffer): Buffer[][] {
    const reader = new PktLineReader();
    reader.push(buf);
    const lists: Buffer[][] = [];
    for (;;) {
      const list = reader.readList();
      if (list === undefined) break;
      lists.push(list);
    }
    return lists;
  }
  function textOf(list: Buffer[]): string[] {
    return list.map((b) => b.toString('utf8').replace(/\n$/, ''));
  }

  function filterProcessHarness(overrides: Partial<FilterProcessIO> = {}) {
    const written: Buffer[] = [];
    const errLines: string[] = [];
    let dataHandler: ((chunk: Buffer) => void | Promise<void>) | null = null;
    let endHandler: (() => void) | null = null;
    // `runFilterProcess` registers onData/onEnd only after an `await
    // readConfig(...)` — a real async file read — so a test that calls
    // `push()`/`end()` right after `start()` has to wait for that
    // registration first, not just for one microtask tick.
    let resolveReady: () => void;
    const ready = new Promise<void>((resolve) => {
      resolveReady = resolve;
    });
    let dataSet = false;
    let endSet = false;
    const checkReady = (): void => {
      if (dataSet && endSet) resolveReady();
    };
    const io: FilterProcessIO = {
      cwd: dir,
      env: {},
      home,
      onData: (h) => {
        dataHandler = h;
        dataSet = true;
        checkReady();
      },
      onEnd: (h) => {
        endHandler = h;
        endSet = true;
        checkReady();
      },
      write: (chunk) => written.push(chunk),
      stderr: (message) => errLines.push(message),
      ...overrides,
    };
    return {
      start: () => runFilterProcess(io),
      push: async (chunk: Buffer): Promise<void> => {
        await ready;
        await dataHandler!(chunk);
      },
      end: async (): Promise<void> => {
        await ready;
        endHandler!();
      },
      outBuf: () => Buffer.concat(written),
      reset: () => {
        written.length = 0;
      },
      stderrText: () => errLines.join('\n'),
    };
  }

  it('exits misconfigured before init', async () => {
    const h = filterProcessHarness();
    expect(await h.start()).toBe(2);
  });

  it('resolves with exit 0 once stdin ends', async () => {
    const initHarness = harness();
    await initHarness.run(['init']);
    await initHarness.run(['unlock']);

    const h = filterProcessHarness();
    const result = h.start();
    await h.end();
    expect(await result).toBe(0);
  });

  it('serves a real handshake, capabilities, and a clean/smudge round trip', async () => {
    const initHarness = harness();
    await initHarness.run(['init']);
    await initHarness.run(['unlock']);

    const h = filterProcessHarness();
    const result = h.start();

    await h.push(handshakeRequest());
    expect(textOf(readAllLists(h.outBuf())[0]!)).toEqual(['git-filter-server', 'version=2']);

    h.reset();
    await h.push(capabilitiesRequest());
    expect(textOf(readAllLists(h.outBuf())[0]!)).toEqual(['capability=clean', 'capability=smudge']);

    h.reset();
    await h.push(commandRequest('clean', PATH, PT));
    const cleanLists = readAllLists(h.outBuf());
    expect(textOf(cleanLists[0]!)).toEqual(['status=success']);
    const ciphertext = Buffer.concat(cleanLists[1]!);
    expect(looksLikeEnvelope(ciphertext)).toBe(true);

    h.reset();
    await h.push(commandRequest('smudge', PATH, ciphertext));
    const smudgeLists = readAllLists(h.outBuf());
    expect(textOf(smudgeLists[0]!)).toEqual(['status=success']);
    expect(Buffer.concat(smudgeLists[1]!).equals(PT)).toBe(true);

    await h.end();
    expect(await result).toBe(0);
  });

  it('clean over the process protocol matches clean over the one-shot CLI, byte for byte', async () => {
    const initHarness = harness();
    await initHarness.run(['init']);
    await initHarness.run(['unlock']);
    await initHarness.run(['clean', '--', PATH], { stdin: PT });
    const viaOneShot = initHarness.stdoutBuf();

    const h = filterProcessHarness();
    const result = h.start();
    await h.push(handshakeRequest());
    await h.push(capabilitiesRequest());
    h.reset();
    await h.push(commandRequest('clean', PATH, PT));
    const viaProcess = Buffer.concat(readAllLists(h.outBuf())[1]!);
    await h.end();
    await result;

    expect(viaProcess.equals(viaOneShot)).toBe(true);
  });

  it('resolves with the usage exit code on a protocol violation, without hanging', async () => {
    const initHarness = harness();
    await initHarness.run(['init']);
    await initHarness.run(['unlock']);

    const h = filterProcessHarness();
    const result = h.start();
    await h.push(encodePacketList([Buffer.from('not-a-handshake\n')]));
    expect(await result).toBe(4);
    expect(h.stderrText().length).toBeGreaterThan(0);
  });

  it('serializes chunks that arrive before the previous one finished processing', async () => {
    // `keys()` does real async work per command (a session read), so two
    // `onData` firings close together — as a real pipe can deliver — must
    // not both start processing before the first settles; the server's
    // parse state (pending header, in-progress content) is shared mutable
    // state, and interleaving it would corrupt whichever blob loses the
    // race. Firing both pushes WITHOUT awaiting the first, then awaiting
    // both, is what actually exercises the ordering guarantee.
    const initHarness = harness();
    await initHarness.run(['init']);
    await initHarness.run(['unlock']);

    const h = filterProcessHarness();
    const result = h.start();
    await h.push(handshakeRequest());
    await h.push(capabilitiesRequest());
    h.reset();

    const aContent = Buffer.from('{"a":1}\n');
    const bContent = Buffer.from('{"b":2}\n');
    const first = h.push(commandRequest('clean', 'a.json', aContent));
    const second = h.push(commandRequest('clean', 'b.json', bContent));
    await Promise.all([first, second]);

    const lists = readAllLists(h.outBuf());
    // Two full command responses, each three lists (status, content, trailing).
    expect(lists).toHaveLength(6);
    expect(textOf(lists[0]!)).toEqual(['status=success']);
    expect(textOf(lists[3]!)).toEqual(['status=success']);

    // Each response decrypts back to exactly the content its own request
    // carried — proof neither blob's content leaked into the other's.
    expect(await initHarness.run(['smudge', '--', 'a.json'], { stdin: Buffer.concat(lists[1]!) })).toBe(0);
    expect(initHarness.stdoutBuf().equals(aContent)).toBe(true);
    expect(await initHarness.run(['smudge', '--', 'b.json'], { stdin: Buffer.concat(lists[4]!) })).toBe(0);
    expect(initHarness.stdoutBuf().equals(bContent)).toBe(true);

    await h.end();
    await result;
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
