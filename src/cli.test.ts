import { describe, it, expect, beforeAll, beforeEach, afterEach } from 'vitest';
import { execFile as execFileCb } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, rm, mkdir, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import { randomBytes } from 'node:crypto';
import { looksLikeEnvelope, parseEnvelope } from './envelope.js';
import { runCli, runFilterProcess, type CliIO, type FilterProcessIO } from './cli.js';
import { resolveSessionPath } from './session.js';
import { resolveKeyringPath } from './config.js';
import { createKeyring, writeKeyringFile } from './keyring.js';
import { PassphraseFileProvider, DEFAULT_SCRYPT_N } from './provider.js';
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
  const infoLines: string[] = [];
  const io: CliIO = {
    argv: [],
    cwd: dir,
    env: { SECUREGIT_PASSPHRASE: 'correct horse battery staple' },
    stdin: Buffer.alloc(0),
    home,
    stdout: (chunk) => outChunks.push(chunk),
    stderr: (message) => errLines.push(message),
    info: (message) => infoLines.push(message),
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
      infoLines.length = 0;
      return runCli({ ...io, argv, ...io2 });
    },
    stdoutBuf: () => Buffer.concat(outChunks),
    stdoutText: () => Buffer.concat(outChunks).toString('utf8'),
    stderrText: () => errLines.join('\n'),
    infoText: () => infoLines.join('\n'),
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

describe('--repo <path>', () => {
  let otherDir: string;

  beforeEach(async () => {
    otherDir = await mkdtemp(join(tmpdir(), 'securegit-cli-repo-flag-'));
    await mkdir(join(otherDir, '.git'));
  });

  afterEach(async () => {
    await rm(otherDir, { recursive: true, force: true });
  });

  it('operates on the named repository instead of the default cwd, flag before the command', async () => {
    const h = harness();
    expect(await h.run(['--repo', otherDir, 'init'])).toBe(0);
    await expect(readFile(join(otherDir, '.securegit', 'config.json'))).resolves.toBeDefined();
    await expect(readFile(join(dir, '.securegit', 'config.json'))).rejects.toThrow();
  });

  it('works with the flag placed after the command too', async () => {
    const h = harness();
    expect(await h.run(['init', '--repo', otherDir])).toBe(0);
    await expect(readFile(join(otherDir, '.securegit', 'config.json'))).resolves.toBeDefined();
  });

  it('resolves a relative path against the default cwd', async () => {
    const relativePath = relative(dir, otherDir);
    const h = harness();
    expect(await h.run(['--repo', relativePath, 'init'])).toBe(0);
    await expect(readFile(join(otherDir, '.securegit', 'config.json'))).resolves.toBeDefined();
  });

  it('exits usage when --repo has no path argument', async () => {
    const h = harness();
    expect(await h.run(['--repo'])).toBe(4);
  });

  it('combines with other flags — e.g. status --json — and never leaks into the stripped argv', async () => {
    const h = harness();
    await h.run(['--repo', otherDir, 'init']);
    await h.run(['--repo', otherDir, 'unlock']);
    expect(await h.run(['--repo', otherDir, 'status', '--json'])).toBe(0);
    const parsed = JSON.parse(h.stdoutText());
    expect(parsed.repository).toBe(otherDir);
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

describe('unprotect', () => {
  it('exits 4 with no patterns', async () => {
    const h = harness();
    expect(await h.run(['unprotect'])).toBe(4);
  });

  it('removes the pattern from .gitattributes and warns about already-committed blobs', async () => {
    const h = harness();
    await h.run(['protect', '.env']);
    expect(await h.run(['unprotect', '.env'])).toBe(0);
    const content = await readFile(join(dir, '.gitattributes'), 'utf8');
    expect(content).not.toContain('.env filter=securegit');
    expect(h.infoText()).toContain('stay encrypted');
  });

  it('is a silent no-op (exit 0) for a pattern that was never protected', async () => {
    const h = harness();
    expect(await h.run(['unprotect', '.never-protected'])).toBe(0);
  });

  it('writes nothing to stdout', async () => {
    const h = harness();
    await h.run(['protect', '.env']);
    await h.run(['unprotect', '.env']);
    expect(h.stdoutCalls()).toBe(0);
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
    // No SECUREGIT_PASSPHRASE on this call — genuinely no credentials at
    // all, not just no session, now that the env var is also a filter-time
    // source (07-unlock-session.md).
    expect(await h.run(['status'], { env: {} })).toBe(1);
  });

  it('unlock exits 0 with the right passphrase, status then exits 0', async () => {
    const h = harness();
    await h.run(['init']);
    expect(await h.run(['unlock'])).toBe(0);
    expect(await h.run(['status'])).toBe(0);
  });

  it('re-wraps a keyring wrapped at an old scrypt cost on the next successful unlock', async () => {
    const h = harness();
    await h.run(['init']);
    const config = JSON.parse(
      await readFile(join(dir, '.securegit', 'config.json'), 'utf8'),
    ) as { repoId: string };
    const keyringPath = resolveKeyringPath(config.repoId, home);

    // Overwrite init's own (already-current-cost) keyring with a hand-built
    // one at an old, low cost — same repoId, same passphrase.
    const oldProvider = new PassphraseFileProvider(
      () => 'correct horse battery staple',
      { N: 2 ** 10, r: 8, p: 1 },
    );
    const { file: oldFile } = await createKeyring(config.repoId, [oldProvider]);
    expect(oldFile.generations[0]!.wrapped[0]!.state.N).toBe(2 ** 10);
    await writeKeyringFile(keyringPath, oldFile);

    expect(await h.run(['unlock'])).toBe(0);
    expect(h.infoText()).toContain('re-wrapped');

    const after = JSON.parse(await readFile(keyringPath, 'utf8')) as {
      generations: { wrapped: { state: { N: number } }[] }[];
    };
    expect(after.generations[0]!.wrapped[0]!.state.N).toBe(DEFAULT_SCRYPT_N);

    // Still usable: lock, then unlock again with the same passphrase.
    await h.run(['lock']);
    expect(await h.run(['unlock'])).toBe(0);
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
    // No SECUREGIT_PASSPHRASE here — otherwise the filter-time source would
    // mask what `lock` actually did to the session.
    expect(await h.run(['status'], { env: {} })).toBe(1);
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

  describe('status --json', () => {
    it('writes machine-readable output to stdout, not stderr', async () => {
      const h = harness();
      await h.run(['init']);
      await h.run(['unlock']);
      expect(await h.run(['status', '--json'])).toBe(0);
      expect(h.stderrText()).toBe('');
      const parsed = JSON.parse(h.stdoutText());
      expect(parsed.repository).toBe(dir);
      expect(parsed.locked).toBe(false);
      expect(typeof parsed.generation).toBe('string');
      expect(parsed.bindPath).toBe(false);
      expect(parsed.padTo).toBe(0);
    });

    it('reports locked: true and generation: null while locked, still exiting 1', async () => {
      const h = harness();
      await h.run(['init']);
      expect(await h.run(['status', '--json'], { env: {} })).toBe(1);
      const parsed = JSON.parse(h.stdoutText());
      expect(parsed.locked).toBe(true);
      expect(parsed.generation).toBe(null);
    });

    it('includes the M1–M12 metadata report, reflecting padTo and bindPath', async () => {
      const h = harness();
      await h.run(['init', '--bind-path', '--pad-to', '4096']);
      await h.run(['unlock']);
      expect(await h.run(['status', '--json'])).toBe(0);
      const parsed = JSON.parse(h.stdoutText());
      expect(parsed.metadata.observables).toHaveLength(12);
      const m2 = parsed.metadata.observables.find((o: { code: string }) => o.code === 'M2');
      expect(m2.note).toContain('4096');
      const m8 = parsed.metadata.observables.find((o: { code: string }) => o.code === 'M8');
      expect(m8.note).toMatch(/partially mitigated/);
    });
  });

  it('the human-readable form points at status --json for the M1–M12 detail, and shows padTo', async () => {
    const h = harness();
    await h.run(['init']);
    await h.run(['unlock']);
    await h.run(['status']);
    const text = h.stderrText();
    expect(text).toContain('padTo');
    expect(text).toContain('status --json');
  });

  it('warns about a single recovery path for a fresh solo repository, in both forms', async () => {
    const h = harness();
    await h.run(['init']);
    await h.run(['unlock']);

    await h.run(['status']);
    expect(h.stderrText()).toMatch(/recovery.*⚠.*1 recovery path/);

    expect(await h.run(['status', '--json'])).toBe(0);
    const parsed = JSON.parse(h.stdoutText());
    expect(parsed.recoveryPaths).toEqual({ paths: 1, hasExport: false, warn: true });
  });

  it('stops warning once a second recipient covers the current generation', async () => {
    const h = harness();
    await h.run(['init']);
    await h.run(['unlock']);

    const otherHome = await mkdtemp(join(tmpdir(), 'securegit-cli-recovery-path-identity-'));
    const other = harness({ home: otherHome });
    await other.run(['identity', 'init']);
    const identity = JSON.parse(await readFile(join(otherHome, '.securegit', 'identity.json'), 'utf8'));
    await h.run(['key', 'add-recipient', identity.publicKey, '--label', 'laptop']);

    await h.run(['status']);
    expect(h.stderrText()).not.toContain('recovery ');

    await h.run(['status', '--json']);
    const parsed = JSON.parse(h.stdoutText());
    expect(parsed.recoveryPaths).toEqual({ paths: 2, hasExport: false, warn: false });
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
    expect(await h.run(['key', 'add-recipient', identity.publicKey], { env: {} })).toBe(1);
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
    expect(b.infoText()).toContain('unlocked via recipient');

    // Machine A encrypts; machine B, unlocked purely via the recipient file, decrypts.
    // No SECUREGIT_PASSPHRASE on this call: machine B has no local repo
    // keyring for that filter-time source to unwrap (it only ever joined via
    // the recipient file), but its harness's default value is still a
    // *string* the source would try first — proving decryption genuinely
    // comes from the session `unlock` established above, not incidentally
    // masked by a same-named env var left over from identity setup.
    await a.run(['clean', '--', PATH], { stdin: PT });
    const ciphertext = a.stdoutBuf();
    expect(await b.run(['smudge', '--', PATH], { stdin: ciphertext, env: {} })).toBe(0);
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
    expect(await h.run(['key', 'export-recovery', '--out', 'r.json'], { env: {} })).toBe(1);
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

  it('clean fails with exit 1 while locked, writing the diagnostic to stderr only, nothing to stdout', async () => {
    const h = harness();
    await h.run(['init']);
    expect(await h.run(['clean', '--', PATH], { stdin: PT, env: {} })).toBe(1);
    expect(h.stderrText()).toContain(PATH);
    expect(h.stdoutCalls()).toBe(0);
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
    expect(await h.run(['smudge', '--', PATH], { stdin: ciphertext, env: {} })).toBe(0);
    expect(h.stdoutBuf().equals(ciphertext)).toBe(true);
    expect(h.stderrText().length).toBeGreaterThan(0);
  });

  it('smudge --strict fails instead of passing through while locked', async () => {
    const h = harness();
    await initAndUnlock(h);
    await h.run(['clean', '--', PATH], { stdin: PT });
    const ciphertext = h.stdoutBuf();

    await h.run(['lock']);
    expect(await h.run(['smudge', '--strict', '--', PATH], { stdin: ciphertext, env: {} })).toBe(1);
  });

  it('clean/smudge exit 4 when the `--` separator is missing', async () => {
    const h = harness();
    await initAndUnlock(h);
    expect(await h.run(['clean', PATH], { stdin: PT })).toBe(4);
    expect(await h.run(['smudge', PATH], { stdin: PT })).toBe(4);
  });

  describe('-v / --verbose', () => {
    it('clean -v traces the path and generation to stderr, without plaintext or key material', async () => {
      const h = harness();
      await initAndUnlock(h);
      expect(await h.run(['clean', '-v', '--', PATH], { stdin: PT })).toBe(0);
      const trace = h.stderrText();
      expect(trace).toContain(PATH);
      expect(trace).toContain('generation');
      expect(trace).not.toContain('timeout'); // the plaintext content
      expect(trace).not.toContain('correct horse battery staple'); // the passphrase
    });

    it('clean without -v traces nothing', async () => {
      const h = harness();
      await initAndUnlock(h);
      await h.run(['clean', '--', PATH], { stdin: PT });
      expect(h.stderrText()).toBe('');
    });

    it('smudge --verbose traces the path and generation to stderr, without plaintext', async () => {
      const h = harness();
      await initAndUnlock(h);
      await h.run(['clean', '--', PATH], { stdin: PT });
      const ciphertext = h.stdoutBuf();

      expect(await h.run(['smudge', '--verbose', '--', PATH], { stdin: ciphertext })).toBe(0);
      const trace = h.stderrText();
      expect(trace).toContain(PATH);
      expect(trace).toContain('generation');
      expect(trace).not.toContain('timeout');
    });

    it('smudge without --verbose traces nothing on the happy path', async () => {
      const h = harness();
      await initAndUnlock(h);
      await h.run(['clean', '--', PATH], { stdin: PT });
      const ciphertext = h.stdoutBuf();

      await h.run(['smudge', '--', PATH], { stdin: ciphertext });
      expect(h.stderrText()).toBe('');
    });
  });

  describe('SECUREGIT_SESSION_KEY', () => {
    it('clean/smudge/status work from the env var alone, without ever calling unlock', async () => {
      const h = harness();
      await h.run(['init']);
      await h.run(['unlock']); // only to produce a real session file to extract from
      const config = JSON.parse(
        await readFile(join(dir, '.securegit', 'config.json'), 'utf8'),
      ) as { repoId: string };
      const sessionPath = resolveSessionPath(config.repoId, h.io.env, home);
      const sessionKey = (await readFile(sessionPath)).toString('base64');

      // A fresh harness: unlock is never called on it — only the env var.
      const fresh = harness({ env: { SECUREGIT_SESSION_KEY: sessionKey } });
      expect(await fresh.run(['status'])).toBe(0);
      expect(await fresh.run(['clean', '--', PATH], { stdin: PT })).toBe(0);
      const ciphertext = fresh.stdoutBuf();
      expect(looksLikeEnvelope(ciphertext)).toBe(true);

      expect(await fresh.run(['smudge', '--', PATH], { stdin: ciphertext })).toBe(0);
      expect(fresh.stdoutBuf().equals(PT)).toBe(true);
    });

    it('takes precedence over an existing, valid session file — an invalid env value does not fall back to it', async () => {
      const h = harness();
      await h.run(['init']);
      await h.run(['unlock']); // writes a real, valid session file on disk

      expect(
        await h.run(['status'], { env: { ...h.io.env, SECUREGIT_SESSION_KEY: 'not a real session key' } }),
      ).toBe(1); // locked, not 0 — the good session file on disk is never consulted
    });

    it('an expired session key is locked, same as an expired session file', async () => {
      const h = harness();
      await h.run(['init']);
      await h.run(['unlock']);
      const config = JSON.parse(
        await readFile(join(dir, '.securegit', 'config.json'), 'utf8'),
      ) as { repoId: string };
      const sessionPath = resolveSessionPath(config.repoId, h.io.env, home);
      const expired = JSON.parse(await readFile(sessionPath, 'utf8')) as { expiresAt: string };
      expired.expiresAt = new Date(0).toISOString();
      const sessionKey = Buffer.from(JSON.stringify(expired), 'utf8').toString('base64');

      const fresh = harness({ env: { SECUREGIT_SESSION_KEY: sessionKey } });
      expect(await fresh.run(['status'])).toBe(1);
    });
  });

  // SECUREGIT_PASSPHRASE ranks second, unwrapping the *local* keyring
  // directly — no `unlock` ever has to run, nothing written to disk. Unlike
  // SECUREGIT_SESSION_KEY this gives standing, non-time-bounded access for
  // as long as the variable is set: there is no expiresAt, and `lock` can't
  // revoke it (there's no session file behind it to remove). Accepted
  // tradeoff for the CI use case 07-unlock-session.md documents — a real
  // developer shell that happens to have this set persistently gets the
  // same standing access, which is exactly why it's not the harness's
  // default for any test below that means to assert "locked".
  describe('SECUREGIT_PASSPHRASE (filter-time source)', () => {
    it('clean/smudge/status work from the env var alone, without ever calling unlock', async () => {
      const h = harness();
      await h.run(['init']); // the default harness env's passphrase is what the keyring gets created with
      expect(await h.run(['status'])).toBe(0); // same default env, consulted again here — no unlock in between
      expect(await h.run(['clean', '--', PATH], { stdin: PT })).toBe(0);
      const ciphertext = h.stdoutBuf();
      expect(looksLikeEnvelope(ciphertext)).toBe(true);

      expect(await h.run(['smudge', '--', PATH], { stdin: ciphertext })).toBe(0);
      expect(h.stdoutBuf().equals(PT)).toBe(true);
    });

    it('a wrong passphrase is locked, not a throw', async () => {
      const h = harness();
      await h.run(['init']);
      expect(
        await h.run(['status'], { env: { SECUREGIT_PASSPHRASE: 'a totally different passphrase' } }),
      ).toBe(1);
    });

    it('takes precedence over an existing, valid session file — a wrong env value does not fall back to it', async () => {
      const h = harness();
      await h.run(['init']);
      await h.run(['unlock']); // writes a real, valid session file on disk

      expect(
        await h.run(['status'], { env: { SECUREGIT_PASSPHRASE: 'a totally different passphrase' } }),
      ).toBe(1); // locked, not 0 — the good session file on disk is never consulted
    });

    it('SECUREGIT_SESSION_KEY still wins when both are set', async () => {
      const h = harness();
      await h.run(['init']);
      await h.run(['unlock']);
      const config = JSON.parse(
        await readFile(join(dir, '.securegit', 'config.json'), 'utf8'),
      ) as { repoId: string };
      const sessionKey = (
        await readFile(resolveSessionPath(config.repoId, h.io.env, home))
      ).toString('base64');

      // A wrong passphrase alongside a genuinely good session key — if
      // precedence were wrong, this would be locked.
      expect(
        await h.run(['status'], {
          env: { SECUREGIT_SESSION_KEY: sessionKey, SECUREGIT_PASSPHRASE: 'a totally different passphrase' },
        }),
      ).toBe(0);
    });
  });

  // SECUREGIT_IDENTITY_FILE names *which* identity to join with, but
  // carries no secret of its own — SECUREGIT_PASSPHRASE unlocks it. So it
  // isn't a fourth independent precedence tier; it changes what
  // SECUREGIT_PASSPHRASE is applied to (this identity, via the
  // recipient-join flow, instead of the local keyring) whenever both are
  // set. Set alone, without SECUREGIT_PASSPHRASE, it's never consulted at
  // all — there's nothing to unlock it with.
  describe('SECUREGIT_IDENTITY_FILE', () => {
    it('clean/smudge/status work via SECUREGIT_IDENTITY_FILE + SECUREGIT_PASSPHRASE, without unlock and without a local keyring', async () => {
      // "Machine A" — already has full repository access.
      const a = harness();
      await a.run(['init']);
      await a.run(['unlock']);

      // "Machine B" — its own identity, in its own home. That home is never
      // used as this test's actual working home below; only its
      // identity.json path matters, as an arbitrary SECUREGIT_IDENTITY_FILE
      // value.
      const bHome = await mkdtemp(join(tmpdir(), 'securegit-cli-identity-file-'));
      const b = harness({ home: bHome });
      await b.run(['identity', 'init', '--label', 'machine-b']);
      const identity = JSON.parse(await readFile(join(bHome, '.securegit', 'identity.json'), 'utf8'));
      const identityFilePath = join(bHome, '.securegit', 'identity.json');

      await a.run(['key', 'add-recipient', identity.publicKey, '--label', 'machine-b']);

      // A fresh harness, its own home with no keyring or session of its
      // own — only the two env vars.
      const fresh = harness({
        env: {
          SECUREGIT_IDENTITY_FILE: identityFilePath,
          SECUREGIT_PASSPHRASE: 'correct horse battery staple',
        },
      });
      expect(await fresh.run(['status'])).toBe(0);

      await a.run(['clean', '--', PATH], { stdin: PT });
      const ciphertext = a.stdoutBuf();
      expect(await fresh.run(['smudge', '--', PATH], { stdin: ciphertext })).toBe(0);
      expect(fresh.stdoutBuf().equals(PT)).toBe(true);
    });

    it('a wrong passphrase is locked, not a throw', async () => {
      const a = harness();
      await a.run(['init']);
      await a.run(['unlock']);
      const bHome = await mkdtemp(join(tmpdir(), 'securegit-cli-identity-file-'));
      const b = harness({ home: bHome });
      await b.run(['identity', 'init']);
      const identity = JSON.parse(await readFile(join(bHome, '.securegit', 'identity.json'), 'utf8'));
      await a.run(['key', 'add-recipient', identity.publicKey]);

      const fresh = harness({
        env: {
          SECUREGIT_IDENTITY_FILE: join(bHome, '.securegit', 'identity.json'),
          SECUREGIT_PASSPHRASE: 'a totally different passphrase',
        },
      });
      expect(await fresh.run(['status'])).toBe(1);
    });

    it('a missing SECUREGIT_IDENTITY_FILE path is locked, not a throw', async () => {
      const fresh = harness({
        env: {
          SECUREGIT_IDENTITY_FILE: join(tmpdir(), 'securegit-nonexistent-identity.json'),
          SECUREGIT_PASSPHRASE: 'correct horse battery staple',
        },
      });
      await fresh.run(['init']); // this repo's own config must exist for loadKeys() to get past readConfig()
      expect(await fresh.run(['status'])).toBe(1);
    });

    it('an identity with no matching recipient file is locked, not a throw', async () => {
      const h = harness();
      await h.run(['init']);
      await h.run(['unlock']); // never adds any recipient
      const bHome = await mkdtemp(join(tmpdir(), 'securegit-cli-identity-file-'));
      const b = harness({ home: bHome });
      await b.run(['identity', 'init']);

      const fresh = harness({
        env: {
          SECUREGIT_IDENTITY_FILE: join(bHome, '.securegit', 'identity.json'),
          SECUREGIT_PASSPHRASE: 'correct horse battery staple',
        },
      });
      expect(await fresh.run(['status'])).toBe(1);
    });

    it('is ignored without SECUREGIT_PASSPHRASE — falls through to the session file', async () => {
      const h = harness();
      await h.run(['init']);
      await h.run(['unlock']); // writes a real, valid session

      // Pointing at something that doesn't even exist — if this were
      // consulted on its own, it would still resolve to locked. The point
      // is it's never looked at at all without a passphrase alongside it.
      expect(
        await h.run(['status'], { env: { SECUREGIT_IDENTITY_FILE: '/nonexistent/identity.json' } }),
      ).toBe(0);
    });

    it('takes precedence over an existing, valid session file', async () => {
      const fresh = harness();
      await fresh.run(['init']);
      await fresh.run(['unlock']); // a valid session, from fresh's own local keyring

      // SECUREGIT_IDENTITY_FILE + a passphrase now set for this call —
      // should not fall back to the good session sitting on disk.
      expect(
        await fresh.run(['status'], {
          env: {
            SECUREGIT_IDENTITY_FILE: join(tmpdir(), 'securegit-nonexistent-identity.json'),
            SECUREGIT_PASSPHRASE: 'irrelevant',
          },
        }),
      ).toBe(1);
    });
  });
});

describe('key add-provider / key remove-provider / key list / key list-recipients', () => {
  const BACKUP_PASSPHRASE = 'a second, independent secret!!';

  it('add-provider wraps every generation for a second, independent passphrase, unlockable on its own', async () => {
    const h = harness();
    await h.run(['init']);
    await h.run(['unlock']);

    // SECUREGIT_PASSPHRASE stays unset here on purpose: `loadKeys()` would
    // otherwise treat it as the credential to authenticate the *current*
    // keyring with (07-unlock-session.md), colliding with its other job
    // here — the *new* provider's passphrase. Already unlocked above (a
    // real session), the new one arrives over stdin instead, same as
    // `import-recovery`'s own two-secrets-one-command precedent.
    expect(
      await h.run(['key', 'add-provider', 'passphrase-file', '--label', 'backup'], {
        env: {},
        stdin: Buffer.from(`${BACKUP_PASSPHRASE}\n`),
      }),
    ).toBe(0);

    // The original passphrase still works...
    expect(await h.run(['lock'])).toBe(0);
    expect(await h.run(['unlock'])).toBe(0);

    // ...and so does the new one, entered on its own — `unlock` doesn't
    // need to be told which provider id it belongs to.
    expect(await h.run(['lock'])).toBe(0);
    expect(await h.run(['unlock'], { env: { SECUREGIT_PASSPHRASE: BACKUP_PASSPHRASE } })).toBe(0);
  });

  it('add-provider refuses without a --label, colliding with the existing unlabeled provider', async () => {
    const h = harness();
    await h.run(['init']);
    await h.run(['unlock']);
    expect(await h.run(['key', 'add-provider', 'passphrase-file'])).toBe(4);
  });

  it('add-provider exits locked when the repository is locked', async () => {
    const h = harness();
    await h.run(['init']); // never unlocked
    expect(
      await h.run(['key', 'add-provider', 'passphrase-file', '--label', 'backup'], { env: {} }),
    ).toBe(1);
  });

  it('add-provider exits usage for an unknown provider type', async () => {
    const h = harness();
    await h.run(['init']);
    await h.run(['unlock']);
    expect(await h.run(['key', 'add-provider', 'tpm2'])).toBe(4);
  });

  it('remove-provider deletes the named slot — the removed passphrase stops working, the remaining one still does', async () => {
    const h = harness();
    await h.run(['init']);
    await h.run(['unlock']);
    await h.run(['key', 'add-provider', 'passphrase-file', '--label', 'backup'], {
      env: {},
      stdin: Buffer.from(`${BACKUP_PASSPHRASE}\n`),
    });

    expect(await h.run(['key', 'remove-provider', 'passphrase-file'])).toBe(0);

    await h.run(['lock']);
    expect(await h.run(['unlock'])).toBe(1); // the removed (original) passphrase no longer works
    expect(await h.run(['unlock'], { env: { SECUREGIT_PASSPHRASE: BACKUP_PASSPHRASE } })).toBe(0);
  });

  it('remove-provider refuses to remove the only provider a generation has', async () => {
    const h = harness();
    await h.run(['init']);
    expect(await h.run(['key', 'remove-provider', 'passphrase-file'])).toBe(4);
  });

  it('remove-provider exits usage for an id that was never present', async () => {
    const h = harness();
    await h.run(['init']);
    expect(await h.run(['key', 'remove-provider', 'never-existed'])).toBe(4);
  });

  it('list reports generations, fingerprints, dates and providers, without needing a key', async () => {
    const h = harness();
    await h.run(['init']);
    expect(await h.run(['key', 'list'], { env: {} })).toBe(0);
    const text = h.stderrText();
    expect(text).toContain('gen 1');
    expect(text).toContain('providers: passphrase-file');
    expect(text).toContain('*'); // current marker
  });

  it('list --json writes the same information as structured data, to stdout', async () => {
    const h = harness();
    await h.run(['init']);
    expect(await h.run(['key', 'list', '--json'], { env: {} })).toBe(0);
    const parsed = JSON.parse(h.stdoutText());
    expect(parsed.current).toBe(1);
    expect(parsed.generations).toHaveLength(1);
    expect(parsed.generations[0].providers).toEqual(['passphrase-file']);
  });

  it('list-recipients exits misconfigured before init', async () => {
    const h = harness();
    expect(await h.run(['key', 'list-recipients'])).toBe(2);
  });

  it('list-recipients reports "(none)" for a fresh repository', async () => {
    const h = harness();
    await h.run(['init']);
    expect(await h.run(['key', 'list-recipients'], { env: {} })).toBe(0);
    expect(h.stderrText()).toContain('(none)');
  });

  it('list-recipients reports fingerprint, label, added-at and generations, without needing a key', async () => {
    const h = harness();
    await h.run(['init']);
    await h.run(['unlock']);
    const otherHome = await mkdtemp(join(tmpdir(), 'securegit-cli-list-recipients-'));
    const other = harness({ home: otherHome });
    await other.run(['identity', 'init']);
    const identity = JSON.parse(await readFile(join(otherHome, '.securegit', 'identity.json'), 'utf8'));
    await h.run(['key', 'add-recipient', identity.publicKey, '--label', 'laptop']);

    expect(await h.run(['key', 'list-recipients'], { env: {} })).toBe(0);
    const text = h.stderrText();
    expect(text).toContain(identity.fingerprint);
    expect(text).toContain('laptop');
    expect(text).toContain('gen 1');
  });

  it('list-recipients --json writes the same information as structured data, to stdout', async () => {
    const h = harness();
    await h.run(['init']);
    await h.run(['unlock']);
    const otherHome = await mkdtemp(join(tmpdir(), 'securegit-cli-list-recipients-'));
    const other = harness({ home: otherHome });
    await other.run(['identity', 'init']);
    const identity = JSON.parse(await readFile(join(otherHome, '.securegit', 'identity.json'), 'utf8'));
    await h.run(['key', 'add-recipient', identity.publicKey, '--label', 'laptop']);

    expect(await h.run(['key', 'list-recipients', '--json'], { env: {} })).toBe(0);
    const parsed = JSON.parse(h.stdoutText());
    expect(parsed).toHaveLength(1);
    expect(parsed[0].fingerprint).toBe(identity.fingerprint);
    expect(parsed[0].label).toBe('laptop');
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

    expect(await h.run(['merge', '--', baseFile, oursFile, theirsFile, '7', PATH], { env: {} })).toBe(1);
  });

  it('-v traces the path, generation and outcome to stderr, without plaintext', async () => {
    const h = harness();
    await initAndUnlock(h);

    const baseFile = join(dir, 'O');
    const oursFile = join(dir, 'A');
    const theirsFile = join(dir, 'B');
    await encryptToFile(h, BASE, baseFile);
    await encryptToFile(h, OURS, oursFile);
    await encryptToFile(h, THEIRS, theirsFile);

    expect(await h.run(['merge', '-v', '--', baseFile, oursFile, theirsFile, '7', PATH])).toBe(0);
    const trace = h.stderrText();
    expect(trace).toContain(PATH);
    expect(trace).toContain('generation');
    expect(trace).not.toContain('"a": 10'); // the plaintext content
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

    it('--json writes the AccessReport shape to stdout, not stderr', async () => {
      const h = harness({ cwd: realDir });
      await h.run(['init']);
      await h.run(['unlock']);

      expect(await h.run(['verify', '--access', '--json'])).toBe(0);
      expect(h.stderrText()).toBe('');
      const parsed = JSON.parse(h.stdoutText());
      expect(parsed.recipients).toEqual([]);
      expect(parsed.providers).toEqual([{ id: 'passphrase-file', generations: [1] }]);
      expect(parsed.recoveryExports).toEqual([]);
      expect(parsed.removedRecipients).toEqual([]);
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
      // `add-recipient` deliberately doesn't commit its own output.
      expect(text).toContain('(uncommitted)');

      await h.run(['verify', '--access', '--json']);
      const parsed = JSON.parse(h.stdoutText());
      expect(parsed.recipients[0].addedCommit).toBe(null);

      await execFile('git', ['add', '.securegit/recipients'], { cwd: realDir });
      await execFile('git', ['commit', '--quiet', '-m', 'add recipient'], { cwd: realDir });
      const expectedSha = (await execFile('git', ['log', '-1', '--format=%h'], { cwd: realDir })).stdout.trim();

      expect(await h.run(['verify', '--access'])).toBe(0);
      expect(h.stderrText()).toContain(`commit ${expectedSha}`);

      await h.run(['verify', '--access', '--json']);
      const parsedAfterCommit = JSON.parse(h.stdoutText());
      expect(parsedAfterCommit.recipients[0].addedCommit).toBe(expectedSha);
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

    it('--json writes the HistoryReport shape to stdout, same exit code', async () => {
      const h = harness({ cwd: realDir });
      await h.run(['init']);
      await h.run(['protect', 'config/production.json']);
      await execFile('git', ['add', '-A'], { cwd: realDir });
      await execFile('git', ['commit', '--quiet', '-m', 'init'], { cwd: realDir });
      await stageContent(realDir, 'config/production.json', Buffer.from('{"password":"hunter2"}\n'));
      await execFile('git', ['commit', '--quiet', '-m', 'oops'], { cwd: realDir });

      expect(await h.run(['verify', '--history', '--json'])).toBe(5);
      expect(h.stderrText()).toBe('');
      const parsed = JSON.parse(h.stdoutText());
      expect(parsed.findings).toHaveLength(1);
      expect(parsed.findings[0].path).toBe('config/production.json');
      expect(parsed.textconvNotesRef).toEqual({ present: false, count: 0 });
    });
  });

  describe('--json (base form)', () => {
    it('writes the VerifyReport shape to stdout, not stderr', async () => {
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

      expect(await h.run(['verify', '--json'])).toBe(0);
      expect(h.stderrText()).toBe('');
      const parsed = JSON.parse(h.stdoutText());
      expect(Array.isArray(parsed.checks)).toBe(true);
      expect(parsed.checks.every((c: { ok: boolean }) => c.ok)).toBe(true);
      // A solo repo with no recipients and no recovery export is a genuine
      // single point of failure — this advisory finding is expected, not noise.
      expect(parsed.findings).toEqual([{ kind: 'recovery', path: '(repository)', detail: expect.any(String) }]);
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

    it('refuses without --confirm-recipients, printing the (empty) recipient list', async () => {
      const h = await setUp();
      expect(await h.run(['key', 'rotate'], { env: {} })).toBe(4);
      const text = h.stderrText();
      expect(text).toContain('0 recipient');
      expect(text).toContain('--confirm-recipients 0');
    });

    it('refuses a --confirm-recipients count that does not match reality', async () => {
      const h = await setUp();
      expect(await h.run(['key', 'rotate', '--confirm-recipients', '3'], { env: {} })).toBe(4);
    });

    it('refuses a dirty working tree', async () => {
      const h = await setUp();
      await writeFile(join(realDir, 'untracked.txt'), 'dirty\n');
      await execFile('git', ['add', 'untracked.txt'], { cwd: realDir, env: gitEnv(realHome) });
      expect(await h.run(['key', 'rotate', '--confirm-recipients', '0'], { env: {} })).toBe(4);
    });

    it('refuses when locked, before ever asking for recipient confirmation', async () => {
      const h = await setUp();
      await h.run(['lock']);
      expect(await h.run(['key', 'rotate'], { env: {} })).toBe(1);
    });

    it('adds a generation, keeps the old one, and invalidates the session', async () => {
      const h = await setUp();
      // `key rotate` itself needs SECUREGIT_PASSPHRASE (or stdin) for its
      // own resolvePassphrase() call — it wraps the *new* generation with
      // it, a genuinely separate need from loadKeys()'s authentication
      // check, which is why this one call keeps the default env while
      // every other call in this file strips it.
      expect(await h.run(['key', 'rotate', '--confirm-recipients', '0'])).toBe(0);
      expect(await h.run(['status'], { env: {} })).toBe(1); // rotate locks; a fresh unlock is required

      await h.run(['unlock']);
      // The file committed under generation 1 must still decrypt.
      const committed = await execFile('git', ['cat-file', '-p', `HEAD:${PATH}`], {
        cwd: realDir,
        encoding: 'buffer',
        env: gitEnv(realHome),
      });
      expect(await h.run(['smudge', '--', PATH], { stdin: committed.stdout, env: {} })).toBe(0);
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

        await h.run(['key', 'add-recipient', identity.publicKey, '--label', 'recipient'], { env: {} });
        // `add-recipient` writes the file but deliberately doesn't commit it
        // (its own message says to) — `rotate`'s dirty-tree check would
        // otherwise correctly refuse here, exactly as it should for a real
        // uncommitted change.
        await execFile('git', ['add', '.securegit/recipients'], { cwd: realDir, env: gitEnv(realHome) });
        await execFile('git', ['commit', '--quiet', '-m', 'add recipient'], {
          cwd: realDir,
          env: gitEnv(realHome),
        });

        // Without confirmation, the list names the actual recipient.
        expect(await h.run(['key', 'rotate'], { env: {} })).toBe(4);
        expect(h.stderrText()).toContain(identity.fingerprint);

        // `key rotate` itself needs SECUREGIT_PASSPHRASE (or stdin) to wrap
        // the new generation — default env, unlike the calls around it.
        expect(await h.run(['key', 'rotate', '--confirm-recipients', '1'])).toBe(0);

        const recipientFile = JSON.parse(
          await readFile(
            join(realDir, '.securegit', 'recipients', `${identity.fingerprint}.json`),
            'utf8',
          ),
        ) as { keys: Record<string, unknown> };
        expect(Object.keys(recipientFile.keys).sort()).toEqual(['1', '2']);

        // The recipient can unlock and land on the new generation as current.
        expect(await recipient.run(['unlock'])).toBe(0);
        expect(recipient.infoText()).toContain('generation 2.');
      } finally {
        await rm(recipientHome, { recursive: true, force: true });
      }
    });
  });

  describe('reencrypt', () => {
    it('--dry-run stages nothing', async () => {
      const h = await setUp();
      expect(await h.run(['key', 'rotate', '--confirm-recipients', '0'])).toBe(0);
      await h.run(['unlock']);

      const before = await realGit(['status', '--porcelain']);
      expect(await h.run(['reencrypt', '--dry-run'], { env: {} })).toBe(0);
      expect(await realGit(['status', '--porcelain'])).toBe(before);
      expect(h.stderrText()).toContain('would change');
    });

    it('moves a protected file to the current generation, staged but not committed', async () => {
      const h = await setUp();
      expect(await h.run(['key', 'rotate', '--confirm-recipients', '0'])).toBe(0);
      await h.run(['unlock']);

      const beforeHead = await realGit(['rev-parse', `HEAD:${PATH}`]);
      expect(await h.run(['reencrypt'], { env: {} })).toBe(0);

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
      expect(await h.run(['smudge', '--', PATH], { stdin: staged.stdout, env: {} })).toBe(0);
      expect(h.stdoutBuf().equals(PT1)).toBe(true);
    });

    it('is a no-op the second time, once everything is already current', async () => {
      const h = await setUp();
      expect(await h.run(['key', 'rotate', '--confirm-recipients', '0'])).toBe(0);
      await h.run(['unlock']);
      await h.run(['reencrypt'], { env: {} });

      const stagedSha = await realGit(['rev-parse', ':' + PATH]);
      expect(await h.run(['reencrypt'], { env: {} })).toBe(0);
      expect(h.stderrText()).toContain('already current');
      expect(await realGit(['rev-parse', ':' + PATH])).toBe(stagedSha);
    });

    it('exits locked when the repository is locked', async () => {
      const h = await setUp();
      await h.run(['lock']);
      expect(await h.run(['reencrypt'], { env: {} })).toBe(1);
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

  it('cleans via SECUREGIT_SESSION_KEY alone, without ever calling unlock', async () => {
    const initHarness = harness();
    await initHarness.run(['init']);
    await initHarness.run(['unlock']); // only to produce a real session file to extract from
    const config = JSON.parse(
      await readFile(join(dir, '.securegit', 'config.json'), 'utf8'),
    ) as { repoId: string };
    const sessionKey = (await readFile(resolveSessionPath(config.repoId, {}, home))).toString('base64');

    const h = filterProcessHarness({ env: { SECUREGIT_SESSION_KEY: sessionKey } });
    const result = h.start();

    await h.push(handshakeRequest());
    h.reset();
    await h.push(capabilitiesRequest());
    h.reset();
    await h.push(commandRequest('clean', PATH, PT));
    const cleanLists = readAllLists(h.outBuf());
    expect(textOf(cleanLists[0]!)).toEqual(['status=success']);
    expect(looksLikeEnvelope(Buffer.concat(cleanLists[1]!))).toBe(true);

    await h.end();
    expect(await result).toBe(0);
  });

  it('cleans via SECUREGIT_PASSPHRASE alone, caching the unwrap across multiple blobs in one server', async () => {
    const initHarness = harness();
    await initHarness.run(['init']); // no unlock — this proves SECUREGIT_PASSPHRASE alone drives it
    const config = JSON.parse(
      await readFile(join(dir, '.securegit', 'config.json'), 'utf8'),
    ) as { repoId: string };

    const h = filterProcessHarness({ env: { SECUREGIT_PASSPHRASE: 'correct horse battery staple' } });
    const result = h.start();

    await h.push(handshakeRequest());
    h.reset();
    await h.push(capabilitiesRequest());
    h.reset();
    await h.push(commandRequest('clean', PATH, PT));
    expect(textOf(readAllLists(h.outBuf())[0]!)).toEqual(['status=success']);

    // The local keyring is gone entirely now. If the passphrase were
    // re-unwrapped per blob rather than cached for the server's lifetime,
    // this next clean would find nothing to unwrap and report locked.
    await rm(resolveKeyringPath(config.repoId, home), { force: true });

    h.reset();
    await h.push(commandRequest('clean', 'other.json', PT));
    expect(textOf(readAllLists(h.outBuf())[0]!)).toEqual(['status=success']);

    await h.end();
    expect(await result).toBe(0);
  });

  it('cleans via SECUREGIT_IDENTITY_FILE + SECUREGIT_PASSPHRASE, caching the unwrap across multiple blobs in one server', async () => {
    const initHarness = harness();
    await initHarness.run(['init']);
    await initHarness.run(['unlock']);

    const bHome = await mkdtemp(join(tmpdir(), 'securegit-cli-identity-file-'));
    const b = harness({ home: bHome });
    await b.run(['identity', 'init']);
    const identity = JSON.parse(await readFile(join(bHome, '.securegit', 'identity.json'), 'utf8'));
    const identityFilePath = join(bHome, '.securegit', 'identity.json');
    await initHarness.run(['key', 'add-recipient', identity.publicKey]);

    const h = filterProcessHarness({
      env: { SECUREGIT_IDENTITY_FILE: identityFilePath, SECUREGIT_PASSPHRASE: 'correct horse battery staple' },
    });
    const result = h.start();

    await h.push(handshakeRequest());
    h.reset();
    await h.push(capabilitiesRequest());
    h.reset();
    await h.push(commandRequest('clean', PATH, PT));
    expect(textOf(readAllLists(h.outBuf())[0]!)).toEqual(['status=success']);

    // The recipient file is gone entirely now. If the identity/recipient
    // lookup were redone per blob rather than cached for the server's
    // lifetime, this next clean would find no matching recipient and
    // report locked.
    await rm(join(dir, '.securegit', 'recipients', `${identity.fingerprint}.json`), { force: true });

    h.reset();
    await h.push(commandRequest('clean', 'other.json', PT));
    expect(textOf(readAllLists(h.outBuf())[0]!)).toEqual(['status=success']);

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
    expect(await h.run(['textconv', '--', filePath], { env: {} })).toBe(0);
    expect(h.stdoutBuf().toString('utf8')).toContain('securegit');
  });
});

describe('encrypt / decrypt / inspect', () => {
  const PT = Buffer.from('hello from the ad-hoc path\n');
  const PATH = 'config/production.json';

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
    expect(await h.run(['encrypt', '-'], { stdin: PT, env: {} })).toBe(1);
  });

  it('encrypt produces the same bytes as clean, byte for byte, given the same path and content', async () => {
    const h = harness();
    await h.run(['init', '--bind-path']); // so the path genuinely enters the derivation
    await h.run(['unlock']);

    const filePath = join(dir, 'plain.json');
    const content = Buffer.from('{"a":1}\n');
    await writeFile(filePath, content);

    expect(await h.run(['encrypt', filePath, '--out', '-'])).toBe(0);
    const viaEncrypt = h.stdoutBuf();

    expect(await h.run(['clean', '--', filePath], { stdin: content })).toBe(0);
    const viaClean = h.stdoutBuf();

    expect(viaEncrypt.equals(viaClean)).toBe(true);
  });

  it('decrypt produces the same bytes as smudge, byte for byte', async () => {
    const h = harness();
    await h.run(['init']);
    await h.run(['unlock']);
    const content = Buffer.from('{"a":1}\n');

    expect(await h.run(['clean', '--', PATH], { stdin: content })).toBe(0);
    const ciphertext = h.stdoutBuf();

    expect(await h.run(['smudge', '--', PATH], { stdin: ciphertext })).toBe(0);
    const viaSmudge = h.stdoutBuf();

    expect(await h.run(['decrypt', '-'], { stdin: ciphertext })).toBe(0);
    const viaDecrypt = h.stdoutBuf();

    expect(viaDecrypt.equals(viaSmudge)).toBe(true);
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

  it('inspect --json writes the header fields to stdout, not stderr', async () => {
    const h = harness();
    await h.run(['init']);
    await h.run(['unlock']);
    await h.run(['encrypt', '-'], { stdin: PT });
    const ciphertext = h.stdoutBuf();

    const fresh = harness();
    expect(await fresh.run(['inspect', '--json', '-'], { stdin: ciphertext })).toBe(0);
    expect(fresh.stderrText()).toBe('');
    const parsed = JSON.parse(fresh.stdoutText());
    expect(parsed.format).toBe(1);
    expect(parsed.algorithm).toBe(1);
    expect(parsed.bindPath).toBe(false);
    expect(parsed.padded).toBe(false);
    expect(typeof parsed.keyId).toBe('string');
    expect(typeof parsed.ciphertextLength).toBe('number');
  });
});

describe('no error message contains plaintext bytes', () => {
  const PATH = 'config/production.json';
  const SECRET_MARKER = 'sk-supersecretvalue-should-never-leak';
  const SECRET = Buffer.from(`{"apiKey":"${SECRET_MARKER}"}\n`);

  it("a corrupted envelope's error messages never contain the plaintext that produced it", async () => {
    const h = harness();
    await h.run(['init']);
    await h.run(['unlock']);
    expect(await h.run(['clean', '--', PATH], { stdin: SECRET })).toBe(0);
    const ciphertext = h.stdoutBuf();

    // Flip the very last byte — well past the header, into the ciphertext
    // itself — to trigger an authentication failure, not a format error.
    const corrupted = Buffer.from(ciphertext);
    corrupted[corrupted.length - 1]! ^= 0xff;

    expect(await h.run(['smudge', '--strict', '--', PATH], { stdin: corrupted })).toBe(3);
    expect(h.stderrText()).not.toContain(SECRET_MARKER);

    expect(await h.run(['decrypt', '-'], { stdin: corrupted })).toBe(3);
    expect(h.stderrText()).not.toContain(SECRET_MARKER);
  });

  it("a locked clean's error message never contains the plaintext it refused to encrypt", async () => {
    const h = harness();
    await h.run(['init']); // never unlocked
    expect(await h.run(['clean', '--', PATH], { stdin: SECRET, env: {} })).toBe(1);
    expect(h.stderrText()).not.toContain(SECRET_MARKER);
  });

  it('a missing-generation smudge warning never contains the plaintext, only path and generation', async () => {
    const a = harness();
    await a.run(['init']);
    await a.run(['unlock']);
    expect(await a.run(['clean', '--', PATH], { stdin: SECRET })).toBe(0);
    const ciphertext = a.stdoutBuf();

    // A genuinely different repository — its keyring holds a generation
    // this ciphertext was never wrapped for.
    const otherDir = await mkdtemp(join(tmpdir(), 'securegit-cli-repo-'));
    await mkdir(join(otherDir, '.git'));
    try {
      const b = harness({ cwd: otherDir });
      await b.run(['init']);
      await b.run(['unlock']);
      // No --strict: this is the warned-passthrough path, not a hard failure.
      expect(await b.run(['smudge', '--', PATH], { stdin: ciphertext })).toBe(0);
      expect(b.stderrText()).not.toContain(SECRET_MARKER);
    } finally {
      await rm(otherDir, { recursive: true, force: true });
    }
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

// `--quiet` distinguishes three tiers of otherwise-undifferentiated stderr
// output (10-cli-contract.md): success confirmations (io.info, suppressed),
// errors and human-readable reports (io.stderr, never suppressed — a report
// command's report is its actual deliverable, not a diagnostic aside).
describe('--quiet', () => {
  it('suppresses a success confirmation, without changing the exit code or the side effect', async () => {
    const h = harness();
    expect(await h.run(['init', '--quiet'])).toBe(0);
    expect(h.infoText()).toBe('');
    expect(h.stderrText()).toBe('');
    // the side effect still happened — a keyring was actually written
    expect(await h.run(['status'], { env: {} })).toBe(1); // locked, not misconfigured
  });

  it('without --quiet, the same command still prints its confirmation', async () => {
    const h = harness();
    expect(await h.run(['init'])).toBe(0);
    expect(h.infoText()).toContain('initialized repository');
  });

  it('suppresses unlock\'s confirmation too', async () => {
    const h = harness();
    await h.run(['init']);
    expect(await h.run(['unlock', '--quiet'])).toBe(0);
    expect(h.infoText()).toBe('');
  });

  it('never suppresses an error message', async () => {
    const h = harness();
    await h.run(['init']);
    expect(
      await h.run(['unlock', '--quiet'], { env: { SECUREGIT_PASSPHRASE: 'a totally different passphrase' } }),
    ).toBe(1);
    expect(h.stderrText()).toContain('wrong passphrase');
  });

  it('never suppresses `status`\'s human-readable report', async () => {
    const h = harness();
    await h.run(['init']);
    await h.run(['unlock']);
    await h.run(['status', '--quiet']);
    expect(h.stderrText()).toContain('padTo');
  });

  it('never suppresses `identity show`\'s human-readable report', async () => {
    const h = harness();
    await h.run(['identity', 'init']);
    await h.run(['identity', 'show', '--quiet']);
    expect(h.stderrText()).toContain('SGPUB1');
  });
});
