import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { execFile as execFileCb } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, rm, writeFile, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { install, protect, EXCLUSION_LINE } from './install.js';
import { initConfig, resolveKeyringPath } from './config.js';
import { createKeyring, writeKeyringFile } from './keyring.js';
import { PassphraseFileProvider } from './provider.js';
import type { KeyProvider, ProviderContext, ProviderInfo, ProviderState, WrappedKey } from './provider.js';
import { seal } from './envelope.js';
import {
  verify,
  verifyExitCode,
  NAME_HEURISTICS,
  CONTENT_HEURISTICS,
  EXIT_VERIFY_OK,
  EXIT_VERIFY_MISCONFIGURED,
  EXIT_VERIFY_LEAK,
  type VerifyReport,
} from './verify.js';

const execFile = promisify(execFileCb);
const PASSPHRASE = 'correct horse battery staple';

async function git(repoDir: string, args: string[]): Promise<string> {
  const { stdout } = await execFile('git', args, { cwd: repoDir });
  return stdout.replace(/\n$/, '');
}

/** Never custodial in v1 — a stand-in for a KMS/HSM provider, for L10. */
class FakeCustodialProvider implements KeyProvider {
  readonly id = 'fake-kms';

  describe(): ProviderInfo {
    return { id: this.id, label: 'Fake KMS', custodial: true, requiresHardware: false };
  }

  async available(): Promise<boolean> {
    return true;
  }

  async init(): Promise<ProviderState> {
    return {};
  }

  async wrap(key: Buffer, _ctx: ProviderContext): Promise<WrappedKey> {
    void _ctx;
    return { provider: this.id, payload: { key: key.toString('base64') } };
  }

  async unwrap(wrapped: WrappedKey, _ctx: ProviderContext): Promise<Buffer> {
    void _ctx;
    return Buffer.from(wrapped.payload.key!, 'base64');
  }
}

let dir: string;
let home: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'securegit-verify-'));
  home = await mkdtemp(join(tmpdir(), 'securegit-verify-home-'));
  await execFile('git', ['init', '--quiet', '-b', 'main'], { cwd: dir });
  await execFile('git', ['config', 'user.name', 'Test'], { cwd: dir });
  await execFile('git', ['config', 'user.email', 'test@example.com'], { cwd: dir });
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
  await rm(home, { recursive: true, force: true });
});

interface SetUp {
  repoId: string;
  rmk: Buffer;
  keyId: string;
  provider: PassphraseFileProvider;
}

/** init + keyring + install + protect(config/production.json), committed. */
async function setUpProtectedRepo(): Promise<SetUp> {
  const config = await initConfig(dir);
  const provider = new PassphraseFileProvider(() => PASSPHRASE);
  const { file, rmk } = await createKeyring(config.repoId, [provider]);
  await writeKeyringFile(resolveKeyringPath(config.repoId, home), file);
  await install({ repoDir: dir });
  await protect(dir, ['config/production.json']);
  await execFile('git', ['add', '-A'], { cwd: dir });
  await execFile('git', ['commit', '--quiet', '-m', 'init'], { cwd: dir });

  const gen = file.generations[0]!;
  return { repoId: config.repoId, rmk, keyId: `${gen.generation}.${gen.fingerprint}`, provider };
}

// Stages content via `hash-object`/`update-index` plumbing rather than
// `git add`, so these helpers never invoke the configured clean filter —
// module-level tests have no real `securegit` binary on PATH, and these
// helpers need to write both already-encrypted and deliberately-plaintext
// blobs regardless of what the filter would have done.
async function stageContent(relPath: string, content: Buffer): Promise<void> {
  const tmp = join(tmpdir(), `securegit-verify-blob-${randomBytes(4).toString('hex')}`);
  await writeFile(tmp, content);
  const sha = await git(dir, ['hash-object', '-w', tmp]);
  await rm(tmp, { force: true });
  await execFile('git', ['update-index', '--add', '--cacheinfo', `100644,${sha},${relPath}`], {
    cwd: dir,
  });
}

async function commitEncrypted(
  rmk: Buffer,
  keyId: string,
  relPath: string,
  plaintext: Buffer,
): Promise<void> {
  await stageContent(relPath, seal(plaintext, { rmk, keyId, path: relPath }));
  await execFile('git', ['commit', '--quiet', '-m', `add ${relPath}`], { cwd: dir });
}

async function commitPlaintext(relPath: string, content: string): Promise<void> {
  await stageContent(relPath, Buffer.from(content, 'utf8'));
  await execFile('git', ['commit', '--quiet', '-m', `add ${relPath}`], { cwd: dir });
}

describe('verify()', () => {
  it('a clean, correctly configured repository passes every check with no findings', async () => {
    const { rmk, keyId, provider } = await setUpProtectedRepo();
    await commitEncrypted(rmk, keyId, 'config/production.json', Buffer.from('{"password":"hunter2"}\n'));

    const report = await verify({ repoDir: dir, home, providers: [provider] });

    expect(report.checks.every((c) => c.ok)).toBe(true);
    expect(report.findings).toEqual([]);
    expect(verifyExitCode(report)).toBe(EXIT_VERIFY_OK);
  });

  it('runs without any unlocked session present', async () => {
    const { rmk, keyId, provider } = await setUpProtectedRepo();
    await commitEncrypted(rmk, keyId, 'config/production.json', Buffer.from('{"password":"hunter2"}\n'));

    // session.ts is never imported/touched by verify() — no session file
    // exists anywhere under `home`, and this must still succeed.
    const report = await verify({ repoDir: dir, home, providers: [provider] });
    expect(verifyExitCode(report)).toBe(EXIT_VERIFY_OK);
  });

  it('reports a missing filter configuration (L1) and exits misconfigured', async () => {
    const config = await initConfig(dir);
    const provider = new PassphraseFileProvider(() => PASSPHRASE);
    const { file } = await createKeyring(config.repoId, [provider]);
    await writeKeyringFile(resolveKeyringPath(config.repoId, home), file);
    // install() never called.
    await execFile('git', ['add', '-A'], { cwd: dir });
    await execFile('git', ['commit', '--quiet', '-m', 'init'], { cwd: dir });

    const report = await verify({ repoDir: dir, home, providers: [provider] });
    const check = report.checks.find((c) => c.id === 'filter-configured');
    expect(check?.ok).toBe(false);
    expect(verifyExitCode(report)).toBe(EXIT_VERIFY_MISCONFIGURED);
  });

  it('reports filter.securegit.required = false (L2)', async () => {
    const { provider } = await setUpProtectedRepo();
    await execFile('git', ['config', '--local', 'filter.securegit.required', 'false'], { cwd: dir });

    const report = await verify({ repoDir: dir, home, providers: [provider] });
    const check = report.checks.find((c) => c.id === 'filter-required');
    expect(check?.ok).toBe(false);
    expect(verifyExitCode(report)).toBe(EXIT_VERIFY_MISCONFIGURED);
  });

  it('reports a removed attribute line (L3)', async () => {
    const { provider } = await setUpProtectedRepo();
    await writeFile(join(dir, '.gitattributes'), `${EXCLUSION_LINE}\n`);

    const report = await verify({ repoDir: dir, home, providers: [provider] });
    const check = report.checks.find((c) => c.id === 'attributes-present');
    expect(check?.ok).toBe(false);
  });

  it('flags a file left unprotected by a directory rename, once its content looks sensitive (L4)', async () => {
    const { provider } = await setUpProtectedRepo();
    // `config/` was renamed to `conf/` after `protect` ran; the
    // `config/production.json` pattern no longer matches, so a later
    // plaintext edit here is never re-encrypted.
    await commitPlaintext('conf/production.json', '{"note":"key AKIAABCDEFGHIJKL1234"}\n');

    const report = await verify({ repoDir: dir, home, providers: [provider] });
    const finding = report.findings.find((f) => f.path === 'conf/production.json');
    expect(finding?.kind).toBe('advice');
    expect(report.findings.some((f) => f.kind === 'leak')).toBe(false);
  });

  it('flags an unprotected file matching a name heuristic as advice, not a leak', async () => {
    const { provider } = await setUpProtectedRepo();
    await commitPlaintext('.env', 'PORT=3000\n');

    const report = await verify({ repoDir: dir, home, providers: [provider] });
    const finding = report.findings.find((f) => f.path === '.env');
    expect(finding?.kind).toBe('advice');
    expect(verifyExitCode(report)).toBe(EXIT_VERIFY_OK);
  });

  it('flags an unprotected file containing an AWS access key id as advice', async () => {
    const { provider } = await setUpProtectedRepo();
    await commitPlaintext('notes.txt', 'key: AKIAABCDEFGHIJKL1234\n');

    const report = await verify({ repoDir: dir, home, providers: [provider] });
    const finding = report.findings.find((f) => f.path === 'notes.txt');
    expect(finding?.kind).toBe('advice');
  });

  it('reports diff.securegit.cachetextconv = true (L7)', async () => {
    const { provider } = await setUpProtectedRepo();
    await execFile('git', ['config', '--local', 'diff.securegit.cachetextconv', 'true'], { cwd: dir });

    const report = await verify({ repoDir: dir, home, providers: [provider] });
    const check = report.checks.find((c) => c.id === 'textconv-cache-disabled');
    expect(check?.ok).toBe(false);
  });

  it('reports a conflicting text attribute on a protected path (L8)', async () => {
    const { rmk, keyId, provider } = await setUpProtectedRepo();
    await commitEncrypted(rmk, keyId, 'config/production.json', Buffer.from('{"password":"hunter2"}\n'));
    const attrPath = join(dir, '.gitattributes');
    const existing = await readFile(attrPath, 'utf8');
    await writeFile(attrPath, `${existing}config/production.json text\n`);
    await execFile('git', ['add', '.gitattributes'], { cwd: dir });
    await execFile('git', ['commit', '--quiet', '-m', 'inherit text'], { cwd: dir });

    const report = await verify({ repoDir: dir, home, providers: [provider] });
    const check = report.checks.find((c) => c.id === 'no-conflicting-attributes');
    expect(check?.ok).toBe(false);
    expect(check?.detail).toContain('config/production.json');
  });

  it('reports the keyring living inside the worktree (L9)', async () => {
    const { provider } = await setUpProtectedRepo();

    const report = await verify({ repoDir: dir, home: dir, providers: [provider] });
    const check = report.checks.find((c) => c.id === 'key-material-outside-worktree');
    expect(check?.ok).toBe(false);
  });

  it('reports a custodial-only provider set (L10)', async () => {
    const config = await initConfig(dir);
    const custodial = new FakeCustodialProvider();
    const { file } = await createKeyring(config.repoId, [custodial]);
    await writeKeyringFile(resolveKeyringPath(config.repoId, home), file);
    await install({ repoDir: dir });
    await protect(dir, ['config/production.json']);
    await execFile('git', ['add', '-A'], { cwd: dir });
    await execFile('git', ['commit', '--quiet', '-m', 'init'], { cwd: dir });

    const report = await verify({ repoDir: dir, home, providers: [custodial] });
    const check = report.checks.find((c) => c.id === 'non-custodial-unwrap-path');
    expect(check?.ok).toBe(false);
  });

  it('a leak: attribute protects the path but the filter was never installed', async () => {
    const config = await initConfig(dir);
    const provider = new PassphraseFileProvider(() => PASSPHRASE);
    const { file } = await createKeyring(config.repoId, [provider]);
    await writeKeyringFile(resolveKeyringPath(config.repoId, home), file);
    await protect(dir, ['config/production.json']); // attribute only, no install()
    await commitPlaintext('config/production.json', '{"password":"hunter2"}\n');

    const report = await verify({ repoDir: dir, home, providers: [provider] });
    const leak = report.findings.find((f) => f.kind === 'leak' && f.path === 'config/production.json');
    expect(leak).toBeDefined();
    expect(verifyExitCode(report)).toBe(EXIT_VERIFY_LEAK);
  });

  it('exits leaked even when a config check also fails', async () => {
    const config = await initConfig(dir);
    const provider = new PassphraseFileProvider(() => PASSPHRASE);
    const { file } = await createKeyring(config.repoId, [provider]);
    await writeKeyringFile(resolveKeyringPath(config.repoId, home), file);
    await protect(dir, ['config/production.json']);
    await commitPlaintext('config/production.json', '{"password":"hunter2"}\n');
    // filter was never installed either — both a leak and a misconfiguration.

    const report = await verify({ repoDir: dir, home, providers: [provider] });
    expect(report.findings.some((f) => f.kind === 'leak')).toBe(true);
    expect(report.checks.some((c) => !c.ok)).toBe(true);
    expect(verifyExitCode(report)).toBe(EXIT_VERIFY_LEAK);
  });

  it('exposes the heuristic lists used for advice findings', () => {
    expect(NAME_HEURISTICS.length).toBeGreaterThan(0);
    expect(CONTENT_HEURISTICS.length).toBeGreaterThan(0);
    expect(CONTENT_HEURISTICS.some((re) => re.test('AKIAABCDEFGHIJKL1234'))).toBe(true);
    expect(CONTENT_HEURISTICS.some((re) => re.test('-----BEGIN RSA PRIVATE KEY-----'))).toBe(true);
    expect(CONTENT_HEURISTICS.some((re) => re.test('xoxb-not-a-real-token'))).toBe(true);
  });
});

describe('verifyExitCode()', () => {
  it('is 5 when any leak is present, regardless of other findings', () => {
    const report: VerifyReport = {
      checks: [{ id: 'filter-required', label: 'x', ok: false }],
      findings: [{ kind: 'leak', path: 'a', detail: 'x' }],
    };
    expect(verifyExitCode(report)).toBe(EXIT_VERIFY_LEAK);
  });

  it('is 2 when a check fails and there is no leak', () => {
    const report: VerifyReport = {
      checks: [{ id: 'filter-required', label: 'x', ok: false }],
      findings: [],
    };
    expect(verifyExitCode(report)).toBe(EXIT_VERIFY_MISCONFIGURED);
  });

  it('is 0 when only advice findings are present and every check passes', () => {
    const report: VerifyReport = {
      checks: [{ id: 'filter-required', label: 'x', ok: true }],
      findings: [{ kind: 'advice', path: 'a', detail: 'x' }],
    };
    expect(verifyExitCode(report)).toBe(EXIT_VERIFY_OK);
  });

  it('is 0 for an entirely empty report', () => {
    expect(verifyExitCode({ checks: [], findings: [] })).toBe(EXIT_VERIFY_OK);
  });
});
