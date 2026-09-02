import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { execFile as execFileCb } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, rm, mkdir, writeFile, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { install, protect, EXCLUSION_LINE } from './install.js';
import { initConfig, resolveKeyringPath } from './config.js';
import { createKeyring, readKeyringFile, writeKeyringFile, rotateKeyring } from './keyring.js';
import { PassphraseFileProvider } from './provider.js';
import type { KeyProvider, ProviderContext, ProviderInfo, ProviderState, WrappedKey } from './provider.js';
import { seal } from './envelope.js';
import {
  verify,
  verifyExitCode,
  accessReport,
  historyReport,
  NAME_HEURISTICS,
  CONTENT_HEURISTICS,
  EXIT_VERIFY_OK,
  EXIT_VERIFY_MISCONFIGURED,
  EXIT_VERIFY_LEAK,
  type VerifyReport,
} from './verify.js';
import { generateX25519KeyPair, identityFingerprint } from './identity.js';
import {
  wrapAllGenerations,
  writeRecipientFile,
  recipientPath,
  appendRemovedRecipientLogEntry,
  removedRecipientsLogPath,
  type RecipientFile,
} from './recipients.js';
import { appendRecoveryLogEntry, recoveryLogPath } from './recovery.js';
import type { KeySource } from './filter.js';

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

  it('reports an untracked .orig file beside a protected path (T12)', async () => {
    const { rmk, keyId, provider } = await setUpProtectedRepo();
    await commitEncrypted(rmk, keyId, 'config/production.json', Buffer.from('{"password":"hunter2"}\n'));
    // A conflicted merge would leave this: the plaintext pre-merge content,
    // untracked, sitting right next to the protected path. `commitEncrypted`
    // stages via plumbing and never touches the worktree, so `config/` has
    // to be created here.
    await mkdir(join(dir, 'config'), { recursive: true });
    await writeFile(join(dir, 'config', 'production.json.orig'), '{"password":"hunter2"}\n');

    const report = await verify({ repoDir: dir, home, providers: [provider] });
    const residue = report.findings.find(
      (f) => f.kind === 'residue' && f.path === 'config/production.json.orig',
    );
    expect(residue).toBeDefined();
    expect(verifyExitCode(report)).toBe(EXIT_VERIFY_MISCONFIGURED);
  });

  it('reports an untracked vim swap file beside a protected path (T12)', async () => {
    const { rmk, keyId, provider } = await setUpProtectedRepo();
    await commitEncrypted(rmk, keyId, 'config/production.json', Buffer.from('{"password":"hunter2"}\n'));
    await mkdir(join(dir, 'config'), { recursive: true });
    await writeFile(join(dir, 'config', '.production.json.swp'), 'vim swap contents');

    const report = await verify({ repoDir: dir, home, providers: [provider] });
    const residue = report.findings.find(
      (f) => f.kind === 'residue' && f.path === 'config/.production.json.swp',
    );
    expect(residue).toBeDefined();
  });

  it('does not report a residue-shaped file that does not exist', async () => {
    const { rmk, keyId, provider } = await setUpProtectedRepo();
    await commitEncrypted(rmk, keyId, 'config/production.json', Buffer.from('{"password":"hunter2"}\n'));

    const report = await verify({ repoDir: dir, home, providers: [provider] });
    expect(report.findings.some((f) => f.kind === 'residue')).toBe(false);
    expect(verifyExitCode(report)).toBe(EXIT_VERIFY_OK);
  });

  it('does not report a residue-shaped file that is itself tracked', async () => {
    const { rmk, keyId, provider } = await setUpProtectedRepo();
    await commitEncrypted(rmk, keyId, 'config/production.json', Buffer.from('{"password":"hunter2"}\n'));
    await commitPlaintext('config/production.json.bak', 'deliberately tracked, not residue');

    const report = await verify({ repoDir: dir, home, providers: [provider] });
    expect(report.findings.some((f) => f.kind === 'residue')).toBe(false);
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

  it('is 2 when a residue finding is present and there is no leak', () => {
    const report: VerifyReport = {
      checks: [{ id: 'filter-required', label: 'x', ok: true }],
      findings: [{ kind: 'residue', path: 'a.orig', detail: 'x' }],
    };
    expect(verifyExitCode(report)).toBe(EXIT_VERIFY_MISCONFIGURED);
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

function singleKeySource(keyId: string, rmk: Buffer): KeySource {
  return {
    current: () => ({ keyId, rmk }),
    find: (id) => (id === keyId ? rmk : null),
    available: () => [keyId],
  };
}

describe('accessReport()', () => {
  it('reports one provider covering the current generation, and nothing else, for a plain solo repo', async () => {
    await setUpProtectedRepo();
    const report = await accessReport({ repoDir: dir, home });
    expect(report.recipients).toEqual([]);
    expect(report.providers).toEqual([{ id: 'passphrase-file', generations: [1] }]);
    expect(report.recoveryExports).toEqual([]);
    expect(report.removedRecipients).toEqual([]);
  });

  it('lists a recipient with the generations their file actually covers', async () => {
    const { repoId, rmk, keyId } = await setUpProtectedRepo();
    const recipientKeyPair = generateX25519KeyPair();
    const fingerprint = identityFingerprint(recipientKeyPair.publicKey);
    const wrapped = wrapAllGenerations(singleKeySource(keyId, rmk), [keyId], recipientKeyPair.publicKey, repoId);
    const file: RecipientFile = {
      version: 1,
      fingerprint,
      publicKey: 'SGPUB1-does-not-need-to-decode-for-this-test',
      label: 'laptop',
      addedAt: '2026-01-14T00:00:00.000Z',
      addedBy: 'b30f92ac',
      keys: wrapped,
    };
    await writeRecipientFile(recipientPath(dir, fingerprint), file);

    const report = await accessReport({ repoDir: dir, home });
    expect(report.recipients).toEqual([
      { fingerprint, label: 'laptop', addedAt: '2026-01-14T00:00:00.000Z', addedBy: 'b30f92ac', generations: [1] },
    ]);
  });

  it('providers section reflects coverage across a rotation, not just the current generation', async () => {
    const { repoId, provider } = await setUpProtectedRepo();
    const keyringPath = resolveKeyringPath(repoId, home);
    const before = await readKeyringFile(keyringPath);
    const { file: rotated } = await rotateKeyring(before, [provider]);
    await writeKeyringFile(keyringPath, rotated);

    const report = await accessReport({ repoDir: dir, home });
    expect(report.providers).toEqual([{ id: 'passphrase-file', generations: [1, 2] }]);
  });

  it('providers section is empty, not an error, when no local keyring exists', async () => {
    // A machine that joined purely via a recipient file (08-multi-recipient.md)
    // has no keyring.json at all — accessReport must not throw for it.
    await initConfig(dir);
    await install({ repoDir: dir });
    await protect(dir, ['config/production.json']);
    await execFile('git', ['add', '-A'], { cwd: dir });
    await execFile('git', ['commit', '--quiet', '-m', 'init'], { cwd: dir });

    const report = await accessReport({ repoDir: dir, home });
    expect(report.providers).toEqual([]);
  });

  it('lists recovery exports from the committed recovery log', async () => {
    await setUpProtectedRepo();
    await appendRecoveryLogEntry(recoveryLogPath(dir), {
      exportId: 'ab12cd34',
      timestamp: '2026-01-20T00:00:00.000Z',
      exportedBy: 'b30f92ac',
      generations: [1],
    });

    const report = await accessReport({ repoDir: dir, home });
    expect(report.recoveryExports).toEqual([
      { exportId: 'ab12cd34', timestamp: '2026-01-20T00:00:00.000Z', exportedBy: 'b30f92ac', generations: [1] },
    ]);
  });

  it('lists removed recipients with the generations they can still read', async () => {
    await setUpProtectedRepo();
    await appendRemovedRecipientLogEntry(removedRecipientsLogPath(dir), {
      fingerprint: '9d1c04ff72ab3e58',
      label: 'contractor',
      removedAt: '2026-06-01T00:00:00.000Z',
      removedBy: 'b30f92ac',
      generations: [1, 2],
    });

    const report = await accessReport({ repoDir: dir, home });
    expect(report.removedRecipients).toEqual([
      {
        fingerprint: '9d1c04ff72ab3e58',
        label: 'contractor',
        removedAt: '2026-06-01T00:00:00.000Z',
        removedBy: 'b30f92ac',
        generations: [1, 2],
      },
    ]);
  });
});

describe('historyReport()', () => {
  it('finds plaintext committed on a branch unreachable from HEAD (main)', async () => {
    await protect(dir, ['config/production.json']);
    await execFile('git', ['add', '-A'], { cwd: dir });
    await execFile('git', ['commit', '--quiet', '-m', 'protect'], { cwd: dir });

    await execFile('git', ['checkout', '-b', 'feature'], { cwd: dir });
    await commitPlaintext('config/production.json', '{"password":"leaked-on-branch"}\n');
    await execFile('git', ['checkout', 'main'], { cwd: dir });
    await commitPlaintext('README.md', '# ok\n'); // unrelated commit on main; feature never merged

    const report = await historyReport({ repoDir: dir });
    const finding = report.findings.find((f) => f.path === 'config/production.json');
    expect(finding).toBeDefined();
    expect(finding!.reachableFrom).toContain('feature');
    expect(finding!.reachableFrom).not.toContain('main');
  });

  it('does not flag a file that predates protection, and does flag one leaked after it — proving per-commit attribute resolution', async () => {
    // Committed before `.gitattributes` exists at all: not protected then,
    // so reporting it as a leak would be wrong in that direction.
    await commitPlaintext('config/production.json', '{"password":"predates-securegit"}\n');

    await protect(dir, ['config/production.json']);
    await execFile('git', ['add', '-A'], { cwd: dir });
    await execFile('git', ['commit', '--quiet', '-m', 'protect'], { cwd: dir });

    // Committed after protection exists: this one must be flagged. If the
    // engine always answered the same way regardless of commit, one of
    // these two assertions would fail.
    await commitPlaintext('config/production.json', '{"password":"leaked-after-protection"}\n');

    const report = await historyReport({ repoDir: dir });
    const finding = report.findings.find((f) => f.path === 'config/production.json');
    expect(finding).toBeDefined();
    expect(finding!.commitCount).toBe(1); // only the post-protection commit
  });

  it('finds a textconv notes ref and counts its entries', async () => {
    await protect(dir, ['config/production.json']);
    await execFile('git', ['add', '-A'], { cwd: dir });
    await execFile('git', ['commit', '--quiet', '-m', 'protect'], { cwd: dir });
    const head = (await execFile('git', ['rev-parse', 'HEAD'], { cwd: dir })).stdout.trim();

    await execFile(
      'git',
      ['notes', '--ref', 'textconv/securegit', 'add', '-m', 'cached plaintext from textconv', head],
      { cwd: dir },
    );

    const report = await historyReport({ repoDir: dir });
    expect(report.textconvNotesRef).toEqual({ present: true, count: 1 });
  });

  it('reports no textconv notes ref when none exists', async () => {
    await protect(dir, ['config/production.json']);
    await execFile('git', ['add', '-A'], { cwd: dir });
    await execFile('git', ['commit', '--quiet', '-m', 'protect'], { cwd: dir });

    const report = await historyReport({ repoDir: dir });
    expect(report.textconvNotesRef).toEqual({ present: false, count: 0 });
  });

  it('examines each blob OID once, even when it appears unchanged across many commits', async () => {
    await protect(dir, ['config/production.json']);
    await execFile('git', ['add', '-A'], { cwd: dir });
    await execFile('git', ['commit', '--quiet', '-m', 'protect'], { cwd: dir });
    await commitPlaintext('config/production.json', '{"password":"same-every-time"}\n');
    // Two more commits that never touch the protected path — its blob SHA
    // is identical in all three commits' trees.
    await commitPlaintext('other-a.txt', 'a\n');
    await commitPlaintext('other-b.txt', 'b\n');

    const examined: string[] = [];
    const report = await historyReport({ repoDir: dir, onBlobExamined: (sha) => examined.push(sha) });

    const finding = report.findings.find((f) => f.path === 'config/production.json');
    expect(finding?.commitCount).toBe(3); // present, unchanged, in all three commits
    expect(examined).toHaveLength(1); // but its content was only ever read once
  });

  it('reports commitsWalked as the total number of reachable commits', async () => {
    await protect(dir, ['config/production.json']);
    await execFile('git', ['add', '-A'], { cwd: dir });
    await execFile('git', ['commit', '--quiet', '-m', 'protect'], { cwd: dir });
    await commitPlaintext('a.txt', 'a\n');
    await commitPlaintext('b.txt', 'b\n');

    const report = await historyReport({ repoDir: dir });
    expect(report.commitsWalked).toBe(3);
  });
});
