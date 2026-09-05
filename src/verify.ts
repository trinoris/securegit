// Config, attribute and content checks that catch the ways this design fails
// silently — a missing filter, a removed attribute, a plaintext blob that
// slipped past a pattern that stopped matching. See specs/securegit/13-verify.md.
//
// This module never touches a session or unwraps a key: every check works
// from public information (git config, .gitattributes, blob magic bytes), so
// `verify` runs identically whether the repository is locked or not.
//
// `historyReport()` (the `--history` walk) resolves attributes as of a given
// past commit using a temporary index (`GIT_INDEX_FILE` + `read-tree <sha>`,
// then `check-attr --cached`), not `check-attr --source <tree-ish>` — that
// flag needs Git 2.40, newer than this project can assume a real clone has.

import { execFile as execFileCb, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { readFile, readdir, stat, unlink } from 'node:fs/promises';
import { join, relative, isAbsolute, posix } from 'node:path';
import { tmpdir } from 'node:os';
import { randomBytes } from 'node:crypto';
import { readConfig, resolveKeyringPath } from './config.js';
import { readKeyringFile } from './keyring.js';
import { resolveSessionPath } from './session.js';
import { signingKeyFingerprint } from './identity.js';
import { equalCt } from './crypto.js';
import type { KeyProvider } from './provider.js';
import { looksLikeEnvelope } from './envelope.js';
import { EXCLUSION_LINE, RESIDUE_SUFFIXES } from './install.js';
import {
  recipientsDir,
  recipientPath,
  readRecipientFile,
  removedRecipientsLogPath,
  readRemovedRecipientsLog,
  type RemovedRecipientLogEntry,
} from './recipients.js';
import { recoveryLogPath, readRecoveryLog, type RecoveryLogEntry } from './recovery.js';

const execFile = promisify(execFileCb);

export const EXIT_VERIFY_OK = 0;
export const EXIT_VERIFY_MISCONFIGURED = 2;
export const EXIT_VERIFY_LEAK = 5;

export type CheckId =
  | 'repo-initialised'
  | 'keyring-present'
  | 'filter-configured'
  | 'filter-required'
  | 'diff-driver-configured'
  | 'textconv-cache-disabled'
  | 'attributes-present'
  | 'metadata-exclusion'
  | 'no-conflicting-attributes'
  | 'key-material-outside-worktree'
  | 'non-custodial-unwrap-path'
  | 'commit-signed-by-recipient';

export interface CheckResult {
  id: CheckId;
  label: string;
  ok: boolean;
  detail?: string;
}

export type FindingKind = 'leak' | 'advice' | 'residue' | 'recovery';

export interface Finding {
  kind: FindingKind;
  path: string;
  detail: string;
}

export interface VerifyReport {
  checks: CheckResult[];
  findings: Finding[];
}

export interface VerifyOptions {
  repoDir: string;
  home: string;
  env?: { XDG_RUNTIME_DIR?: string | undefined };
  /** Used only to look up each wrapped provider's `custodial` flag (L10) — no key is unwrapped. */
  providers?: KeyProvider[];
}

/**
 * Leak beats misconfiguration beats advice: a live plaintext exposure is
 * always the loudest thing to report. A residue finding (T12) is plaintext
 * sitting on disk rather than committed — real, but not the same severity as
 * a committed leak — so it joins failed checks at the misconfigured tier.
 */
export function verifyExitCode(report: VerifyReport): number {
  if (report.findings.some((f) => f.kind === 'leak')) return EXIT_VERIFY_LEAK;
  if (report.checks.some((c) => !c.ok) || report.findings.some((f) => f.kind === 'residue')) {
    return EXIT_VERIFY_MISCONFIGURED;
  }
  return EXIT_VERIFY_OK;
}

// ---------------------------------------------------------------------------
// heuristics
// ---------------------------------------------------------------------------

/** Filename patterns that suggest a file is sensitive, whether protected or not. */
export const NAME_HEURISTICS: RegExp[] = [
  /\.env(\..+)?$/i,
  /secret/i,
  /credential/i,
  /(^|\/)id_rsa$/,
  /\.pem$/i,
  /\.p12$/i,
];

/** High-confidence content patterns — deliberately narrow, to keep false positives rare. */
export const CONTENT_HEURISTICS: RegExp[] = [
  /AKIA[0-9A-Z]{16}/,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  /xox[baprs]-/,
];

/** Content heuristics only run on files at most this large. */
const CONTENT_SCAN_MAX_BYTES = 1024 * 1024;

function nameLooksSensitive(path: string): boolean {
  return NAME_HEURISTICS.some((re) => re.test(path));
}

function contentLooksSensitive(content: Buffer): boolean {
  if (content.length > CONTENT_SCAN_MAX_BYTES) return false;
  const text = content.toString('utf8');
  return CONTENT_HEURISTICS.some((re) => re.test(text));
}

// ---------------------------------------------------------------------------
// git plumbing
// ---------------------------------------------------------------------------

async function gitConfigGet(repoDir: string, key: string): Promise<string | null> {
  try {
    const { stdout } = await execFile('git', ['config', '--local', '--get', key], { cwd: repoDir });
    return stdout.replace(/\n$/, '');
  } catch (e) {
    const err = e as { code?: number };
    if (err.code === 1) return null; // unset
    throw e;
  }
}

/**
 * The SSH-format fingerprint of whoever signed `HEAD`, or `null` if it
 * isn't signed at all — `%GF` resolves this straight from the commit's
 * own embedded signature blob, independent of whether the signer is
 * "trusted" by anything (confirmed directly: a commit signed by a key
 * absent from `gpg.ssh.allowedSignersFile` still reports its real
 * fingerprint via `%GF`, just a `%G?` of `U` instead of `G` — this
 * function only ever needs the fingerprint, so it never bothers with
 * `%G?` at all, and comparing the fingerprint against this repository's
 * own recipient list *is* the trust decision, not `gpg.ssh.allowedSignersFile`).
 * `/dev/null` as that file is deliberate, not a placeholder to fill in
 * later — git refuses to attempt SSH signature parsing at all without
 * one configured (confirmed directly too), but never actually reads it
 * for what this function asks of it.
 */
async function headSignerFingerprint(repoDir: string): Promise<string | null> {
  try {
    const { stdout } = await execFile(
      'git',
      ['-c', 'gpg.ssh.allowedSignersFile=/dev/null', 'log', '-1', '--format=%GF', 'HEAD'],
      { cwd: repoDir },
    );
    const fingerprint = stdout.trim();
    return fingerprint.length > 0 ? fingerprint : null;
  } catch {
    return null; // no commits yet, or not a git repository — nothing to check
  }
}

/** Exported for `cli.ts`'s `reencrypt`, which needs the same "which tracked paths are protected" scan. */
export async function listTrackedPaths(repoDir: string): Promise<string[]> {
  const { stdout } = await execFile('git', ['ls-files', '-z'], {
    cwd: repoDir,
    maxBuffer: 64 * 1024 * 1024,
  });
  return stdout.split('\0').filter((p) => p.length > 0);
}

/** `path: attribute: value` per requested attribute, parsed into a map. Exported for `cli.ts`'s `reencrypt`. */
export async function checkAttr(repoDir: string, path: string): Promise<Record<string, string>> {
  const { stdout } = await execFile(
    'git',
    ['check-attr', 'filter', 'diff', 'text', 'ident', 'working-tree-encoding', '--', path],
    { cwd: repoDir },
  );
  const out: Record<string, string> = {};
  for (const line of stdout.split('\n')) {
    if (!line) continue;
    const firstSep = line.lastIndexOf(': ');
    if (firstSep === -1) continue;
    const value = line.slice(firstSep + 2);
    const rest = line.slice(0, firstSep);
    const secondSep = rest.lastIndexOf(': ');
    if (secondSep === -1) continue;
    const attr = rest.slice(secondSep + 2);
    out[attr] = value;
  }
  return out;
}

/** The index's copy of a tracked path — what would be committed right now. Exported for `cli.ts`'s `reencrypt`. */
export async function readIndexBlob(repoDir: string, path: string): Promise<Buffer> {
  const { stdout } = await execFile('git', ['cat-file', '-p', `:${path}`], {
    cwd: repoDir,
    encoding: 'buffer',
    maxBuffer: 512 * 1024 * 1024,
  });
  return stdout;
}

async function readAttributeLines(repoDir: string): Promise<string[]> {
  try {
    const content = await readFile(join(repoDir, '.gitattributes'), 'utf8');
    return content.split('\n').filter((_, i, arr) => !(i === arr.length - 1 && arr[i] === ''));
  } catch (e) {
    if ((e as { code?: string }).code === 'ENOENT') return [];
    throw e;
  }
}

function isInside(dir: string, path: string): boolean {
  const rel = relative(dir, path);
  return rel !== '' && rel !== '..' && !rel.startsWith(`..${'/'}`) && !isAbsolute(rel);
}

async function pathExists(p: string): Promise<boolean> {
  try {
    await stat(p);
    return true;
  } catch {
    return false;
  }
}

/**
 * Residue file shapes (T12) beside a protected path — an editor backup, a
 * conflicted merge's `.orig`, a vim swap file — that exist in the worktree
 * and are not themselves tracked by Git. `.gitignore` (written by `protect`)
 * keeps these out of `git add -A`, but a residue file can predate `protect`,
 * or `protect` can have been run with `residuePatterns: false` — this checks
 * the filesystem directly rather than trusting the ignore rules exist.
 */
async function findResidue(
  repoDir: string,
  protectedPath: string,
  trackedPaths: Set<string>,
): Promise<string[]> {
  const found: string[] = [];

  for (const suffix of RESIDUE_SUFFIXES) {
    const candidate = `${protectedPath}${suffix}`;
    if (trackedPaths.has(candidate)) continue;
    if (await pathExists(join(repoDir, candidate))) found.push(candidate);
  }

  // Vim's actual swap filename varies (.swp, then .swo, .swn, ...) — the
  // `.gitignore` line is the glob `.<base>.sw?`; checking the real directory
  // for anything sharing that prefix is the filesystem-level equivalent.
  const dir = posix.dirname(protectedPath);
  const base = posix.basename(protectedPath);
  const swapPrefix = `.${base}.sw`;
  let entries: string[];
  try {
    entries = await readdir(join(repoDir, dir));
  } catch {
    entries = [];
  }
  for (const entry of entries) {
    if (!entry.startsWith(swapPrefix)) continue;
    const candidate = dir === '.' ? entry : `${dir}/${entry}`;
    if (!trackedPaths.has(candidate)) found.push(candidate);
  }

  return found;
}

export interface RecoveryPathStatus {
  /** Independent paths that can unlock the current generation: the local keyring (if present) plus recipients covering it. */
  paths: number;
  hasExport: boolean;
  /** `paths < 2 && !hasExport` — losing the one path left loses the repository. */
  warn: boolean;
}

/**
 * Whether losing this machine loses the repository. Reads only the local
 * keyring file, `.securegit/recipients/`, and the recovery log — cheap
 * enough for `securegit status` to call directly, not gated behind a full
 * `verify()` scan. Returns `null` when there is no local keyring to
 * determine "the current generation" from at all — a machine that joined
 * purely via a recipient file has no authoritative answer to "what's
 * current" of its own (08-multi-recipient.md), so this check simply
 * doesn't run there rather than guessing.
 */
export async function recoveryPathStatus(opts: {
  repoDir: string;
  home: string;
}): Promise<RecoveryPathStatus | null> {
  let repoId: string;
  try {
    repoId = (await readConfig(opts.repoDir)).repoId;
  } catch {
    return null;
  }

  let current: number;
  let localHolder: boolean;
  try {
    const keyring = await readKeyringFile(resolveKeyringPath(repoId, opts.home));
    current = keyring.current;
    const currentGen = keyring.generations.find((g) => g.generation === current);
    localHolder = currentGen !== undefined && currentGen.wrapped.length > 0;
  } catch {
    return null;
  }

  let recipientCount = 0;
  try {
    const entries = (await readdir(recipientsDir(opts.repoDir))).filter((f) => f.endsWith('.json'));
    for (const entry of entries) {
      const recipient = await readRecipientFile(recipientPath(opts.repoDir, entry.replace(/\.json$/, '')));
      if (recipient.keys[String(current)]) recipientCount += 1;
    }
  } catch {
    // no recipients directory
  }

  const recoveryExports = await readRecoveryLog(recoveryLogPath(opts.repoDir));
  const paths = (localHolder ? 1 : 0) + recipientCount;
  const hasExport = recoveryExports.length > 0;
  return { paths, hasExport, warn: paths < 2 && !hasExport };
}

// ---------------------------------------------------------------------------

export async function verify(opts: VerifyOptions): Promise<VerifyReport> {
  const checks: CheckResult[] = [];
  const findings: Finding[] = [];

  let repoId: string | null = null;
  try {
    const config = await readConfig(opts.repoDir);
    repoId = config.repoId;
    checks.push({ id: 'repo-initialised', label: 'repository initialised', ok: true });
  } catch (e) {
    checks.push({
      id: 'repo-initialised',
      label: 'repository initialised',
      ok: false,
      detail: (e as Error).message,
    });
  }

  if (repoId !== null) {
    const keyringPath = resolveKeyringPath(repoId, opts.home);
    let providerIds: string[] = [];
    try {
      const keyring = await readKeyringFile(keyringPath);
      checks.push({ id: 'keyring-present', label: 'keyring present', ok: true });
      const current = keyring.generations.find((g) => g.generation === keyring.current);
      providerIds = current ? current.wrapped.map((w) => w.provider) : [];
    } catch {
      checks.push({
        id: 'keyring-present',
        label: 'keyring present',
        ok: false,
        detail: `no keyring found at ${keyringPath}`,
      });
    }

    if (providerIds.length > 0) {
      const describeById = new Map((opts.providers ?? []).map((p) => [p.id, p.describe()]));
      const known = providerIds.filter((id) => describeById.has(id));
      const nonCustodial = known.filter((id) => describeById.get(id)!.custodial === false);
      checks.push({
        id: 'non-custodial-unwrap-path',
        label: 'non-custodial unwrap path',
        ok: nonCustodial.length > 0,
        ...(nonCustodial.length === 0
          ? {
              detail:
                'every provider that can unwrap the current generation could be compelled to produce the key',
            }
          : {}),
      });
    }

    const keyringInWorktree = isInside(opts.repoDir, keyringPath);
    const sessionPath = resolveSessionPath(repoId, opts.env ?? {}, opts.home);
    const sessionInWorktree = isInside(opts.repoDir, sessionPath);
    checks.push({
      id: 'key-material-outside-worktree',
      label: 'key material outside worktree',
      ok: !keyringInWorktree && !sessionInWorktree,
      ...(keyringInWorktree
        ? { detail: `keyring path ${keyringPath} is inside the repository` }
        : sessionInWorktree
          ? { detail: `session path ${sessionPath} is inside the repository` }
          : {}),
    });

    const recovery = await recoveryPathStatus({ repoDir: opts.repoDir, home: opts.home });
    if (recovery?.warn) {
      findings.push({
        kind: 'recovery',
        path: '(repository)',
        detail:
          `only ${recovery.paths} recovery path${recovery.paths === 1 ? '' : 's'} to the current ` +
          `generation, and no recovery export on record — losing it means losing the repository`,
      });
    }
  }

  const cleanCfg = await gitConfigGet(opts.repoDir, 'filter.securegit.clean');
  const processCfg = await gitConfigGet(opts.repoDir, 'filter.securegit.process');
  checks.push({
    id: 'filter-configured',
    label: 'filter configured',
    ok: cleanCfg !== null || processCfg !== null,
  });

  const requiredCfg = await gitConfigGet(opts.repoDir, 'filter.securegit.required');
  checks.push({
    id: 'filter-required',
    label: 'filter required',
    ok: requiredCfg === 'true',
    ...(requiredCfg !== 'true' ? { detail: `filter.securegit.required = ${requiredCfg ?? 'unset'}` } : {}),
  });

  const textconvCfg = await gitConfigGet(opts.repoDir, 'diff.securegit.textconv');
  checks.push({ id: 'diff-driver-configured', label: 'diff driver configured', ok: textconvCfg !== null });

  const cacheCfg = await gitConfigGet(opts.repoDir, 'diff.securegit.cachetextconv');
  checks.push({
    id: 'textconv-cache-disabled',
    label: 'textconv cache disabled',
    ok: cacheCfg !== 'true',
    ...(cacheCfg === 'true' ? { detail: 'diff.securegit.cachetextconv = true' } : {}),
  });

  const attrLines = await readAttributeLines(opts.repoDir);
  const patternCount = attrLines.filter((l) => l.includes('filter=securegit')).length;
  checks.push({ id: 'attributes-present', label: 'attributes present', ok: patternCount > 0 });

  const lastLine = attrLines[attrLines.length - 1];
  checks.push({
    id: 'metadata-exclusion',
    label: 'metadata exclusion',
    ok: lastLine === EXCLUSION_LINE,
  });

  const trackedPaths = await listTrackedPaths(opts.repoDir);
  const trackedSet = new Set(trackedPaths);
  const conflicting: string[] = [];
  for (const path of trackedPaths) {
    const attrs = await checkAttr(opts.repoDir, path);
    const isProtected = attrs.filter === 'securegit';

    if (isProtected) {
      for (const attr of ['text', 'ident', 'working-tree-encoding']) {
        const value = attrs[attr];
        if (value !== undefined && value !== 'unset' && value !== 'unspecified') {
          conflicting.push(path);
          break;
        }
      }
    }

    const content = await readIndexBlob(opts.repoDir, path);
    if (isProtected) {
      if (!looksLikeEnvelope(content)) {
        findings.push({
          kind: 'leak',
          path,
          detail: `${path} is protected by an attribute, but its committed content is not a securegit envelope`,
        });
      }
      for (const residuePath of await findResidue(opts.repoDir, path, trackedSet)) {
        findings.push({
          kind: 'residue',
          path: residuePath,
          detail: `${residuePath} is untracked plaintext residue beside the protected path ${path}`,
        });
      }
    } else if (nameLooksSensitive(path) || contentLooksSensitive(content)) {
      findings.push({
        kind: 'advice',
        path,
        detail: `${path} is not protected, and its name or content resembles a secret`,
      });
    }
  }

  checks.push({
    id: 'no-conflicting-attributes',
    label: 'no conflicting attributes',
    ok: conflicting.length === 0,
    ...(conflicting.length > 0 ? { detail: conflicting.join(', ') } : {}),
  });

  checks.push(await commitSignedByRecipientCheck(opts.repoDir));

  return { checks, findings };
}

/**
 * specs/securegit/13-verify.md, "Authenticity" — closes the gap
 * documented in FAQ.md: every attribution claim elsewhere in this
 * project (`addedBy`, git's own author field) is a self-reported string,
 * not a proof. This is the one check that actually verifies who
 * committed something, against this repository's own recipient list —
 * see specs/securegit/08-multi-recipient.md's "Commit signing" for the
 * full design and its honest limits (this checks `HEAD` only, never
 * history predating adoption; see [13](13-verify.md)'s own "Authenticity"
 * section for why a broader per-commit-range version is a merge
 * reviewer's job, not this one's).
 */
async function commitSignedByRecipientCheck(repoDir: string): Promise<CheckResult> {
  const id = 'commit-signed-by-recipient';
  const label = 'HEAD signed by a known recipient';

  const registered: { fingerprint: string; signingFingerprint: string }[] = [];
  let recipientCount = 0;
  try {
    const entries = (await readdir(recipientsDir(repoDir))).filter((f) => f.endsWith('.json'));
    recipientCount = entries.length;
    for (const entry of entries) {
      const recipient = await readRecipientFile(recipientPath(repoDir, entry.replace(/\.json$/, '')));
      if (!recipient.signingKey) continue;
      try {
        registered.push({
          fingerprint: recipient.fingerprint,
          signingFingerprint: signingKeyFingerprint(recipient.signingKey),
        });
      } catch {
        // A malformed signingKey in a committed file is its own problem,
        // but not this check's — it just can never match, same as if the
        // field were absent.
      }
    }
  } catch {
    // no recipients directory at all — recipientCount stays 0
  }

  // Two independent reasons this check has nothing to enforce yet, both
  // "not adopted", neither "broken": nobody else has access at all
  // (0-1 recipients — there is no one to impersonate), or nobody has
  // registered a signing key yet even though others have access (2+
  // recipients, zero signingKeys) — enforcing against an empty allow-list
  // would fail every single commit forever, which is indistinguishable
  // from a repository that simply hasn't turned this on.
  if (recipientCount < 2) return { id, label, ok: true };
  if (registered.length === 0) {
    return { id, label, ok: true, detail: 'not yet enforced — no recipient has a signing key registered' };
  }

  const headFingerprint = await headSignerFingerprint(repoDir);
  if (headFingerprint === null) {
    return { id, label, ok: false, detail: 'HEAD is not signed' };
  }
  const headFingerprintBuf = Buffer.from(headFingerprint, 'utf8');
  const match = registered.find((r) => equalCt(Buffer.from(r.signingFingerprint, 'utf8'), headFingerprintBuf));
  if (!match) {
    return { id, label, ok: false, detail: `HEAD is signed by an unrecognized key (${headFingerprint})` };
  }
  return { id, label, ok: true, detail: `signed by ${match.fingerprint}` };
}

// ---------------------------------------------------------------------------
// --access — "who can read this repository". See 13-verify.md.
// ---------------------------------------------------------------------------

export interface AccessRecipient {
  fingerprint: string;
  label: string;
  addedAt: string;
  addedBy: string;
  /** The oldest commit that added this recipient file, or `null` if it was never committed (T5, 16-adversarial-integrity.md). */
  addedCommit: string | null;
  /** Sorted ascending. Not necessarily contiguous — a recipient can predate a rotation, join after one, or both. */
  generations: number[];
}

export interface AccessProvider {
  id: string;
  /** Every generation across the whole keyring this provider can unwrap, sorted ascending. */
  generations: number[];
}

export interface AccessReport {
  recipients: AccessRecipient[];
  providers: AccessProvider[];
  recoveryExports: RecoveryLogEntry[];
  removedRecipients: RemovedRecipientLogEntry[];
}

function sortedGenerationKeys(keys: Record<string, unknown>): number[] {
  return Object.keys(keys)
    .map(Number)
    .filter((n) => Number.isInteger(n))
    .sort((a, b) => a - b);
}

/**
 * The oldest commit that added `relativePath` to the tree (T5,
 * 16-adversarial-integrity.md) — `git log` lists newest first, so the last
 * line of `--diff-filter=A` output is the first time it was ever added,
 * even if it was later removed and re-added. `null`, not an error, when the
 * path was never committed at all (the common state right after `key
 * add-recipient`, which deliberately doesn't commit its own output) or the
 * repository has no commits yet.
 */
async function firstAddedCommit(repoDir: string, relativePath: string): Promise<string | null> {
  try {
    const { stdout } = await execFile(
      'git',
      ['log', '--diff-filter=A', '--format=%h', '--', relativePath],
      { cwd: repoDir },
    );
    const shas = stdout.split('\n').filter((s) => s.length > 0);
    return shas.length > 0 ? shas[shas.length - 1]! : null;
  } catch {
    return null;
  }
}

/**
 * "Who can read this repository, now and previously" — recipients, the
 * providers wrapping the keyring, and the two append-only logs
 * (`recovery-log.json`, `removed-recipients.json`). Like `verify()`, this
 * unwraps no key and touches no session: recipient files, the keyring's
 * `provider` field on each wrapped slot, and both logs are all public even
 * in a locked repository or on a machine with no keyring of its own.
 */
export async function accessReport(opts: VerifyOptions): Promise<AccessReport> {
  const recipients: AccessRecipient[] = [];
  let entries: string[] = [];
  try {
    entries = (await readdir(recipientsDir(opts.repoDir))).filter((f) => f.endsWith('.json'));
  } catch {
    // no recipients directory — nothing shared beyond the keyring itself
  }
  for (const entry of entries) {
    const file = await readRecipientFile(recipientPath(opts.repoDir, entry.replace(/\.json$/, '')));
    const addedCommit = await firstAddedCommit(opts.repoDir, posix.join('.securegit', 'recipients', entry));
    recipients.push({
      fingerprint: file.fingerprint,
      label: file.label,
      addedAt: file.addedAt,
      addedBy: file.addedBy,
      addedCommit,
      generations: sortedGenerationKeys(file.keys),
    });
  }

  const providers: AccessProvider[] = [];
  try {
    const config = await readConfig(opts.repoDir);
    const keyring = await readKeyringFile(resolveKeyringPath(config.repoId, opts.home));
    const byProvider = new Map<string, number[]>();
    for (const gen of keyring.generations) {
      for (const slot of gen.wrapped) {
        const list = byProvider.get(slot.provider);
        if (list) list.push(gen.generation);
        else byProvider.set(slot.provider, [gen.generation]);
      }
    }
    for (const [id, generations] of byProvider) {
      providers.push({ id, generations: generations.sort((a, b) => a - b) });
    }
  } catch {
    // no local keyring — e.g. a machine that joined purely via a recipient
    // file (08-multi-recipient.md); the providers section is simply empty.
  }

  const recoveryExports = await readRecoveryLog(recoveryLogPath(opts.repoDir));
  const removedRecipients = await readRemovedRecipientsLog(removedRecipientsLogPath(opts.repoDir));

  return { recipients, providers, recoveryExports, removedRecipients };
}

// ---------------------------------------------------------------------------
// --history — walks every reachable commit. See 13-verify.md.
// ---------------------------------------------------------------------------

export interface HistoryFinding {
  path: string;
  firstSha: string;
  firstDate: string;
  firstSubject: string;
  lastSha: string;
  lastDate: string;
  lastSubject: string;
  /** How many walked commits had plaintext at this path — not necessarily contiguous. */
  commitCount: number;
  /** Local branches whose tip can reach the *last* offending commit. */
  reachableFrom: string[];
}

export interface HistoryReport {
  commitsWalked: number;
  findings: HistoryFinding[];
  textconvNotesRef: { present: boolean; count: number };
}

export interface HistoryOptions {
  repoDir: string;
  /**
   * Fires once per *unique* blob OID whose content was actually read — never
   * for a repeat encounter of a blob already in the cache. Exists so the
   * OID-deduplication this scan depends on for real-repository performance
   * (unwalked, this is thousands of commits mostly re-touching the same
   * unchanged blobs) is something a test can observe directly, not just
   * assert about in prose.
   */
  onBlobExamined?: (blobSha: string) => void;
}

/** Exported for `cli.ts`'s `verify --history` output. */
export const TEXTCONV_NOTES_REF = 'refs/notes/textconv/securegit';
const FIELD_SEP = '\x1f'; // unit separator — safe against anything a commit subject could contain

async function execWithStdin(
  cmd: string,
  args: string[],
  opts: { cwd: string; env: NodeJS.ProcessEnv; input: string },
): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { cwd: opts.cwd, env: opts.env });
    const outChunks: Buffer[] = [];
    const errChunks: Buffer[] = [];
    child.stdout.on('data', (c: Buffer) => outChunks.push(c));
    child.stderr.on('data', (c: Buffer) => errChunks.push(c));
    child.on('error', reject);
    child.on('close', (code) => {
      if (code === 0) resolve(Buffer.concat(outChunks).toString('utf8'));
      else reject(new Error(`${cmd} ${args.join(' ')} exited ${code}: ${Buffer.concat(errChunks).toString('utf8')}`));
    });
    child.stdin.write(opts.input);
    child.stdin.end();
  });
}

/** Every commit reachable from any ref, oldest first. */
async function listAllCommits(repoDir: string): Promise<string[]> {
  const { stdout } = await execFile('git', ['rev-list', '--all', '--reverse'], {
    cwd: repoDir,
    maxBuffer: 64 * 1024 * 1024,
  });
  return stdout.split('\n').filter((s) => s.length > 0);
}

interface CommitMeta {
  shortSha: string;
  date: string;
  subject: string;
}

async function commitMeta(repoDir: string, sha: string): Promise<CommitMeta> {
  const { stdout } = await execFile('git', ['log', '-1', `--format=%h${FIELD_SEP}%as${FIELD_SEP}%s`, sha], {
    cwd: repoDir,
  });
  const [shortSha, date, subject] = stdout.trim().split(FIELD_SEP);
  return { shortSha: shortSha ?? sha.slice(0, 7), date: date ?? '', subject: subject ?? '' };
}

/** Branches (not tags — the spec's example asks "still reachable from main") whose tip can reach `sha`. */
async function branchesContaining(repoDir: string, sha: string): Promise<string[]> {
  try {
    const { stdout } = await execFile('git', ['branch', '--contains', sha, '--format=%(refname:short)'], {
      cwd: repoDir,
    });
    return stdout.split('\n').filter((l) => l.length > 0);
  } catch {
    return [];
  }
}

/** `path -> blob SHA` for every tracked file at `sha`. */
async function treeEntries(repoDir: string, sha: string): Promise<{ path: string; blobSha: string }[]> {
  const { stdout } = await execFile('git', ['ls-tree', '-r', sha], {
    cwd: repoDir,
    maxBuffer: 64 * 1024 * 1024,
  });
  const out: { path: string; blobSha: string }[] = [];
  for (const line of stdout.split('\n')) {
    if (!line) continue;
    const tab = line.indexOf('\t');
    if (tab === -1) continue;
    const meta = line.slice(0, tab).split(' ');
    if (meta[1] !== 'blob' || !meta[2]) continue;
    out.push({ path: line.slice(tab + 1), blobSha: meta[2] });
  }
  return out;
}

/**
 * Which of `paths` were `filter=securegit` at the commit already loaded into
 * the index at `env.GIT_INDEX_FILE` — `--cached` reads `.gitattributes` from
 * that index only, never the working tree, which is what makes "as of a
 * given historical commit" possible: `git check-attr` has no `--source
 * <tree-ish>` option on the git version this project can assume (added in
 * 2.40; this project targets what a real clone is likely to have), but a
 * temporary index populated via `read-tree <sha>` gets the same resolution
 * for free, without ever materialising a worktree.
 */
async function protectedPathsAt(repoDir: string, env: NodeJS.ProcessEnv, paths: string[]): Promise<Set<string>> {
  if (paths.length === 0) return new Set();
  const input = paths.map((p) => `${p}\0`).join('');
  const stdout = await execWithStdin('git', ['check-attr', '--cached', '-z', '--stdin', 'filter'], {
    cwd: repoDir,
    env,
    input,
  });
  const fields = stdout.split('\0').filter((s) => s.length > 0);
  const out = new Set<string>();
  for (let i = 0; i + 2 < fields.length; i += 3) {
    if (fields[i + 2] === 'securegit') out.add(fields[i]!);
  }
  return out;
}

async function readBlob(repoDir: string, sha: string): Promise<Buffer> {
  const { stdout } = await execFile('git', ['cat-file', '-p', sha], {
    cwd: repoDir,
    encoding: 'buffer',
    maxBuffer: 512 * 1024 * 1024,
  });
  return stdout;
}

async function textconvNotesRefStatus(repoDir: string): Promise<{ present: boolean; count: number }> {
  try {
    await execFile('git', ['show-ref', '--verify', '--quiet', TEXTCONV_NOTES_REF], { cwd: repoDir });
  } catch {
    return { present: false, count: 0 };
  }
  try {
    const { stdout } = await execFile('git', ['notes', '--ref', 'textconv/securegit', 'list'], { cwd: repoDir });
    return { present: true, count: stdout.split('\n').filter((l) => l.trim().length > 0).length };
  } catch {
    return { present: true, count: 0 };
  }
}

/**
 * Walks every reachable commit (`git rev-list --all`), resolving
 * `filter=securegit` protection as it stood *at that commit* — a path
 * protected today may not have been then, and reporting it as a leak either
 * way would be wrong in one direction or the other. Every blob is read at
 * most once regardless of how many commits reference it unchanged, via a
 * plain `Map` keyed by blob SHA — content is content-addressed, so the same
 * SHA always means the same bytes.
 *
 * CI-tier speed, not pre-commit: a repository of any real size means
 * hundreds to thousands of `git` subprocess invocations. See "Use as a
 * hook" in 13-verify.md.
 */
export async function historyReport(opts: HistoryOptions): Promise<HistoryReport> {
  const commits = await listAllCommits(opts.repoDir);
  const blobIsPlaintext = new Map<string, boolean>();
  const perPath = new Map<string, { firstSha: string; lastSha: string; count: number }>();

  const tmpIndex = join(tmpdir(), `securegit-verify-history-index-${randomBytes(4).toString('hex')}`);
  const env: NodeJS.ProcessEnv = { ...process.env, GIT_INDEX_FILE: tmpIndex };
  try {
    for (const sha of commits) {
      const entries = await treeEntries(opts.repoDir, sha);
      if (entries.length === 0) continue;

      await execFile('git', ['read-tree', sha], { cwd: opts.repoDir, env });
      const protectedPaths = await protectedPathsAt(
        opts.repoDir,
        env,
        entries.map((e) => e.path),
      );

      for (const entry of entries) {
        if (!protectedPaths.has(entry.path)) continue;

        let plaintext = blobIsPlaintext.get(entry.blobSha);
        if (plaintext === undefined) {
          const content = await readBlob(opts.repoDir, entry.blobSha);
          plaintext = !looksLikeEnvelope(content);
          blobIsPlaintext.set(entry.blobSha, plaintext);
          opts.onBlobExamined?.(entry.blobSha);
        }
        if (!plaintext) continue;

        const existing = perPath.get(entry.path);
        if (existing) {
          existing.lastSha = sha;
          existing.count += 1;
        } else {
          perPath.set(entry.path, { firstSha: sha, lastSha: sha, count: 1 });
        }
      }
    }
  } finally {
    await unlink(tmpIndex).catch(() => {});
  }

  const findings: HistoryFinding[] = [];
  for (const [path, acc] of perPath) {
    const first = await commitMeta(opts.repoDir, acc.firstSha);
    const last = await commitMeta(opts.repoDir, acc.lastSha);
    const reachableFrom = await branchesContaining(opts.repoDir, acc.lastSha);
    findings.push({
      path,
      firstSha: first.shortSha,
      firstDate: first.date,
      firstSubject: first.subject,
      lastSha: last.shortSha,
      lastDate: last.date,
      lastSubject: last.subject,
      commitCount: acc.count,
      reachableFrom,
    });
  }

  const textconvNotesRef = await textconvNotesRefStatus(opts.repoDir);
  return { commitsWalked: commits.length, findings, textconvNotesRef };
}

// ---------------------------------------------------------------------------
// M1–M12 — "status reports which apply". See 14-metadata-leakage.md.
// ---------------------------------------------------------------------------

export interface MetadataObservable {
  code: string;
  observable: string;
  /** Whether this repository currently has anything to observe here — false only for M11 with no recipients. */
  applies: boolean;
  note: string;
}

export interface MetadataReport {
  observables: MetadataObservable[];
}

/**
 * A static list, not a live audit: every M-code the spec catalogues, with
 * the two that respond to local config (`padTo`, `bindPath`) reflecting
 * their actual current mitigation state, and M11 (recipient metadata)
 * reporting whether it applies at all — every other observable is
 * unconditional (inherent to committing to a Git repository), so
 * `applies` is always `true` for them, and mitigation is always "no" per
 * the spec's own table.
 */
export async function metadataReport(opts: { repoDir: string }): Promise<MetadataReport> {
  const config = await readConfig(opts.repoDir);

  let recipientCount = 0;
  try {
    recipientCount = (await readdir(recipientsDir(opts.repoDir))).filter((f) => f.endsWith('.json')).length;
  } catch {
    // no recipients directory
  }

  const observables: MetadataObservable[] = [
    {
      code: 'M1',
      observable: 'Every file path and directory name',
      applies: true,
      note: 'not mitigable — tree objects are not filtered',
    },
    {
      code: 'M2',
      observable: 'File sizes, ± 63 bytes of envelope overhead',
      applies: true,
      note:
        config.padTo > 0
          ? `partially mitigated — padTo=${config.padTo}`
          : 'not mitigated — padTo is 0 (disabled)',
    },
    {
      code: 'M3',
      observable: 'Which commits touched which paths',
      applies: true,
      note: 'not mitigable — tree diffs',
    },
    {
      code: 'M4',
      observable: 'Commit messages',
      applies: true,
      note: 'not mitigable — commit objects are not filtered',
    },
    {
      code: 'M5',
      observable: 'Author name, email, timestamps',
      applies: true,
      note: 'not mitigable — commit objects',
    },
    {
      code: 'M6',
      observable: 'Branch and tag names',
      applies: true,
      note: 'not mitigable — refs',
    },
    {
      code: 'M7',
      observable: 'The commit graph — merges, rate, contributors',
      applies: true,
      note: 'not mitigable — commit objects',
    },
    {
      code: 'M8',
      observable: 'Blob equality across paths, commits and branches',
      applies: true,
      note: config.bindPath ? 'partially mitigated — bindPath is on' : 'not mitigated — bindPath is off',
    },
    {
      code: 'M9',
      observable: 'Whether a change reverted to an earlier state',
      applies: true,
      note: 'not mitigable — neither bindPath nor padTo removes this',
    },
    {
      code: 'M10',
      observable: 'Which files are protected at all',
      applies: true,
      note: 'not mitigable — .gitattributes is plaintext',
    },
    {
      code: 'M11',
      observable: 'Recipient count, labels, fingerprints, join dates',
      applies: recipientCount > 0,
      note:
        recipientCount > 0
          ? 'not mitigable — .securegit/recipients/ is plaintext'
          : 'does not apply — no recipients',
    },
    {
      code: 'M12',
      observable: 'Key generation in use per blob',
      applies: true,
      note: 'not mitigable — envelope keyId',
    },
  ];

  return { observables };
}
