// Config, attribute and content checks that catch the ways this design fails
// silently — a missing filter, a removed attribute, a plaintext blob that
// slipped past a pattern that stopped matching. See specs/securegit/13-verify.md.
//
// This module never touches a session or unwraps a key: every check works
// from public information (git config, .gitattributes, blob magic bytes), so
// `verify` runs identically whether the repository is locked or not.
//
// Scope for this pass: the always-on configuration and index checks
// (`securegit verify`). `--history` (walking every reachable commit) and
// `--access` (who can read this repository, which needs spec 08's recipient
// list) are out of scope here — see 13-verify.md for why.

import { execFile as execFileCb } from 'node:child_process';
import { promisify } from 'node:util';
import { readFile } from 'node:fs/promises';
import { join, relative, isAbsolute } from 'node:path';
import { readConfig, resolveKeyringPath } from './config.js';
import { readKeyringFile } from './keyring.js';
import { resolveSessionPath } from './session.js';
import type { KeyProvider } from './provider.js';
import { looksLikeEnvelope } from './envelope.js';
import { EXCLUSION_LINE } from './install.js';

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
  | 'non-custodial-unwrap-path';

export interface CheckResult {
  id: CheckId;
  label: string;
  ok: boolean;
  detail?: string;
}

export type FindingKind = 'leak' | 'advice';

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

/** Leak beats misconfiguration beats advice: a live plaintext exposure is always the loudest thing to report. */
export function verifyExitCode(report: VerifyReport): number {
  if (report.findings.some((f) => f.kind === 'leak')) return EXIT_VERIFY_LEAK;
  if (report.checks.some((c) => !c.ok)) return EXIT_VERIFY_MISCONFIGURED;
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

async function listTrackedPaths(repoDir: string): Promise<string[]> {
  const { stdout } = await execFile('git', ['ls-files', '-z'], {
    cwd: repoDir,
    maxBuffer: 64 * 1024 * 1024,
  });
  return stdout.split('\0').filter((p) => p.length > 0);
}

/** `path: attribute: value` per requested attribute, parsed into a map. */
async function checkAttr(repoDir: string, path: string): Promise<Record<string, string>> {
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

/** The index's copy of a tracked path — what would be committed right now. */
async function readIndexBlob(repoDir: string, path: string): Promise<Buffer> {
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

  return { checks, findings };
}
