// Writes local (never committed) Git filter/diff configuration, and manages
// the tracked `.gitattributes` / `.gitignore` entries that route paths
// through it.
// See specs/securegit/02-git-integration.md and 16-adversarial-integrity.md (T10, T12).

import { execFile as execFileCb } from 'node:child_process';
import { promisify } from 'node:util';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

const execFile = promisify(execFileCb);

export class InstallError extends Error {
  readonly code = 'INSTALL';

  constructor(message: string) {
    super(message);
    this.name = 'InstallError';
  }
}

// ---------------------------------------------------------------------------
// git config
// ---------------------------------------------------------------------------

async function gitConfigGet(repoDir: string, key: string): Promise<string | null> {
  try {
    const { stdout } = await execFile('git', ['config', '--local', '--get', key], {
      cwd: repoDir,
    });
    return stdout.replace(/\n$/, '');
  } catch (e) {
    const err = e as { code?: number };
    if (err.code === 1) return null; // unset
    throw new InstallError(
      `could not read git config in ${repoDir}: ${(e as Error).message}`,
    );
  }
}

async function gitConfigSet(repoDir: string, key: string, value: string): Promise<void> {
  await execFile('git', ['config', '--local', '--replace-all', key, value], { cwd: repoDir });
}

async function gitConfigUnset(repoDir: string, key: string): Promise<void> {
  try {
    await execFile('git', ['config', '--local', '--unset-all', key], { cwd: repoDir });
  } catch (e) {
    const err = e as { code?: number };
    if (err.code !== 5) throw e; // 5 = key was already unset
  }
}

export interface InstallOptions {
  repoDir: string;
  /** Command used in the filter lines. Defaults to "securegit". */
  bin?: string;
  /** Use the long-running `filter.securegit.process` form instead of clean/smudge. */
  process?: boolean;
  required?: boolean;
  /** Overwrite pre-existing filter/diff config this tool did not write. */
  force?: boolean;
}

const IDENTITY_KEYS = [
  'filter.securegit.clean',
  'filter.securegit.smudge',
  'filter.securegit.process',
  'diff.securegit.textconv',
  'merge.securegit.driver',
] as const;

/** Every value securegit itself would ever write to an identity key, for any form. */
function recognizedValues(bin: string): Set<string> {
  return new Set([
    `${bin} clean -- %f`,
    `${bin} smudge -- %f`,
    `${bin} filter-process`,
    `${bin} textconv --`,
    `${bin} merge -- %O %A %B %L %P`,
  ]);
}

/**
 * Writes the filter and diff configuration. Refuses to overwrite an existing
 * identity key (clean/smudge/process/textconv) whose value does not look like
 * something securegit itself would have written — for any bin path this call
 * uses — because that value names an executable, and silently replacing it is
 * exactly the risk in specs/securegit/16-adversarial-integrity.md, T10.
 */
export async function install(opts: InstallOptions): Promise<void> {
  const bin = opts.bin ?? 'securegit';
  const useProcess = opts.process ?? false;
  const required = opts.required ?? true;

  const existing: Record<string, string | null> = {};
  for (const key of IDENTITY_KEYS) {
    existing[key] = await gitConfigGet(opts.repoDir, key);
  }

  if (!opts.force) {
    const recognized = recognizedValues(bin);
    const foreign = IDENTITY_KEYS.filter(
      (key) => existing[key] !== null && !recognized.has(existing[key] as string),
    );
    if (foreign.length > 0) {
      const detail = foreign.map((key) => `  ${key} = ${existing[key]}`).join('\n');
      throw new InstallError(
        `securegit: refusing to overwrite existing filter configuration it did not write\n${detail}\n` +
          `  action: remove it manually, or pass force: true to overwrite it`,
      );
    }
  }

  if (useProcess) {
    await gitConfigUnset(opts.repoDir, 'filter.securegit.clean');
    await gitConfigUnset(opts.repoDir, 'filter.securegit.smudge');
    await gitConfigSet(opts.repoDir, 'filter.securegit.process', `${bin} filter-process`);
  } else {
    await gitConfigUnset(opts.repoDir, 'filter.securegit.process');
    await gitConfigSet(opts.repoDir, 'filter.securegit.clean', `${bin} clean -- %f`);
    await gitConfigSet(opts.repoDir, 'filter.securegit.smudge', `${bin} smudge -- %f`);
  }

  await gitConfigSet(opts.repoDir, 'filter.securegit.required', required ? 'true' : 'false');
  await gitConfigSet(opts.repoDir, 'diff.securegit.textconv', `${bin} textconv --`);
  await gitConfigSet(opts.repoDir, 'diff.securegit.cachetextconv', 'false');
  await gitConfigSet(opts.repoDir, 'merge.securegit.name', 'securegit encrypted three-way merge');
  await gitConfigSet(opts.repoDir, 'merge.securegit.driver', `${bin} merge -- %O %A %B %L %P`);
}

// ---------------------------------------------------------------------------
// .gitattributes
// ---------------------------------------------------------------------------

export const EXCLUSION_LINE = '.securegit/** -filter -diff -text';

function attributeLine(pattern: string): string {
  return `${pattern} filter=securegit diff=securegit merge=securegit -text`;
}

async function readLines(path: string): Promise<string[]> {
  try {
    const content = await readFile(path, 'utf8');
    return content.split('\n').filter((_, i, arr) => !(i === arr.length - 1 && arr[i] === ''));
  } catch (e) {
    if ((e as { code?: string }).code === 'ENOENT') return [];
    throw e;
  }
}

async function writeLines(path: string, lines: string[]): Promise<void> {
  await writeFile(path, lines.length > 0 ? `${lines.join('\n')}\n` : '', 'utf8');
}

async function updateGitattributes(repoDir: string, patterns: string[]): Promise<void> {
  const path = join(repoDir, '.gitattributes');
  const existing = (await readLines(path)).filter((line) => line !== EXCLUSION_LINE);

  const present = new Set(existing.map((line) => line.split(/\s+/)[0]));
  const additions = patterns.filter((p) => !present.has(p)).map(attributeLine);

  await writeLines(path, [...existing, ...additions, EXCLUSION_LINE]);
}

// ---------------------------------------------------------------------------
// .gitignore residue entries (T12)
// ---------------------------------------------------------------------------

/** Exported so `verify.ts` (T12) can check for the same shapes on disk. */
export const RESIDUE_SUFFIXES = ['~', '.orig', '.rej', '.bak', '.save'];

/** The path vim actually gives a swap file: dot-prefixed basename, `.sw?`. */
export function swapPattern(pattern: string): string {
  const idx = pattern.lastIndexOf('/');
  const dir = idx === -1 ? '' : pattern.slice(0, idx + 1);
  const base = idx === -1 ? pattern : pattern.slice(idx + 1);
  return `${dir}.${base}.sw?`;
}

function residueLines(pattern: string): string[] {
  return [...RESIDUE_SUFFIXES.map((suffix) => `${pattern}${suffix}`), swapPattern(pattern)];
}

async function updateGitignore(repoDir: string, patterns: string[]): Promise<void> {
  const path = join(repoDir, '.gitignore');
  const existing = await readLines(path);
  const present = new Set(existing);
  const additions = patterns.flatMap(residueLines).filter((line) => !present.has(line));
  await writeLines(path, [...existing, ...additions]);
}

// ---------------------------------------------------------------------------

export interface ProtectOptions {
  /** Also write `.gitignore` entries for editor/merge residue. Default true. */
  residuePatterns?: boolean;
}

/**
 * Protects one or more path patterns: writes them into `.gitattributes` with
 * the filter, diff driver and `-text`, keeping the `.securegit/**` exclusion
 * last, and (by default) adds `.gitignore` entries for the plaintext residue
 * ordinary tooling leaves beside a protected file.
 */
export async function protect(
  repoDir: string,
  patterns: string[],
  opts: ProtectOptions = {},
): Promise<void> {
  if (patterns.length === 0) {
    throw new InstallError('protect requires at least one pattern');
  }
  await updateGitattributes(repoDir, patterns);
  if (opts.residuePatterns ?? true) {
    await updateGitignore(repoDir, patterns);
  }
}
