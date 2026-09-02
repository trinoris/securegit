// The three-way merge driver: `securegit merge -- %O %A %B %L %P`.
//
// Without this, merging a protected file is a binary conflict with no option
// but to take one side whole. This decrypts all three inputs, runs Git's own
// `merge-file` over the plaintexts (conflict markers included on a conflict),
// and re-encrypts the result — which is why the driver never itself resolves
// or masks a conflict, only relocates where one is visible.
// See specs/securegit/12-diff-merge.md.

import { execFile as execFileCb } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { looksLikeEnvelope, parseEnvelope, seal, unseal } from './envelope.js';
import { LockedError, type KeySource } from './filter.js';

export { LockedError };

const execFile = promisify(execFileCb);

export class MergeError extends Error {
  readonly code = 'MERGE';

  constructor(message: string) {
    super(message);
    this.name = 'MergeError';
  }
}

export interface MergeOptions {
  keys: KeySource;
  /** Repository-relative path — %P. Used for key derivation and diagnostics only. */
  path: string;
  bindPath?: boolean;
  padTo?: number;
  /** Conflict marker length — %L. Git's own default is 7. */
  markerSize?: number;
  base: Buffer;
  ours: Buffer;
  theirs: Buffer;
}

export interface MergeResult {
  /** false when conflict markers remain in the result. */
  clean: boolean;
  /** Ciphertext — what the driver writes back to %A. Never plaintext. */
  output: Buffer;
}

function lockedMessage(path: string): string {
  return (
    `securegit: repository is locked\n` +
    `  file:   ${path}\n` +
    `  action: run \`securegit unlock\`, then retry`
  );
}

/**
 * Plaintext or (already-authenticated) ciphertext in, plaintext out. Unlike
 * `smudge`, this never passes ciphertext through on failure — a merge that
 * cannot see one side's real content cannot be trusted to produce anything,
 * so it fails the whole operation rather than guessing.
 */
function resolvePlaintext(content: Buffer, keys: KeySource, path: string, label: string): Buffer {
  if (!looksLikeEnvelope(content)) return content; // predates protection, or filter was never installed

  let header;
  try {
    header = parseEnvelope(content);
  } catch (e) {
    throw new MergeError(`securegit: cannot merge ${path}: ${label} is not a valid envelope: ${(e as Error).message}`);
  }

  const rmk = keys.find(header.keyId);
  if (rmk === null) {
    throw new MergeError(
      `securegit: cannot merge ${path}: ${label} wants generation ${header.keyId}, which this keyring does not hold`,
    );
  }

  try {
    return unseal(content, { rmk, path });
  } catch (e) {
    throw new MergeError(`securegit: cannot merge ${path}: authentication failed for ${label}: ${(e as Error).message}`);
  }
}

/**
 * Runs `git merge-file` in place over three temp files and reports whether it
 * was clean. Not `-p`: letting it rewrite `oursFile` directly, then reading
 * that back regardless of exit code, avoids depending on Node's undocumented
 * stdout-on-nonzero-exit behaviour for a subprocess result.
 */
async function runMergeFile(
  oursFile: string,
  baseFile: string,
  theirsFile: string,
  markerSize: number,
): Promise<boolean> {
  try {
    await execFile('git', ['merge-file', `--marker-size=${markerSize}`, oursFile, baseFile, theirsFile]);
    return true;
  } catch (e) {
    const err = e as { code?: number };
    if (typeof err.code === 'number' && err.code > 0) {
      return false; // conflicts remain; oursFile now holds markers
    }
    throw new MergeError(`securegit: git merge-file failed: ${(e as Error).message}`);
  }
}

export async function merge(opts: MergeOptions): Promise<MergeResult> {
  const bindPath = opts.bindPath ?? false;
  const markerSize = opts.markerSize ?? 7;

  const basePlain = resolvePlaintext(opts.base, opts.keys, opts.path, 'the ancestor');
  const oursPlain = resolvePlaintext(opts.ours, opts.keys, opts.path, 'our side');
  const theirsPlain = resolvePlaintext(opts.theirs, opts.keys, opts.path, 'their side');

  // mkdtemp always creates its directory with mode 0700, satisfying the
  // "temporary files go in a 0700 directory" requirement without further work.
  const tmpDir = await mkdtemp(join(tmpdir(), 'securegit-merge-'));
  try {
    const baseFile = join(tmpDir, 'base');
    const oursFile = join(tmpDir, 'ours');
    const theirsFile = join(tmpDir, 'theirs');
    await writeFile(baseFile, basePlain);
    await writeFile(oursFile, oursPlain);
    await writeFile(theirsFile, theirsPlain);

    const clean = await runMergeFile(oursFile, baseFile, theirsFile, markerSize);
    const merged = await readFile(oursFile);

    const current = opts.keys.current();
    if (current === null) {
      throw new LockedError(lockedMessage(opts.path));
    }

    const output = seal(merged, {
      rmk: current.rmk,
      keyId: current.keyId,
      path: opts.path,
      bindPath,
      ...(opts.padTo !== undefined ? { padTo: opts.padTo } : {}),
    });
    return { clean, output };
  } finally {
    await rm(tmpDir, { recursive: true, force: true });
  }
}
