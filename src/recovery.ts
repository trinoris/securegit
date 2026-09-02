// The offline path back in when every workstation is gone: a recovery
// FILE (ciphertext, safe to commit) and a recovery CODE (256 bits, offline,
// on paper), neither of which is anything alone. Also the committed
// recovery log — not the code, not the file, just the fact that an export
// happened.
// See specs/securegit/09-rotation-recovery.md.

import { createHash, hkdfSync, randomBytes } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { aeadDecrypt, aeadEncrypt } from './crypto.js';
import { crockfordEncode, crockfordDecode } from './identity.js';

export class RecoveryError extends Error {
  readonly code = 'RECOVERY';

  constructor(message: string) {
    super(message);
    this.name = 'RecoveryError';
  }
}

export const RECOVERY_CODE_LEN = 32;
const CHECKSUM_LEN = 4;
const RECOVERY_FORMAT_V1 = 1;
const WRAP_INFO = Buffer.from('securegit/recovery/v1', 'utf8');
const AAD_LABEL = Buffer.from('securegit/recovery-file/v1', 'utf8');
const SEP = Buffer.from([0x00]);
const NO_SALT = Buffer.alloc(0);
const NONCE_LEN = 12;

/** A fresh 256-bit recovery code. */
export function generateRecoveryCode(): Buffer {
  return randomBytes(RECOVERY_CODE_LEN);
}

function checksum(code: Buffer): Buffer {
  return createHash('sha256').update(code).digest().subarray(0, CHECKSUM_LEN);
}

/** Crockford-encodes `code ‖ checksum(code)`, grouped in 4s for a card. */
export function formatRecoveryCode(code: Buffer): string {
  if (code.length !== RECOVERY_CODE_LEN) {
    throw new RecoveryError(`recovery code must be ${RECOVERY_CODE_LEN} bytes, got ${code.length}`);
  }
  const encoded = crockfordEncode(Buffer.concat([code, checksum(code)]));
  const groups: string[] = [];
  for (let i = 0; i < encoded.length; i += 4) groups.push(encoded.slice(i, i + 4));
  return groups.join('-');
}

/**
 * Reverses `formatRecoveryCode`. This code is meant to be read off a
 * printed card, possibly under stress — so hyphens and whitespace are
 * ignored, case doesn't matter, and `O`/`I`/`L` are folded to `0`/`1`/`1`
 * before decoding, the transcription confusions the spec calls out
 * explicitly. The checksum, not strict formatting, is what actually catches
 * a mistake.
 */
export function parseRecoveryCode(input: string): Buffer {
  const cleaned = input
    .toUpperCase()
    .replace(/[\s-]/g, '')
    .replace(/O/g, '0')
    .replace(/[IL]/g, '1');

  let decoded: Buffer;
  try {
    decoded = crockfordDecode(cleaned);
  } catch {
    throw new RecoveryError('recovery code is not valid — check for transcription errors');
  }
  if (decoded.length !== RECOVERY_CODE_LEN + CHECKSUM_LEN) {
    throw new RecoveryError('recovery code is the wrong length');
  }
  const code = decoded.subarray(0, RECOVERY_CODE_LEN);
  const given = decoded.subarray(RECOVERY_CODE_LEN);
  if (!checksum(code).equals(given)) {
    throw new RecoveryError('recovery code checksum does not match — check for transcription errors');
  }
  return code;
}

function deriveWrapKey(code: Buffer): Buffer {
  return Buffer.from(hkdfSync('sha256', code, NO_SALT, WRAP_INFO, 32));
}

function buildAad(repoId: string, format: number): Buffer {
  return Buffer.concat([AAD_LABEL, SEP, Buffer.from(repoId, 'utf8'), SEP, Buffer.from([format])]);
}

export interface RecoveryGenerationEntry {
  nonce: string;
  ciphertext: string;
  authTag: string;
}

export interface RecoveryFile {
  version: 1;
  repoId: string;
  format: number;
  /** Keyed by generation number as a string ("1", "2", ...). */
  generations: Record<string, RecoveryGenerationEntry>;
}

export interface ExportRecoveryOptions {
  repoId: string;
  generations: { generation: number; rmk: Buffer }[];
}

/**
 * Generates a fresh code and encrypts every given generation's RMK under a
 * key derived from it. Each generation gets its own random nonce — unlike
 * `recipients.ts`'s zero-nonce wrap, every generation here is encrypted
 * under the *same* wrap key (derived once from the code, not per-wrap from
 * a fresh ephemeral secret), so nonce reuse would be a real risk without one.
 */
export function exportRecovery(opts: ExportRecoveryOptions): { code: Buffer; file: RecoveryFile } {
  const code = generateRecoveryCode();
  const wrapKey = deriveWrapKey(code);
  const aad = buildAad(opts.repoId, RECOVERY_FORMAT_V1);

  const generations: Record<string, RecoveryGenerationEntry> = {};
  for (const { generation, rmk } of opts.generations) {
    const nonce = randomBytes(NONCE_LEN);
    const { ciphertext, authTag } = aeadEncrypt(wrapKey, nonce, rmk, aad);
    generations[String(generation)] = {
      nonce: nonce.toString('hex'),
      ciphertext: ciphertext.toString('hex'),
      authTag: authTag.toString('hex'),
    };
  }

  return { code, file: { version: 1, repoId: opts.repoId, format: RECOVERY_FORMAT_V1, generations } };
}

/**
 * Decrypts every generation in `file` under `code`. Fails closed and all at
 * once: unlike a recipient (who may legitimately hold only some
 * generations), one code either decrypts the whole file or none of it, so
 * a wrong code or a `repoId` mismatch is an error, not a silently empty
 * result.
 */
export function importRecovery(
  file: RecoveryFile,
  code: Buffer,
  expectedRepoId: string,
): { generation: number; rmk: Buffer }[] {
  if (file.repoId !== expectedRepoId) {
    throw new RecoveryError(
      `securegit: this recovery file belongs to repository ${file.repoId}\n` +
        `  this repository is ${expectedRepoId}`,
    );
  }

  const wrapKey = deriveWrapKey(code);
  const aad = buildAad(file.repoId, file.format);
  const out: { generation: number; rmk: Buffer }[] = [];

  for (const [genStr, entry] of Object.entries(file.generations)) {
    const generation = Number(genStr);
    if (!Number.isInteger(generation)) continue;
    try {
      const rmk = aeadDecrypt(
        wrapKey,
        Buffer.from(entry.nonce, 'hex'),
        Buffer.from(entry.ciphertext, 'hex'),
        Buffer.from(entry.authTag, 'hex'),
        aad,
      );
      out.push({ generation, rmk });
    } catch {
      throw new RecoveryError(`securegit: cannot decrypt recovery file — wrong code, or the file is corrupted`);
    }
  }

  return out;
}

export function recoveryFilePath(repoDir: string, filename: string): string {
  return join(repoDir, filename);
}

/**
 * Ordinary permissions, no atomic temp+rename: unlike the keyring or an
 * identity file, this is written once to a fresh path the caller chose, not
 * repeatedly overwritten in place, and it holds nothing secret — the file
 * alone decrypts nothing without the code.
 */
export async function writeRecoveryFile(path: string, file: RecoveryFile): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, JSON.stringify(file, null, 2));
}

export async function readRecoveryFile(path: string): Promise<RecoveryFile> {
  const raw = await readFile(path, 'utf8');
  return JSON.parse(raw) as RecoveryFile;
}

export interface RecoveryLogEntry {
  exportId: string;
  timestamp: string;
  /** The exporter's own identity fingerprint, or "" if they have none locally. */
  exportedBy: string;
  /** Which generations this export covers — public metadata, never the code or file content. */
  generations: number[];
}

export function recoveryLogPath(repoDir: string): string {
  return join(repoDir, '.securegit', 'recovery-log.json');
}

export function generateExportId(): string {
  return randomBytes(4).toString('hex');
}

export async function readRecoveryLog(path: string): Promise<RecoveryLogEntry[]> {
  try {
    return JSON.parse(await readFile(path, 'utf8')) as RecoveryLogEntry[];
  } catch {
    return [];
  }
}

/** Records that an export happened — never the code, never the file's content. */
export async function appendRecoveryLogEntry(
  path: string,
  entry: RecoveryLogEntry,
): Promise<RecoveryLogEntry[]> {
  const log = await readRecoveryLog(path);
  log.push(entry);
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, JSON.stringify(log, null, 2));
  return log;
}
