import { describe, it, expect } from 'vitest';
import { mkdtemp, rm, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  RecoveryError,
  RECOVERY_CODE_LEN,
  generateRecoveryCode,
  formatRecoveryCode,
  parseRecoveryCode,
  exportRecovery,
  importRecovery,
  recoveryLogPath,
  appendRecoveryLogEntry,
  readRecoveryLog,
  generateExportId,
  recoveryFilePath,
  writeRecoveryFile,
  readRecoveryFile,
  type RecoveryFile,
} from './recovery.js';

const REPO_ID = 'repo-a';

describe('generateRecoveryCode()', () => {
  it('produces 32 bytes', () => {
    expect(generateRecoveryCode().length).toBe(RECOVERY_CODE_LEN);
  });

  it('two calls differ', () => {
    expect(generateRecoveryCode().equals(generateRecoveryCode())).toBe(false);
  });
});

describe('formatRecoveryCode() / parseRecoveryCode()', () => {
  it('round-trips', () => {
    const code = generateRecoveryCode();
    expect(parseRecoveryCode(formatRecoveryCode(code)).equals(code)).toBe(true);
  });

  it('formats as hyphen-separated groups of up to 4 characters', () => {
    // 36 bytes (32-byte code + 4-byte checksum) Crockford-encode to 58
    // characters, which isn't a multiple of 4 — the final group is shorter.
    const formatted = formatRecoveryCode(generateRecoveryCode());
    const groups = formatted.split('-');
    expect(groups.length).toBeGreaterThan(1);
    for (const group of groups.slice(0, -1)) expect(group).toMatch(/^[0-9A-Z]{4}$/);
    expect(groups[groups.length - 1]).toMatch(/^[0-9A-Z]{1,4}$/);
  });

  it('accepts lowercase input', () => {
    const code = generateRecoveryCode();
    const formatted = formatRecoveryCode(code);
    expect(parseRecoveryCode(formatted.toLowerCase()).equals(code)).toBe(true);
  });

  it('accepts input with hyphens and whitespace stripped or added', () => {
    const code = generateRecoveryCode();
    const formatted = formatRecoveryCode(code);
    const unspaced = formatted.replace(/-/g, '');
    expect(parseRecoveryCode(unspaced).equals(code)).toBe(true);
    const extraSpaced = formatted.split('-').join('  ');
    expect(parseRecoveryCode(extraSpaced).equals(code)).toBe(true);
  });

  it('folds O -> 0 and I/L -> 1 on input', () => {
    const code = generateRecoveryCode();
    const formatted = formatRecoveryCode(code);
    // Only meaningful if the formatted string actually uses digits that a
    // transcriber might mis-key as letters — round-trip through the fold
    // regardless, since fold is a no-op on characters it doesn't touch.
    const withConfusables = formatted.replace(/0/g, 'O').replace(/1/g, 'I');
    expect(parseRecoveryCode(withConfusables).equals(code)).toBe(true);
  });

  it('rejects a single-character transcription error via the checksum', () => {
    const code = generateRecoveryCode();
    const formatted = formatRecoveryCode(code).replace(/-/g, '');
    const firstChar = formatted[0]!;
    const replacement = firstChar === '2' ? '3' : '2';
    const corrupted = replacement + formatted.slice(1);
    expect(corrupted).not.toBe(formatted);
    expect(() => parseRecoveryCode(corrupted)).toThrow(RecoveryError);
  });

  it('rejects a garbage string', () => {
    expect(() => parseRecoveryCode('not a recovery code')).toThrow(RecoveryError);
  });
});

describe('exportRecovery() / importRecovery()', () => {
  const RMK1 = Buffer.alloc(32, 0x11);
  const RMK2 = Buffer.alloc(32, 0x22);

  it('round-trips every generation', () => {
    const { code, file } = exportRecovery({
      repoId: REPO_ID,
      generations: [
        { generation: 1, rmk: RMK1 },
        { generation: 2, rmk: RMK2 },
      ],
    });

    const recovered = importRecovery(file, code, REPO_ID);
    const byGen = new Map(recovered.map((r) => [r.generation, r.rmk]));
    expect(byGen.get(1)!.equals(RMK1)).toBe(true);
    expect(byGen.get(2)!.equals(RMK2)).toBe(true);
  });

  it('the file alone does not decrypt — a wrong code fails cleanly', () => {
    const { file } = exportRecovery({ repoId: REPO_ID, generations: [{ generation: 1, rmk: RMK1 }] });
    const wrongCode = generateRecoveryCode();
    expect(() => importRecovery(file, wrongCode, REPO_ID)).toThrow(RecoveryError);
  });

  it('is bound to repoId — fails against a different repository', () => {
    const { code, file } = exportRecovery({ repoId: REPO_ID, generations: [{ generation: 1, rmk: RMK1 }] });
    expect(() => importRecovery(file, code, 'a-different-repo')).toThrow(RecoveryError);
  });

  it('two exports of the same generations use different codes and different ciphertext', () => {
    const a = exportRecovery({ repoId: REPO_ID, generations: [{ generation: 1, rmk: RMK1 }] });
    const b = exportRecovery({ repoId: REPO_ID, generations: [{ generation: 1, rmk: RMK1 }] });
    expect(a.code.equals(b.code)).toBe(false);
    expect(a.file.generations['1']!.ciphertext).not.toBe(b.file.generations['1']!.ciphertext);
  });

  it('the recovery code never appears in the file that gets written', () => {
    const { code, file } = exportRecovery({ repoId: REPO_ID, generations: [{ generation: 1, rmk: RMK1 }] });
    const serialized = JSON.stringify(file);
    expect(serialized).not.toContain(code.toString('hex'));
    expect(serialized).not.toContain(formatRecoveryCode(code));
  });

  it('never puts an RMK in the file in the clear', () => {
    const { file } = exportRecovery({ repoId: REPO_ID, generations: [{ generation: 1, rmk: RMK1 }] });
    expect(JSON.stringify(file)).not.toContain(RMK1.toString('hex'));
  });
});

let dir: string;

describe('recoveryFilePath() / writeRecoveryFile() / readRecoveryFile()', () => {
  it('round-trips through disk', async () => {
    dir = await mkdtemp(join(tmpdir(), 'securegit-recovery-'));
    try {
      const { file } = exportRecovery({
        repoId: REPO_ID,
        generations: [{ generation: 1, rmk: Buffer.alloc(32, 0x11) }],
      });
      const path = recoveryFilePath(dir, 'proj.recovery.txt');
      await writeRecoveryFile(path, file);
      expect(await readRecoveryFile(path)).toEqual(file satisfies RecoveryFile);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe('recoveryLogPath() / appendRecoveryLogEntry() / readRecoveryLog()', () => {
  it('resolves to .securegit/recovery-log.json', () => {
    expect(recoveryLogPath('/repo')).toBe(join('/repo', '.securegit', 'recovery-log.json'));
  });

  it('records the event, not the code or file', async () => {
    dir = await mkdtemp(join(tmpdir(), 'securegit-recovery-log-'));
    try {
      const path = recoveryLogPath(dir);
      const entry = {
        exportId: generateExportId(),
        timestamp: new Date().toISOString(),
        exportedBy: '',
        generations: [1],
      };
      const log = await appendRecoveryLogEntry(path, entry);
      expect(log).toEqual([entry]);
      expect(await readRecoveryLog(path)).toEqual([entry]);

      const raw = await readFile(path, 'utf8');
      expect(raw).not.toMatch(/[0-9a-f]{64}/); // no 32-byte hex value anywhere (a code or RMK)
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('appends rather than overwriting', async () => {
    dir = await mkdtemp(join(tmpdir(), 'securegit-recovery-log-'));
    try {
      const path = recoveryLogPath(dir);
      const first = {
        exportId: generateExportId(),
        timestamp: new Date().toISOString(),
        exportedBy: '',
        generations: [1],
      };
      const second = {
        exportId: generateExportId(),
        timestamp: new Date().toISOString(),
        exportedBy: 'abc',
        generations: [1, 2],
      };
      await appendRecoveryLogEntry(path, first);
      const log = await appendRecoveryLogEntry(path, second);
      expect(log).toEqual([first, second]);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('reading a missing log returns an empty array, not an error', async () => {
    dir = await mkdtemp(join(tmpdir(), 'securegit-recovery-log-'));
    try {
      expect(await readRecoveryLog(recoveryLogPath(dir))).toEqual([]);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe('generateExportId()', () => {
  it('produces distinct ids', () => {
    expect(generateExportId()).not.toBe(generateExportId());
  });
});
