import { describe, it, expect } from 'vitest';
import { readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { seal, unseal, looksLikeEnvelope, parseEnvelope } from './envelope.js';
import type { KeySource } from './filter.js';
import { LockedError, MergeError, merge } from './merge.js';

const RMK = Buffer.alloc(32, 0xa5);
const OTHER_RMK = Buffer.alloc(32, 0x5a);
const KEY_ID = '3.a1b2c3d4e5f60718';
const OTHER_KEY_ID = '4.9f0c1a2b3c4d5e6f';
const PATH = 'config/production.json';

function unlocked(): KeySource {
  const held = new Map([[KEY_ID, RMK]]);
  return {
    current: () => ({ keyId: KEY_ID, rmk: RMK }),
    find: (keyId) => held.get(keyId) ?? null,
    available: () => [...held.keys()],
  };
}

function locked(): KeySource {
  return { current: () => null, find: () => null, available: () => [] };
}

/** Holds an OLD generation (can decrypt), but has no *current* generation to encrypt under. */
function readOnlyOldGeneration(): KeySource {
  const held = new Map([[KEY_ID, RMK]]);
  return {
    current: () => null,
    find: (keyId) => held.get(keyId) ?? null,
    available: () => [...held.keys()],
  };
}

function env(plaintext: string): Buffer {
  return seal(Buffer.from(plaintext), { rmk: RMK, keyId: KEY_ID, path: PATH });
}

function decrypt(output: Buffer): string {
  return unseal(output, { rmk: RMK, path: PATH }).toString('utf8');
}

// diff3 needs at least one unchanged line of context between two edits to
// treat them as separate, non-overlapping hunks — two changed lines with no
// context between them conflict even when the changes themselves don't.
const BASE = '{\n  "a": 1,\n  "x": true,\n  "y": true,\n  "b": 2\n}\n';
const OURS_NONCONFLICT = '{\n  "a": 10,\n  "x": true,\n  "y": true,\n  "b": 2\n}\n';
const THEIRS_NONCONFLICT = '{\n  "a": 1,\n  "x": true,\n  "y": true,\n  "b": 20\n}\n';
const MERGED_NONCONFLICT = '{\n  "a": 10,\n  "x": true,\n  "y": true,\n  "b": 20\n}\n';
const OURS_CONFLICT = '{\n  "a": 10,\n  "x": true,\n  "y": true,\n  "b": 2\n}\n';
const THEIRS_CONFLICT = '{\n  "a": 999,\n  "x": true,\n  "y": true,\n  "b": 2\n}\n';

describe('merge()', () => {
  it('resolves a non-overlapping three-way merge cleanly and re-encrypts the result', async () => {
    const result = await merge({
      keys: unlocked(),
      path: PATH,
      base: env(BASE),
      ours: env(OURS_NONCONFLICT),
      theirs: env(THEIRS_NONCONFLICT),
    });

    expect(result.clean).toBe(true);
    expect(decrypt(result.output)).toBe(MERGED_NONCONFLICT);
  });

  it('pads the re-encrypted result when padTo is given', async () => {
    const result = await merge({
      keys: unlocked(),
      path: PATH,
      base: env(BASE),
      ours: env(OURS_NONCONFLICT),
      theirs: env(THEIRS_NONCONFLICT),
      padTo: 64,
    });

    expect(parseEnvelope(result.output).padded).toBe(true);
    expect(decrypt(result.output)).toBe(MERGED_NONCONFLICT);
  });

  it('writes ciphertext to the result, never plaintext', async () => {
    const result = await merge({
      keys: unlocked(),
      path: PATH,
      base: env(BASE),
      ours: env(OURS_NONCONFLICT),
      theirs: env(THEIRS_NONCONFLICT),
    });

    expect(looksLikeEnvelope(result.output)).toBe(true);
    expect(result.output.includes(Buffer.from('"a": 10'))).toBe(false);
    const header = parseEnvelope(result.output);
    expect(header.keyId).toBe(KEY_ID);
  });

  it('reports a real conflict: clean is false and the result carries plaintext markers once decrypted', async () => {
    const result = await merge({
      keys: unlocked(),
      path: PATH,
      base: env(BASE),
      ours: env(OURS_CONFLICT),
      theirs: env(THEIRS_CONFLICT),
    });

    expect(result.clean).toBe(false);
    const plaintext = decrypt(result.output);
    expect(plaintext).toContain('<<<<<<<');
    expect(plaintext).toContain('=======');
    expect(plaintext).toContain('>>>>>>>');
  });

  it('handles a plaintext ancestor — a side that predates protection', async () => {
    const result = await merge({
      keys: unlocked(),
      path: PATH,
      base: Buffer.from(BASE), // never encrypted
      ours: env(OURS_NONCONFLICT),
      theirs: env(THEIRS_NONCONFLICT),
    });

    expect(result.clean).toBe(true);
    expect(decrypt(result.output)).toBe(MERGED_NONCONFLICT);
  });

  it('handles a plaintext side — committed without the filter installed', async () => {
    const result = await merge({
      keys: unlocked(),
      path: PATH,
      base: env(BASE),
      ours: Buffer.from(OURS_NONCONFLICT), // never encrypted
      theirs: env(THEIRS_NONCONFLICT),
    });

    expect(result.clean).toBe(true);
    expect(decrypt(result.output)).toBe(MERGED_NONCONFLICT);
  });

  it('fails closed rather than guessing when one side cannot be decrypted', async () => {
    const wrongGenEnvelope = seal(Buffer.from(OURS_NONCONFLICT), {
      rmk: OTHER_RMK,
      keyId: OTHER_KEY_ID,
      path: PATH,
    });

    await expect(
      merge({
        keys: unlocked(),
        path: PATH,
        base: env(BASE),
        ours: wrongGenEnvelope,
        theirs: env(THEIRS_NONCONFLICT),
      }),
    ).rejects.toThrow(MergeError);
  });

  it('fails closed with LockedError when there is no current generation to encrypt the result under', async () => {
    await expect(
      merge({
        keys: readOnlyOldGeneration(),
        path: PATH,
        base: env(BASE),
        ours: env(OURS_NONCONFLICT),
        theirs: env(THEIRS_NONCONFLICT),
      }),
    ).rejects.toThrow(LockedError);
  });

  it('fails closed entirely when locked, before ever writing anything to %A', async () => {
    await expect(
      merge({
        keys: locked(),
        path: PATH,
        base: env(BASE),
        ours: env(OURS_NONCONFLICT),
        theirs: env(THEIRS_NONCONFLICT),
      }),
    ).rejects.toThrow();
  });

  it('removes its temporary files on the error path', async () => {
    const before = (await readdir(tmpdir())).filter((n) => n.startsWith('securegit-merge-'));

    await expect(
      merge({
        keys: readOnlyOldGeneration(), // decrypts fine, but has no current generation
        path: PATH,
        base: env(BASE),
        ours: env(OURS_NONCONFLICT),
        theirs: env(THEIRS_NONCONFLICT),
      }),
    ).rejects.toThrow(LockedError);

    const after = (await readdir(tmpdir())).filter((n) => n.startsWith('securegit-merge-'));
    expect(after.length).toBe(before.length);
  });

  it('respects a custom marker size', async () => {
    const result = await merge({
      keys: unlocked(),
      path: PATH,
      markerSize: 20,
      base: env(BASE),
      ours: env(OURS_CONFLICT),
      theirs: env(THEIRS_CONFLICT),
    });

    const plaintext = decrypt(result.output);
    expect(plaintext).toContain('<'.repeat(20));
  });
});
