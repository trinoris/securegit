// Known-answer vectors: bytes frozen once, reviewed, and never regenerated.
//
// Everything else in this package tests "does the current implementation
// round-trip its own output" — which stays true even if a derivation label,
// a byte offset, or the HKDF wiring silently changes, as long as both sides
// of the test change together. These fixtures are the one place that would
// notice: they were produced once, by src/envelope.ts as it existed when
// this file was written, and are compared byte-for-byte against whatever
// the current build produces. A failure here means the wire format moved,
// not that a test assumption drifted — see specs/securegit/03-determinism.md
// and 04-envelope-format.md.

import { describe, it, expect } from 'vitest';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { seal, unseal } from './envelope.js';
import { deriveTagKey, contentTag, deriveFileKey } from './crypto.js';

const FIXTURES = join(import.meta.dirname, '..', 'tests', 'fixtures');

interface VectorCase {
  name: string;
  rmk: string;
  path: string;
  keyId: string;
  bindPath: boolean;
  plaintext: string;
  envelope: string;
}

interface HkdfVector {
  rmk: string;
  path: string;
  plaintext: string;
  tagKey: string;
  tag: string;
  dekBoundToPath: string;
}

interface VectorFile {
  algorithm: number;
  hkdf: HkdfVector;
  cases: VectorCase[];
}

async function loadVectors(): Promise<VectorFile> {
  const raw = await readFile(join(FIXTURES, 'vectors', 'v1.json'), 'utf8');
  return JSON.parse(raw) as VectorFile;
}

describe('known-answer vectors (tests/fixtures/vectors/v1.json)', () => {
  it('the fixture file has the six documented cases', async () => {
    const vectors = await loadVectors();
    expect(vectors.algorithm).toBe(1);
    expect(vectors.cases.map((c) => c.name)).toEqual([
      'empty',
      'one byte',
      '4095 bytes',
      'utf8 bom',
      'crlf content',
      'bindPath',
    ]);
  });

  it('sealing each case with the committed inputs reproduces the committed envelope byte-for-byte', async () => {
    const vectors = await loadVectors();
    for (const c of vectors.cases) {
      const out = seal(Buffer.from(c.plaintext, 'hex'), {
        rmk: Buffer.from(c.rmk, 'hex'),
        keyId: c.keyId,
        path: c.path,
        bindPath: c.bindPath,
      });
      expect(out.toString('hex'), `case "${c.name}"`).toBe(c.envelope);
    }
  });

  it('unsealing each committed envelope reproduces the committed plaintext byte-for-byte', async () => {
    const vectors = await loadVectors();
    for (const c of vectors.cases) {
      const out = unseal(Buffer.from(c.envelope, 'hex'), {
        rmk: Buffer.from(c.rmk, 'hex'),
        path: c.path,
      });
      expect(out.toString('hex'), `case "${c.name}"`).toBe(c.plaintext);
    }
  });

  it('the bindPath case actually has the flag set, and fails to decrypt under a different path', async () => {
    const vectors = await loadVectors();
    const c = vectors.cases.find((v) => v.name === 'bindPath')!;
    expect(c.bindPath).toBe(true);
    expect(() =>
      unseal(Buffer.from(c.envelope, 'hex'), {
        rmk: Buffer.from(c.rmk, 'hex'),
        path: 'a-different/path.txt',
      }),
    ).toThrow();
  });
});

describe('HKDF labels match the committed vectors', () => {
  // Pins securegit/tag/v1 and securegit/dek/v1 directly, independent of the
  // envelope round-trip above — a rename of either label would still
  // produce a self-consistent envelope (seal and unseal share the same
  // labels), so this is the test that actually notices.
  it('deriveTagKey / contentTag / deriveFileKey reproduce the frozen hex', async () => {
    const { hkdf } = await loadVectors();
    const rmk = Buffer.from(hkdf.rmk, 'hex');
    const plaintext = Buffer.from(hkdf.plaintext, 'hex');

    const tagKey = deriveTagKey(rmk);
    expect(tagKey.toString('hex')).toBe(hkdf.tagKey);

    const tag = contentTag(tagKey, plaintext, null);
    expect(tag.toString('hex')).toBe(hkdf.tag);

    const dek = deriveFileKey(rmk, tag, hkdf.path);
    expect(dek.toString('hex')).toBe(hkdf.dekBoundToPath);
  });
});

describe('committed v1 envelopes still decrypt (tests/fixtures/envelopes/)', () => {
  // The rmk/path/keyId below are not secrets — they're the known answer that
  // makes the committed .bin file meaningful. Changing them would just be
  // testing a different envelope, not this one.
  it('v1-basic.bin decrypts to its frozen plaintext', async () => {
    const envelope = await readFile(join(FIXTURES, 'envelopes', 'v1-basic.bin'));
    const rmk = Buffer.from('c3'.repeat(32), 'hex');
    const out = unseal(envelope, { rmk, path: 'envelopes/basic.txt' });
    expect(out.toString('utf8')).toBe('the canonical v1 envelope\n');
  });

  it('v1-bindpath.bin decrypts to its frozen plaintext, and only under its bound path', async () => {
    const envelope = await readFile(join(FIXTURES, 'envelopes', 'v1-bindpath.bin'));
    const rmk = Buffer.from('d4'.repeat(32), 'hex');
    const out = unseal(envelope, { rmk, path: 'envelopes/bound.txt' });
    expect(out.toString('utf8')).toBe('the canonical v1 bound envelope\n');
    expect(() => unseal(envelope, { rmk, path: 'somewhere/else.txt' })).toThrow();
  });
});
