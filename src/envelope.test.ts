import { describe, it, expect } from 'vitest';
import { randomBytes } from 'node:crypto';
import {
  MAGIC, FORMAT_V1, ALG_AES256GCM_CONVERGENT, FLAG_BIND_PATH, FLAG_PADDED,
  HEADER_FIXED_LEN, OVERHEAD_MIN, DEFAULT_MAX_BYTES,
  EnvelopeError,
  looksLikeEnvelope, parseEnvelope, seal, unseal,
} from './envelope.js';

const RMK = Buffer.alloc(32, 0xa5);
const OTHER = Buffer.alloc(32, 0x5a);
const KEY_ID = '3.a1b2c3d4e5f60718';
const PATH = 'config/production.json';
const PT = Buffer.from('{"timeout":30}\n');

const sealed = (plaintext = PT, over: Partial<Parameters<typeof seal>[1]> = {}): Buffer =>
  seal(plaintext, { rmk: RMK, keyId: KEY_ID, path: PATH, ...over });

function flipBit(buf: Buffer, index: number): Buffer {
  const copy = Buffer.from(buf);
  copy.writeUInt8(copy.readUInt8(index) ^ 0x01, index);
  return copy;
}

describe('constants', () => {
  it('pin the wire format', () => {
    expect(MAGIC.length).toBe(11);
    expect(MAGIC.toString('binary')).toBe('\0SECUREGIT\0');
    expect(FORMAT_V1).toBe(1);
    expect(ALG_AES256GCM_CONVERGENT).toBe(1);
    expect(FLAG_BIND_PATH).toBe(0x01);
    expect(HEADER_FIXED_LEN).toBe(15);
    expect(OVERHEAD_MIN).toBe(63);
  });

  it('begins with NUL so Git classifies the blob as binary', () => {
    expect(MAGIC.readUInt8(0)).toBe(0);
  });
});

describe('seal()', () => {
  it('round-trips', () => {
    expect(unseal(sealed(), { rmk: RMK, path: PATH }).equals(PT)).toBe(true);
  });

  it('costs exactly 63 + keyId bytes of overhead', () => {
    expect(sealed().length).toBe(PT.length + OVERHEAD_MIN + KEY_ID.length);
  });

  it.each([0, 1, 15, 4095, 4096, 4097, 65_536])('round-trips %i bytes', (n) => {
    const pt = randomBytes(n);
    expect(unseal(sealed(pt), { rmk: RMK, path: PATH }).equals(pt)).toBe(true);
  });

  it('encrypts an empty file rather than passing it through', () => {
    const out = sealed(Buffer.alloc(0));
    expect(out.length).toBe(OVERHEAD_MIN + KEY_ID.length);
    expect(looksLikeEnvelope(out)).toBe(true);
  });

  it('is deterministic — the property Git depends on', () => {
    expect(sealed().equals(sealed())).toBe(true);
  });

  it('does not leak the plaintext into the ciphertext', () => {
    expect(sealed().includes(Buffer.from('timeout'))).toBe(false);
  });

  it('produces a different envelope for different content', () => {
    expect(sealed().equals(sealed(Buffer.from('{"timeout":60}\n')))).toBe(false);
  });

  it('produces a different envelope under a different master key', () => {
    expect(sealed().equals(seal(PT, { rmk: OTHER, keyId: KEY_ID, path: PATH }))).toBe(false);
  });

  it('encrypts plaintext that happens to begin with the magic', () => {
    const evil = Buffer.concat([MAGIC, Buffer.from('not really an envelope')]);
    const out = sealed(evil);
    expect(out.equals(evil)).toBe(false);
    expect(unseal(out, { rmk: RMK, path: PATH }).equals(evil)).toBe(true);
  });

  it('rejects an empty keyId', () => {
    expect(() => seal(PT, { rmk: RMK, keyId: '', path: PATH })).toThrow(/keyId/i);
  });

  it('rejects a keyId longer than 64 bytes', () => {
    expect(() => seal(PT, { rmk: RMK, keyId: 'x'.repeat(65), path: PATH })).toThrow(/keyId/i);
  });

  it('rejects a non-ASCII keyId, which would not survive the length byte', () => {
    expect(() => seal(PT, { rmk: RMK, keyId: 'gen-ü', path: PATH })).toThrow(/keyId/i);
  });

  it('rejects input above the size limit before doing any work', () => {
    expect(() => seal(randomBytes(2048), { rmk: RMK, keyId: KEY_ID, path: PATH, maxBytes: 1024 }))
      .toThrow(/too large|2048|limit/i);
  });

  it('defaults the size limit to 512 MiB', () => {
    expect(DEFAULT_MAX_BYTES).toBe(512 * 1024 * 1024);
  });
});

describe('path binding', () => {
  it('ignores the path by default, so a moved file keeps its blob', () => {
    const a = seal(PT, { rmk: RMK, keyId: KEY_ID, path: 'config/staging.json' });
    const b = seal(PT, { rmk: RMK, keyId: KEY_ID, path: 'config/production.json' });
    expect(a.equals(b)).toBe(true);
  });

  it('decrypts under any path when unbound', () => {
    const out = seal(PT, { rmk: RMK, keyId: KEY_ID, path: 'config/staging.json' });
    expect(unseal(out, { rmk: RMK, path: 'somewhere/else.json' }).equals(PT)).toBe(true);
  });

  it('binds the path when asked, so identical content differs by location', () => {
    const a = seal(PT, { rmk: RMK, keyId: KEY_ID, path: 'config/staging.json', bindPath: true });
    const b = seal(PT, { rmk: RMK, keyId: KEY_ID, path: 'config/production.json', bindPath: true });
    expect(a.equals(b)).toBe(false);
  });

  it('records bindPath in the flags byte', () => {
    expect(parseEnvelope(sealed()).bindPath).toBe(false);
    expect(parseEnvelope(sealed(PT, { bindPath: true })).bindPath).toBe(true);
  });

  it('refuses to decrypt a bound envelope at another path — the relocation defence', () => {
    const out = seal(PT, { rmk: RMK, keyId: KEY_ID, path: 'config/staging.json', bindPath: true });
    expect(() => unseal(out, { rmk: RMK, path: 'config/production.json' })).toThrow();
    expect(unseal(out, { rmk: RMK, path: 'config/staging.json' }).equals(PT)).toBe(true);
  });

  it('treats POSIX and Windows spellings of a bound path as the same path', () => {
    const out = seal(PT, { rmk: RMK, keyId: KEY_ID, path: 'config/production.json', bindPath: true });
    expect(unseal(out, { rmk: RMK, path: 'config\\production.json' }).equals(PT)).toBe(true);
  });
});

describe('padding', () => {
  it('is disabled by default — ciphertext length is unaffected, no flag set', () => {
    const withoutOpt = seal(PT, { rmk: RMK, keyId: KEY_ID, path: PATH });
    const withZero = seal(PT, { rmk: RMK, keyId: KEY_ID, path: PATH, padTo: 0 });
    expect(withoutOpt.length).toBe(withZero.length);
    expect(parseEnvelope(withoutOpt).padded).toBe(false);
    expect(FLAG_PADDED).toBe(0x02);
  });

  it('round-trips exactly and sets the padded flag when padTo is used', () => {
    const out = seal(PT, { rmk: RMK, keyId: KEY_ID, path: PATH, padTo: 64 });
    expect(parseEnvelope(out).padded).toBe(true);
    expect(unseal(out, { rmk: RMK, path: PATH }).equals(PT)).toBe(true);
  });

  it('round-trips exactly including trailing NULs in the original content', () => {
    // A naive "trim trailing zero bytes" unpad would corrupt this; the
    // length prefix this scheme uses instead cannot.
    const withTrailingNuls = Buffer.concat([PT, Buffer.alloc(5)]);
    const out = seal(withTrailingNuls, { rmk: RMK, keyId: KEY_ID, path: PATH, padTo: 64 });
    const decrypted = unseal(out, { rmk: RMK, path: PATH });
    expect(decrypted.length).toBe(withTrailingNuls.length);
    expect(decrypted.equals(withTrailingNuls)).toBe(true);
  });

  it('files under padTo all yield the same ciphertext length', () => {
    const small = Buffer.from('x');
    const medium = Buffer.from('x'.repeat(100));
    const a = seal(small, { rmk: RMK, keyId: KEY_ID, path: PATH, padTo: 4096 });
    const b = seal(medium, { rmk: RMK, keyId: KEY_ID, path: PATH, padTo: 4096 });
    expect(a.length).toBe(b.length);
  });

  it('a file above padTo rounds up to the next multiple', () => {
    const overOneBucket = Buffer.alloc(4100, 0x41);
    const out = seal(overOneBucket, { rmk: RMK, keyId: KEY_ID, path: PATH, padTo: 4096 });
    expect(unseal(out, { rmk: RMK, path: PATH }).equals(overOneBucket)).toBe(true);

    const withinOneBucket = seal(Buffer.from('x'), { rmk: RMK, keyId: KEY_ID, path: PATH, padTo: 4096 });
    expect(out.length).toBeGreaterThan(withinOneBucket.length);
  });

  it('is deterministic: same plaintext and padTo always produce the same ciphertext', () => {
    const a = seal(PT, { rmk: RMK, keyId: KEY_ID, path: PATH, padTo: 64 });
    const b = seal(PT, { rmk: RMK, keyId: KEY_ID, path: PATH, padTo: 64 });
    expect(a.equals(b)).toBe(true);
  });

  it('a different padTo for the same plaintext yields a different ciphertext', () => {
    const a = seal(PT, { rmk: RMK, keyId: KEY_ID, path: PATH, padTo: 64 });
    const b = seal(PT, { rmk: RMK, keyId: KEY_ID, path: PATH, padTo: 128 });
    expect(a.equals(b)).toBe(false);
  });

  it('a bit flip anywhere in a padded envelope still fails authentication', () => {
    const out = seal(PT, { rmk: RMK, keyId: KEY_ID, path: PATH, padTo: 64 });
    expect(() => unseal(flipBit(out, out.length - 1), { rmk: RMK, path: PATH })).toThrow();
  });
});

describe('looksLikeEnvelope()', () => {
  it('recognises the magic', () => {
    expect(looksLikeEnvelope(sealed())).toBe(true);
  });

  it('rejects plaintext', () => {
    expect(looksLikeEnvelope(PT)).toBe(false);
  });

  it('rejects a buffer shorter than the magic', () => {
    expect(looksLikeEnvelope(Buffer.alloc(4))).toBe(false);
    expect(looksLikeEnvelope(Buffer.alloc(0))).toBe(false);
  });

  it('is a magic check only — it says nothing about authenticity', () => {
    // This is exactly why `clean` must authenticate before passing through.
    const forged = Buffer.concat([MAGIC, Buffer.from('not really an envelope')]);
    expect(looksLikeEnvelope(forged)).toBe(true);
    expect(() => parseEnvelope(forged)).toThrow();
  });
});

describe('parseEnvelope()', () => {
  it('reads every header field without a key', () => {
    const h = parseEnvelope(sealed());
    expect(h.format).toBe(FORMAT_V1);
    expect(h.algorithm).toBe(ALG_AES256GCM_CONVERGENT);
    expect(h.bindPath).toBe(false);
    expect(h.keyId).toBe(KEY_ID);
    expect(h.tag.length).toBe(32);
    expect(h.authTag.length).toBe(16);
    expect(h.ciphertext.length).toBe(PT.length);
    expect(h.headerLength).toBe(HEADER_FIXED_LEN + KEY_ID.length);
  });

  it('rejects a buffer without the magic', () => {
    expect(() => parseEnvelope(PT)).toThrow(/not a securegit envelope/i);
  });

  it('rejects an unknown format rather than guessing', () => {
    const bad = Buffer.from(sealed());
    bad.writeUInt8(2, 11);
    expect(() => parseEnvelope(bad)).toThrow(/format/i);
  });

  it('names the observed format in the error', () => {
    const bad = Buffer.from(sealed());
    bad.writeUInt8(9, 11);
    expect(() => parseEnvelope(bad)).toThrow(/9/);
  });

  it('rejects an unknown algorithm', () => {
    const bad = Buffer.from(sealed());
    bad.writeUInt8(0x7f, 12);
    expect(() => parseEnvelope(bad)).toThrow(/algorithm/i);
  });

  it('rejects a set reserved flag bit', () => {
    // 0x04 — not FLAG_BIND_PATH (0x01) or FLAG_PADDED (0x02), still reserved.
    const bad = Buffer.from(sealed());
    bad.writeUInt8(0x04, 13);
    expect(() => parseEnvelope(bad)).toThrow(/reserved/i);
  });

  it('rejects a zero-length keyId', () => {
    const bad = Buffer.from(sealed());
    bad.writeUInt8(0, 14);
    expect(() => parseEnvelope(bad)).toThrow(/keyId/i);
  });

  it('rejects a keyId length that runs past the buffer', () => {
    const bad = Buffer.from(sealed());
    bad.writeUInt8(200, 14);
    expect(() => parseEnvelope(bad)).toThrow(/truncated|short/i);
  });

  it('rejects an envelope truncated below the header minimum, naming both lengths', () => {
    // keyId is 18 bytes, so the minimum is 15 + 18 + 32 + 16 = 81.
    const bad = sealed().subarray(0, 70);
    expect(() => parseEnvelope(bad)).toThrow(/70/);
    expect(() => parseEnvelope(bad)).toThrow(/81/);
  });

  it('rejects a buffer holding only the magic', () => {
    expect(() => parseEnvelope(Buffer.from(MAGIC))).toThrow(/truncated|short/i);
  });

  it('throws EnvelopeError, so callers can map it to exit code 3', () => {
    try {
      parseEnvelope(PT);
      expect.unreachable('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(EnvelopeError);
      expect((e as EnvelopeError).code).toBe('ENVELOPE');
    }
  });
});

describe('unseal()', () => {
  it('fails under the wrong master key', () => {
    expect(() => unseal(sealed(), { rmk: OTHER, path: PATH })).toThrow(/authentication/i);
  });

  it('fails if any single byte of the envelope is flipped', () => {
    const out = sealed();
    for (let i = 0; i < out.length; i++) {
      expect(() => unseal(flipBit(out, i), { rmk: RMK, path: PATH })).toThrow();
    }
  });

  it('authenticates the keyId, so a generation cannot be renumbered', () => {
    const out = sealed();
    const bad = Buffer.from(out);
    bad.write('4', HEADER_FIXED_LEN, 1, 'ascii');
    expect(() => unseal(bad, { rmk: RMK, path: PATH })).toThrow(/authentication/i);
  });

  it('refuses a declared size above the limit', () => {
    const out = sealed(randomBytes(2048));
    expect(() => unseal(out, { rmk: RMK, path: PATH, maxBytes: 1024 })).toThrow(/too large|limit/i);
  });

  it('catches ciphertext truncation, which the header cannot detect', () => {
    // The format carries no length field, so a short ciphertext parses
    // cleanly. Only the GCM tag reveals it — which is why `smudge` must never
    // emit unauthenticated bytes.
    const full = sealed();
    const short = full.subarray(0, full.length - 5);
    expect(() => parseEnvelope(short)).not.toThrow();
    expect(() => unseal(short, { rmk: RMK, path: PATH })).toThrow(/authentication/i);
  });

  it('never puts plaintext or key material in an error message', () => {
    try {
      unseal(sealed(), { rmk: OTHER, path: PATH });
      expect.unreachable('should have thrown');
    } catch (e) {
      const message = (e as Error).message;
      expect(message).not.toContain('timeout');
      expect(message).not.toContain(OTHER.toString('hex'));
    }
  });
});

describe('cross-machine stability', () => {
  it('produces byte-identical envelopes for the same inputs, repeatedly', () => {
    const first = sealed();
    for (let i = 0; i < 50; i++) expect(sealed().equals(first)).toBe(true);
  });

  it('holds for random binary content at random sizes', () => {
    for (let i = 0; i < 25; i++) {
      const pt = randomBytes(Math.floor(Math.random() * 8192));
      const a = sealed(pt);
      expect(a.equals(sealed(pt))).toBe(true);
      expect(unseal(a, { rmk: RMK, path: PATH }).equals(pt)).toBe(true);
    }
  });
});
