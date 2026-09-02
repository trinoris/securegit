import { describe, it, expect } from 'vitest';
import { randomBytes, createHash } from 'node:crypto';
import { inspect } from 'node:util';
import {
  KEY_LEN, NONCE_LEN, TAG_LEN,
  secret, isSecret,
  normalizePath,
  deriveTagKey, contentTag, deriveFileKey, keyFingerprint,
  aeadEncrypt, aeadDecrypt,
  equalCt,
} from './crypto.js';

const RMK = Buffer.alloc(32, 0xa5);
const OTHER = Buffer.alloc(32, 0x5a);
const PT = Buffer.from('{"timeout":30}\n');

/** A copy of `buf` with the low bit of byte `index` flipped. */
function flipBit(buf: Buffer, index: number): Buffer {
  const copy = Buffer.from(buf);
  copy.writeUInt8(copy.readUInt8(index) ^ 0x01, index);
  return copy;
}

describe('constants', () => {
  it('are the AES-256-GCM sizes', () => {
    expect(KEY_LEN).toBe(32);
    expect(NONCE_LEN).toBe(12);
    expect(TAG_LEN).toBe(16);
  });
});

describe('secret()', () => {
  it('redacts on bare toString, so interpolation cannot leak a key', () => {
    const k = secret(RMK);
    expect(`${k}`).toBe('[redacted]');
    expect(String(k)).toBe('[redacted]');
    expect(k.toString()).toBe('[redacted]');
  });

  it('redacts under JSON.stringify', () => {
    expect(JSON.stringify({ k: secret(RMK) })).toBe('{"k":"[redacted]"}');
  });

  it('redacts under console/util inspection', () => {
    expect(inspect(secret(RMK))).toBe('[redacted]');
  });

  it('still yields real bytes when an encoding is asked for explicitly', () => {
    expect(secret(RMK).toString('hex')).toBe(RMK.toString('hex'));
  });

  it('is still a Buffer, usable directly by node:crypto', () => {
    const k = secret(RMK);
    expect(Buffer.isBuffer(k)).toBe(true);
    expect(k.length).toBe(32);
    expect(k.equals(RMK)).toBe(true);
    expect(isSecret(k)).toBe(true);
  });

  it('does not mutate the buffer it was given', () => {
    const source = Buffer.alloc(32, 0x11);
    const k = secret(source);
    expect(isSecret(source)).toBe(false);
    expect(`${source}`).not.toBe('[redacted]');
    expect(k).not.toBe(source);
  });

  it('copies, so a later mutation of the source cannot change the key', () => {
    const source = Buffer.alloc(32, 0x11);
    const k = secret(source);
    source.fill(0xff);
    expect(k.toString('hex')).toBe('11'.repeat(32));
  });

  it('is idempotent', () => {
    const k = secret(RMK);
    expect(isSecret(secret(k))).toBe(true);
    expect(secret(k).toString('hex')).toBe(RMK.toString('hex'));
  });
});

describe('normalizePath()', () => {
  it('is a no-op for POSIX paths', () => {
    expect(normalizePath('config/production.json')).toBe('config/production.json');
  });

  it('folds Windows separators, so both platforms derive the same key', () => {
    expect(normalizePath('config\\production.json')).toBe('config/production.json');
  });

  it('strips a leading ./ and collapses repeated separators', () => {
    expect(normalizePath('./config//production.json')).toBe('config/production.json');
  });

  it('returns bytes-comparable UTF-8 for non-ASCII paths', () => {
    expect(normalizePath('config/prodüktion.json')).toBe('config/prodüktion.json');
  });

  it('maps null and undefined to null, meaning "unbound"', () => {
    expect(normalizePath(null)).toBeNull();
    expect(normalizePath(undefined)).toBeNull();
  });
});

describe('deriveTagKey()', () => {
  it('is 32 bytes and deterministic', () => {
    const a = deriveTagKey(RMK);
    const b = deriveTagKey(RMK);
    expect(a.length).toBe(32);
    expect(a.equals(b)).toBe(true);
  });

  it('differs for a different master key', () => {
    expect(deriveTagKey(RMK).equals(deriveTagKey(OTHER))).toBe(false);
  });

  it('is not the master key', () => {
    expect(deriveTagKey(RMK).equals(RMK)).toBe(false);
  });

  it('returns a redacting secret', () => {
    expect(`${deriveTagKey(RMK)}`).toBe('[redacted]');
  });

  it('rejects a master key of the wrong length', () => {
    expect(() => deriveTagKey(Buffer.alloc(16))).toThrow(/master key/i);
  });
});

describe('contentTag()', () => {
  const K = deriveTagKey(RMK);

  it('is 32 bytes and deterministic', () => {
    expect(contentTag(K, PT, null).length).toBe(32);
    expect(contentTag(K, PT, null).equals(contentTag(K, PT, null))).toBe(true);
  });

  it('changes completely when one plaintext bit changes', () => {
    const other = flipBit(PT, 0);
    const a = contentTag(K, PT, null);
    const b = contentTag(K, other, null);
    expect(a.equals(b)).toBe(false);
    let differing = 0;
    for (let i = 0; i < 32; i++) if (a.readUInt8(i) !== b.readUInt8(i)) differing++;
    expect(differing).toBeGreaterThan(24);
  });

  it('binds the path when one is given', () => {
    const a = contentTag(K, PT, 'config/staging.json');
    const b = contentTag(K, PT, 'config/production.json');
    expect(a.equals(b)).toBe(false);
  });

  it('ignores the path when unbound', () => {
    expect(contentTag(K, PT, null).equals(contentTag(K, PT, null))).toBe(true);
  });

  it('derives the same tag from POSIX and Windows spellings of a path', () => {
    const a = contentTag(K, PT, 'config/production.json');
    const b = contentTag(K, PT, 'config\\production.json');
    expect(a.equals(b)).toBe(true);
  });

  it('cannot be forged by appending the path to the content', () => {
    // The 0x00 separator makes (path, content) unambiguous.
    const a = contentTag(K, PT, 'ab');
    const b = contentTag(K, Buffer.concat([Buffer.from('b'), PT]), 'a');
    expect(a.equals(b)).toBe(false);
  });

  it('differs under a different tag key', () => {
    const a = contentTag(K, PT, null);
    const b = contentTag(deriveTagKey(OTHER), PT, null);
    expect(a.equals(b)).toBe(false);
  });

  it('handles empty plaintext', () => {
    expect(contentTag(K, Buffer.alloc(0), null).length).toBe(32);
  });

  it('is not a plain unkeyed hash of the content', () => {
    // Confirmation-of-file resistance: without K_tag the tag is unreachable.
    const naive = createHash('sha256').update(PT).digest();
    expect(contentTag(K, PT, null).equals(naive)).toBe(false);
  });
});

describe('deriveFileKey()', () => {
  const K = deriveTagKey(RMK);
  const tag = contentTag(K, PT, null);

  it('is 32 bytes, deterministic, and redacting', () => {
    const k = deriveFileKey(RMK, tag, null);
    expect(k.length).toBe(32);
    expect(k.equals(deriveFileKey(RMK, tag, null))).toBe(true);
    expect(`${k}`).toBe('[redacted]');
  });

  it('is unrelated to the tag it was derived from', () => {
    expect(deriveFileKey(RMK, tag, null).equals(tag)).toBe(false);
  });

  it('is unrelated to the master key', () => {
    expect(deriveFileKey(RMK, tag, null).equals(RMK)).toBe(false);
  });

  it('differs for different content, which is what makes the nonce safe', () => {
    const tagB = contentTag(K, Buffer.from('{"timeout":60}\n'), null);
    expect(deriveFileKey(RMK, tag, null).equals(deriveFileKey(RMK, tagB, null))).toBe(false);
  });

  it('differs under a different master key', () => {
    expect(deriveFileKey(RMK, tag, null).equals(deriveFileKey(OTHER, tag, null))).toBe(false);
  });

  it('binds the path when one is given', () => {
    const a = deriveFileKey(RMK, tag, 'config/staging.json');
    const b = deriveFileKey(RMK, tag, 'config/production.json');
    expect(a.equals(b)).toBe(false);
  });

  it('rejects a content tag of the wrong length', () => {
    expect(() => deriveFileKey(RMK, Buffer.alloc(16), null)).toThrow(/content tag/i);
  });
});

describe('keyFingerprint()', () => {
  it('is 16 lowercase hex characters and deterministic', () => {
    const f = keyFingerprint(RMK);
    expect(f).toMatch(/^[0-9a-f]{16}$/);
    expect(f).toBe(keyFingerprint(RMK));
  });

  it('differs for a different key', () => {
    expect(keyFingerprint(RMK)).not.toBe(keyFingerprint(OTHER));
  });

  it('does not reveal the key', () => {
    expect(RMK.toString('hex')).not.toContain(keyFingerprint(RMK));
  });
});

describe('aeadEncrypt / aeadDecrypt', () => {
  const key = deriveFileKey(RMK, contentTag(deriveTagKey(RMK), PT, null), null);
  const nonce = Buffer.alloc(12, 7);
  const aad = Buffer.from('header');

  it('round-trips', () => {
    const { ciphertext, authTag } = aeadEncrypt(key, nonce, PT, aad);
    expect(authTag.length).toBe(16);
    expect(aeadDecrypt(key, nonce, ciphertext, authTag, aad).equals(PT)).toBe(true);
  });

  it('preserves plaintext length', () => {
    expect(aeadEncrypt(key, nonce, PT, aad).ciphertext.length).toBe(PT.length);
  });

  it('round-trips empty plaintext', () => {
    const { ciphertext, authTag } = aeadEncrypt(key, nonce, Buffer.alloc(0), aad);
    expect(ciphertext.length).toBe(0);
    expect(aeadDecrypt(key, nonce, ciphertext, authTag, aad).length).toBe(0);
  });

  it('is deterministic for fixed inputs', () => {
    const a = aeadEncrypt(key, nonce, PT, aad);
    const b = aeadEncrypt(key, nonce, PT, aad);
    expect(a.ciphertext.equals(b.ciphertext)).toBe(true);
    expect(a.authTag.equals(b.authTag)).toBe(true);
  });

  it('does not resemble the plaintext', () => {
    const { ciphertext } = aeadEncrypt(key, nonce, PT, aad);
    expect(ciphertext.equals(PT)).toBe(false);
    expect(ciphertext.includes(Buffer.from('timeout'))).toBe(false);
  });

  it('fails under a wrong key', () => {
    const { ciphertext, authTag } = aeadEncrypt(key, nonce, PT, aad);
    expect(() => aeadDecrypt(OTHER, nonce, ciphertext, authTag, aad)).toThrow();
  });

  it('fails under a wrong nonce', () => {
    const { ciphertext, authTag } = aeadEncrypt(key, nonce, PT, aad);
    expect(() => aeadDecrypt(key, Buffer.alloc(12, 8), ciphertext, authTag, aad)).toThrow();
  });

  it('fails under a wrong AAD', () => {
    const { ciphertext, authTag } = aeadEncrypt(key, nonce, PT, aad);
    expect(() => aeadDecrypt(key, nonce, ciphertext, authTag, Buffer.from('other'))).toThrow();
  });

  it('fails on any flipped ciphertext byte', () => {
    const { ciphertext, authTag } = aeadEncrypt(key, nonce, PT, aad);
    for (let i = 0; i < ciphertext.length; i++) {
      expect(() => aeadDecrypt(key, nonce, flipBit(ciphertext, i), authTag, aad)).toThrow();
    }
  });

  it('fails on a flipped auth tag byte', () => {
    const { ciphertext, authTag } = aeadEncrypt(key, nonce, PT, aad);
    expect(() => aeadDecrypt(key, nonce, ciphertext, flipBit(authTag, 0), aad)).toThrow();
  });

  it('rejects a key of the wrong length rather than padding it', () => {
    expect(() => aeadEncrypt(Buffer.alloc(16), nonce, PT, aad)).toThrow(/key/i);
  });

  it('rejects a nonce of the wrong length', () => {
    expect(() => aeadEncrypt(key, Buffer.alloc(8), PT, aad)).toThrow(/nonce/i);
  });

  it('rejects an auth tag of the wrong length', () => {
    const { ciphertext } = aeadEncrypt(key, nonce, PT, aad);
    expect(() => aeadDecrypt(key, nonce, ciphertext, Buffer.alloc(8), aad)).toThrow(/tag/i);
  });

  it('never puts key material or content in its error messages', () => {
    const { ciphertext, authTag } = aeadEncrypt(key, nonce, PT, aad);
    try {
      aeadDecrypt(OTHER, nonce, ciphertext, authTag, aad);
      expect.unreachable('should have thrown');
    } catch (e) {
      const message = (e as Error).message;
      expect(message).not.toContain(OTHER.toString('hex'));
      expect(message).not.toContain('timeout');
    }
  });
});

describe('equalCt()', () => {
  it('compares equal buffers', () => {
    expect(equalCt(Buffer.from('abc'), Buffer.from('abc'))).toBe(true);
  });

  it('rejects different buffers', () => {
    expect(equalCt(Buffer.from('abc'), Buffer.from('abd'))).toBe(false);
  });

  it('rejects different lengths without throwing', () => {
    expect(equalCt(Buffer.from('abc'), Buffer.from('ab'))).toBe(false);
  });

  it('compares empty buffers as equal', () => {
    expect(equalCt(Buffer.alloc(0), Buffer.alloc(0))).toBe(true);
  });
});

describe('end-to-end determinism (the property the whole design exists for)', () => {
  it('encrypting the same content twice yields identical bytes', () => {
    const run = (): Buffer => {
      const tag = contentTag(deriveTagKey(RMK), PT, null);
      const key = deriveFileKey(RMK, tag, null);
      const { ciphertext, authTag } = aeadEncrypt(key, tag.subarray(0, NONCE_LEN), PT, Buffer.from('h'));
      return Buffer.concat([tag, authTag, ciphertext]);
    };
    expect(run().equals(run())).toBe(true);
  });

  it('gives different content a different key AND a different nonce', () => {
    const K = deriveTagKey(RMK);
    const a = contentTag(K, PT, null);
    const b = contentTag(K, Buffer.from('{"timeout":60}\n'), null);
    expect(a.subarray(0, NONCE_LEN).equals(b.subarray(0, NONCE_LEN))).toBe(false);
    expect(deriveFileKey(RMK, a, null).equals(deriveFileKey(RMK, b, null))).toBe(false);
  });

  it('never reuses a (key, nonce) pair across 500 distinct plaintexts', () => {
    const K = deriveTagKey(RMK);
    const seen = new Set<string>();
    for (let i = 0; i < 500; i++) {
      const pt = Buffer.from(`secret value ${i}\n`);
      const tag = contentTag(K, pt, null);
      const pair = `${deriveFileKey(RMK, tag, null).toString('hex')}:${tag.subarray(0, NONCE_LEN).toString('hex')}`;
      expect(seen.has(pair)).toBe(false);
      seen.add(pair);
    }
  });

  it('holds for random binary content', () => {
    const K = deriveTagKey(RMK);
    for (let i = 0; i < 20; i++) {
      const pt = randomBytes(1 + Math.floor(Math.random() * 4096));
      expect(contentTag(K, pt, null).equals(contentTag(K, Buffer.from(pt), null))).toBe(true);
    }
  });
});
