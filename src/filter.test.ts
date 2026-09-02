import { describe, it, expect, vi } from 'vitest';
import { randomBytes } from 'node:crypto';
import { MAGIC, seal, parseEnvelope, looksLikeEnvelope } from './envelope.js';
import {
  LockedError,
  clean, smudge, textconv,
  type KeySource, type FilterContext,
} from './filter.js';

const RMK3 = Buffer.alloc(32, 0xa5);
const RMK2 = Buffer.alloc(32, 0x33);
const OTHER = Buffer.alloc(32, 0x5a);
const KEY_ID_3 = '3.a1b2c3d4e5f60718';
const KEY_ID_2 = '2.b30f92ac1e7d4405';
const PATH = 'config/production.json';
const PT = Buffer.from('{"timeout":30}\n');

/** An unlocked keyring holding generations 2 and 3, current 3. */
function unlocked(): KeySource {
  const held = new Map([[KEY_ID_3, RMK3], [KEY_ID_2, RMK2]]);
  return {
    current: () => ({ keyId: KEY_ID_3, rmk: RMK3 }),
    find: (keyId) => held.get(keyId) ?? null,
    available: () => [...held.keys()],
  };
}

/** A locked keyring: knows which generations exist, holds none of them. */
function locked(): KeySource {
  return {
    current: () => null,
    find: () => null,
    available: () => [],
  };
}

/** Unlocked, but missing the generation an envelope asks for. */
function partial(): KeySource {
  return {
    current: () => ({ keyId: KEY_ID_2, rmk: RMK2 }),
    find: (keyId) => (keyId === KEY_ID_2 ? RMK2 : null),
    available: () => [KEY_ID_2],
  };
}

function ctx(over: Partial<FilterContext> = {}): FilterContext {
  return { keys: unlocked(), path: PATH, ...over };
}

const envelope3 = seal(PT, { rmk: RMK3, keyId: KEY_ID_3, path: PATH });
const envelope2 = seal(PT, { rmk: RMK2, keyId: KEY_ID_2, path: PATH });

describe('clean()', () => {
  it('encrypts plaintext under the current generation', () => {
    const out = clean(PT, ctx());
    expect(looksLikeEnvelope(out)).toBe(true);
    expect(parseEnvelope(out).keyId).toBe(KEY_ID_3);
  });

  it('is deterministic', () => {
    expect(clean(PT, ctx()).equals(clean(PT, ctx()))).toBe(true);
  });

  it('encrypts an empty file rather than passing it through', () => {
    expect(looksLikeEnvelope(clean(Buffer.alloc(0), ctx()))).toBe(true);
  });

  it('round-trips through smudge for random binary content', () => {
    for (let i = 0; i < 20; i++) {
      const pt = randomBytes(Math.floor(Math.random() * 4096));
      expect(smudge(clean(pt, ctx()), ctx()).equals(pt)).toBe(true);
    }
  });

  it('is idempotent — cleaning its own output changes nothing', () => {
    const once = clean(PT, ctx());
    expect(clean(once, ctx()).equals(once)).toBe(true);
  });

  it('passes through an authenticated envelope from an older generation', () => {
    // No churn on rotation: files move to the new generation via `reencrypt`,
    // not by being re-cleaned.
    expect(clean(envelope2, ctx()).equals(envelope2)).toBe(true);
  });

  it('re-encrypts an envelope whose generation this keyring does not hold', () => {
    // Cannot authenticate it, so cannot assume it is safe to store as-is.
    const out = clean(envelope3, ctx({ keys: partial() }));
    expect(out.equals(envelope3)).toBe(false);
    expect(parseEnvelope(out).keyId).toBe(KEY_ID_2);
  });

  it('re-encrypts an envelope that fails authentication', () => {
    const corrupt = Buffer.from(envelope3);
    corrupt.writeUInt8(corrupt.readUInt8(corrupt.length - 1) ^ 0x01, corrupt.length - 1);
    const out = clean(corrupt, ctx());
    expect(out.equals(corrupt)).toBe(false);
    expect(looksLikeEnvelope(out)).toBe(true);
  });

  it('encrypts plaintext that merely begins with the magic', () => {
    // The authentication check is what stops this passing through in the clear.
    const evil = Buffer.concat([MAGIC, Buffer.from('pretending to be an envelope')]);
    const out = clean(evil, ctx());
    expect(out.equals(evil)).toBe(false);
    expect(smudge(out, ctx()).equals(evil)).toBe(true);
  });

  it('fails closed when the repository is locked', () => {
    expect(() => clean(PT, ctx({ keys: locked() }))).toThrow(LockedError);
  });

  it('names the path and the remedy when locked', () => {
    try {
      clean(PT, ctx({ keys: locked() }));
      expect.unreachable('should have thrown');
    } catch (e) {
      const message = (e as Error).message;
      expect(message).toContain(PATH);
      expect(message).toContain('securegit unlock');
      expect((e as LockedError).code).toBe('LOCKED');
    }
  });

  it('never emits plaintext when locked, even for an unencrypted input', () => {
    expect(() => clean(PT, ctx({ keys: locked() }))).toThrow();
  });

  it('fails closed even when the input is already an envelope', () => {
    // A locked filter cannot verify the passthrough precondition.
    expect(() => clean(envelope3, ctx({ keys: locked() }))).toThrow(LockedError);
  });

  it('honours bindPath', () => {
    const bound = clean(PT, ctx({ bindPath: true }));
    expect(parseEnvelope(bound).bindPath).toBe(true);
    expect(() => smudge(bound, ctx({ path: 'elsewhere.json' }))).toThrow();
  });

  it('handles a path beginning with a dash', () => {
    expect(looksLikeEnvelope(clean(PT, ctx({ path: '-weird-name.env' })))).toBe(true);
  });

  it('does not touch the filesystem — the path need not exist', () => {
    expect(looksLikeEnvelope(clean(PT, ctx({ path: 'no/such/file/anywhere.json' })))).toBe(true);
  });

  it('writes no warnings on the happy path', () => {
    const warn = vi.fn();
    clean(PT, ctx({ warn }));
    expect(warn).not.toHaveBeenCalled();
  });
});

describe('smudge()', () => {
  it('decrypts an envelope', () => {
    expect(smudge(envelope3, ctx()).equals(PT)).toBe(true);
  });

  it('decrypts an older generation', () => {
    expect(smudge(envelope2, ctx()).equals(PT)).toBe(true);
  });

  it('passes plaintext through — it may predate securegit', () => {
    expect(smudge(PT, ctx()).equals(PT)).toBe(true);
  });

  it('passes empty input through', () => {
    expect(smudge(Buffer.alloc(0), ctx()).length).toBe(0);
  });

  it('fails open when locked, so a keyless clone still completes', () => {
    const warn = vi.fn();
    const out = smudge(envelope3, ctx({ keys: locked(), warn }));
    expect(out.equals(envelope3)).toBe(true);
    expect(warn).toHaveBeenCalled();
  });

  it('warns about the path and the remedy when locked', () => {
    const warn = vi.fn();
    smudge(envelope3, ctx({ keys: locked(), warn }));
    const message = warn.mock.calls.map((c) => String(c[0])).join('\n');
    expect(message).toContain(PATH);
    expect(message).toContain('securegit unlock');
  });

  it('fails open for a generation it does not hold', () => {
    const warn = vi.fn();
    const out = smudge(envelope3, ctx({ keys: partial(), warn }));
    expect(out.equals(envelope3)).toBe(true);
    expect(warn).toHaveBeenCalled();
  });

  it('names the wanted and the held generations, so F5 is diagnosable', () => {
    const warn = vi.fn();
    smudge(envelope3, ctx({ keys: partial(), warn }));
    const message = warn.mock.calls.map((c) => String(c[0])).join('\n');
    expect(message).toContain(KEY_ID_3);
    expect(message).toContain(KEY_ID_2);
  });

  it('fails hard on a tampered envelope, even though it fails open on a missing key', () => {
    // A missing key is somebody else's normal. A failed tag is corruption or
    // an attack, and emitting those bytes as if they were plaintext is wrong.
    const corrupt = Buffer.from(envelope3);
    corrupt.writeUInt8(corrupt.readUInt8(corrupt.length - 1) ^ 0x01, corrupt.length - 1);
    expect(() => smudge(corrupt, ctx())).toThrow(/authentication/i);
  });

  it('names the path when authentication fails', () => {
    const corrupt = Buffer.from(envelope3);
    corrupt.writeUInt8(corrupt.readUInt8(corrupt.length - 1) ^ 0x01, corrupt.length - 1);
    expect(() => smudge(corrupt, ctx())).toThrow(new RegExp(PATH));
  });

  it('fails hard on a malformed envelope rather than emitting it', () => {
    const forged = Buffer.concat([MAGIC, Buffer.from('not really an envelope')]);
    expect(() => smudge(forged, ctx())).toThrow();
  });

  describe('--strict', () => {
    it('throws instead of passing through when locked', () => {
      expect(() => smudge(envelope3, ctx({ keys: locked(), strict: true }))).toThrow(LockedError);
    });

    it('throws instead of passing through for a missing generation', () => {
      expect(() => smudge(envelope3, ctx({ keys: partial(), strict: true }))).toThrow();
    });

    it('still passes plaintext through', () => {
      expect(smudge(PT, ctx({ strict: true })).equals(PT)).toBe(true);
    });
  });
});

describe('textconv()', () => {
  it('decrypts for display', () => {
    expect(textconv(envelope3, ctx()).equals(PT)).toBe(true);
  });

  it('passes plaintext through', () => {
    expect(textconv(PT, ctx()).equals(PT)).toBe(true);
  });

  it('prints a placeholder rather than failing when locked', () => {
    const out = textconv(envelope3, ctx({ keys: locked() })).toString('utf8');
    expect(out).toContain('securegit');
    expect(out).toContain('encrypted');
    expect(out).toContain(KEY_ID_3);
    expect(out).toContain(String(parseEnvelope(envelope3).ciphertext.length));
  });

  it('never throws, so `git log -p` does not stop at the first protected file', () => {
    const corrupt = Buffer.from(envelope3);
    corrupt.writeUInt8(corrupt.readUInt8(corrupt.length - 1) ^ 0x01, corrupt.length - 1);
    const forged = Buffer.concat([MAGIC, Buffer.from('not really an envelope')]);
    expect(() => textconv(corrupt, ctx())).not.toThrow();
    expect(() => textconv(forged, ctx())).not.toThrow();
    expect(() => textconv(envelope3, ctx({ keys: locked() }))).not.toThrow();
    expect(() => textconv(envelope3, ctx({ keys: locked(), strict: true }))).not.toThrow();
  });

  it('never emits ciphertext bytes as if they were content', () => {
    const out = textconv(envelope3, ctx({ keys: locked() }));
    expect(looksLikeEnvelope(out)).toBe(false);
    expect(out.includes(parseEnvelope(envelope3).ciphertext)).toBe(false);
  });

  it('ends its placeholder with a newline, so diffs stay well formed', () => {
    expect(textconv(envelope3, ctx({ keys: locked() })).toString('utf8').endsWith('\n')).toBe(true);
  });
});

describe('clean/smudge are exact inverses', () => {
  it.each([0, 1, 15, 4096, 65_536])('over %i bytes of random data', (n) => {
    const pt = randomBytes(n);
    expect(smudge(clean(pt, ctx()), ctx()).equals(pt)).toBe(true);
  });

  it('over content with CRLF line endings', () => {
    const pt = Buffer.from('a=1\r\nb=2\r\n');
    expect(smudge(clean(pt, ctx()), ctx()).equals(pt)).toBe(true);
  });

  it('over content that is entirely NUL bytes', () => {
    const pt = Buffer.alloc(512, 0);
    expect(smudge(clean(pt, ctx()), ctx()).equals(pt)).toBe(true);
  });
});
