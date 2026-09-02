import { describe, it, expect } from 'vitest';
import { seal, looksLikeEnvelope } from './envelope.js';
import { clean, smudge, LockedError, type KeySource, type FilterContext } from './filter.js';

// Cross-cutting checklist for specs/securegit/15-failure-modes.md: every
// failure message this package controls names what happened, where, and
// what to do about it.
//
// Not every F-code has a test here. F3/F17 are Git's own message, not ours.
// F10/F13/F20 are not built yet (filter-process, key rotate, a Node-version
// startup check). F12/F14/F15 have no code path to test (F12 is "nothing
// goes wrong"; F14/F15 are "nothing can be done"). F2/F4/F8/F16 belong to
// src/git.integration.test.ts (they are about what a real `git` does, not
// about a message). F7 belongs to src/verify.test.ts, F11/F19 to
// src/keyring.test.ts — all closer to the code that actually produces them.

const RMK = Buffer.alloc(32, 0xa5);
const OTHER_RMK = Buffer.alloc(32, 0x5a);
const KEY_ID = '3.a1b2c3d4e5f60718';
const OTHER_KEY_ID = '2.b30f92ac1e7d4405';
const PATH = 'config/production.json';
const PT = Buffer.from('{"timeout":30}\n');

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

function ctx(over: Partial<FilterContext> = {}): FilterContext {
  return { keys: unlocked(), path: PATH, ...over };
}

/** Every message this package writes names what happened, where, and what to do. */
function expectDiscipline(message: string): void {
  expect(message.startsWith('securegit:')).toBe(true); // what
  expect(message).toContain(PATH); // where
  expect(message).toContain('action:'); // what to do
}

describe('F1 / F9: locked keyring, clean() mid-add', () => {
  it('fails closed with a disciplined message', () => {
    let message = '';
    try {
      clean(PT, ctx({ keys: locked() }));
      expect.unreachable();
    } catch (e) {
      expect(e).toBeInstanceOf(LockedError);
      message = (e as Error).message;
    }
    expectDiscipline(message);
    expect(message).toContain('locked');
    expect(message).toContain('securegit unlock');
  });

  it('F9 is not a distinct code path — "expired mid-add" and "never unlocked" both present as keys.current() === null', () => {
    expect(() => clean(PT, ctx({ keys: locked() }))).toThrow(LockedError);
  });
});

describe('F5: wrong key — envelope names a generation not in the keyring', () => {
  it('smudge() fails open, warning with both the wanted and the held generations', () => {
    const envelope = seal(PT, { rmk: OTHER_RMK, keyId: OTHER_KEY_ID, path: PATH });
    const warnings: string[] = [];
    const out = smudge(envelope, ctx({ warn: (m) => warnings.push(m) }));

    expect(out.equals(envelope)).toBe(true); // a keyless clone still completes
    expect(warnings).toHaveLength(1);
    const message = warnings[0]!;
    expectDiscipline(message);
    expect(message).toContain(OTHER_KEY_ID); // wanted
    expect(message).toContain(KEY_ID); // held
  });
});

describe('F6: corrupted blob, authentication fails', () => {
  it('smudge() reports corruption, not a missing key, with a real remedy', () => {
    const envelope = seal(PT, { rmk: RMK, keyId: KEY_ID, path: PATH });
    const corrupt = Buffer.from(envelope);
    corrupt.writeUInt8(corrupt.readUInt8(corrupt.length - 1) ^ 0x01, corrupt.length - 1);

    let message = '';
    try {
      smudge(corrupt, ctx());
      expect.unreachable();
    } catch (e) {
      message = (e as Error).message;
    }
    expectDiscipline(message);
    expect(message).toContain('authentication failed');
    expect(message).toContain('git fsck');
    expect(message.toLowerCase()).not.toContain('decryption failed'); // the one phrase the spec bans
  });
});

/**
 * The ciphertext is pseudorandom, so an LF byte (0x0A) worth mangling isn't
 * guaranteed to appear in any one envelope — this tries a handful of
 * deterministic variants until one does, rather than relying on luck.
 */
function sealContainingLf(): Buffer {
  for (let i = 0; i < 64; i++) {
    const plaintext = Buffer.from(`line one\nline two\nline three\nattempt ${i}\n`);
    const envelope = seal(plaintext, { rmk: RMK, keyId: KEY_ID, path: PATH });
    if (envelope.includes(0x0a)) return envelope;
  }
  throw new Error('no test vector containing an LF byte found in 64 attempts');
}

describe('F18: core.autocrlf mangles the envelope', () => {
  it('reports corruption (F6-shaped), never a missing-generation warning', () => {
    // Simulated the way `core.autocrlf=true` would corrupt it on checkin or
    // checkout if `-text` were missing: every LF byte inside an otherwise
    // valid envelope becomes CRLF. There is no dedicated "looks CRLF-mangled"
    // detector, and there does not need to be — it just fails the same AEAD
    // tag check any other corruption does.
    const envelope = sealContainingLf();
    const mangled = Buffer.from(envelope.toString('binary').split('\n').join('\r\n'), 'binary');
    expect(looksLikeEnvelope(mangled)).toBe(true); // the magic survives; the tag does not
    expect(mangled.equals(envelope)).toBe(false); // the mangling actually changed something

    let message = '';
    try {
      smudge(mangled, ctx());
      expect.unreachable();
    } catch (e) {
      message = (e as Error).message;
    }
    expect(message).toContain('authentication failed');
    expect(message).not.toContain('generation'); // never mistaken for F5's message
  });
});

describe('message discipline is uniform across every message checked above', () => {
  it('every one starts with "securegit:", names the path, and ends in an action line', () => {
    const messages: string[] = [];

    try {
      clean(PT, ctx({ keys: locked() }));
    } catch (e) {
      messages.push((e as Error).message);
    }

    const missingGenEnvelope = seal(PT, { rmk: OTHER_RMK, keyId: OTHER_KEY_ID, path: PATH });
    smudge(missingGenEnvelope, ctx({ warn: (m) => messages.push(m) }));

    const corrupt = Buffer.from(seal(PT, { rmk: RMK, keyId: KEY_ID, path: PATH }));
    corrupt.writeUInt8(corrupt.readUInt8(corrupt.length - 1) ^ 0x01, corrupt.length - 1);
    try {
      smudge(corrupt, ctx());
    } catch (e) {
      messages.push((e as Error).message);
    }

    expect(messages.length).toBe(3);
    for (const message of messages) {
      expectDiscipline(message);
    }
  });
});
