// Cryptographic primitives and derivations.
//
// Everything here is a pure function of its inputs. That is not a style
// preference: `clean` must be deterministic or Git's change detection breaks.
// See specs/securegit/03-determinism.md and 05-key-hierarchy.md.

import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  hkdfSync,
  timingSafeEqual,
} from 'node:crypto';
import { inspect } from 'node:util';

export const KEY_LEN = 32;
export const NONCE_LEN = 12;
export const TAG_LEN = 16;
export const CONTENT_TAG_LEN = 32;

// HKDF labels. Byte-exact and version-suffixed: changing one is a new
// algorithm id in the envelope, never an edit to an existing label.
const INFO_TAG = Buffer.from('securegit/tag/v1', 'utf8');
const INFO_DEK = Buffer.from('securegit/dek/v1', 'utf8');
const PREFIX_KEYID = Buffer.from('securegit/keyid/v1', 'utf8');
const SEP = Buffer.from([0x00]);
const NO_SALT = Buffer.alloc(0);

export class CryptoError extends Error {
  readonly code = 'CRYPTO';

  constructor(message: string) {
    super(message);
    this.name = 'CryptoError';
  }
}

declare const secretBrand: unique symbol;

/** A Buffer carrying key material. Still a Buffer; redacts when printed. */
export type Secret = Buffer & { readonly [secretBrand]?: true };

const IS_SECRET = Symbol('securegit.secret');
const REDACTED = '[redacted]';

const bufferToString = Buffer.prototype.toString as (
  this: Buffer,
  encoding?: BufferEncoding,
  start?: number,
  end?: number,
) => string;

/**
 * Copies `bytes` into a new Buffer and marks it as key material. node:crypto
 * takes it directly, but bare `toString()`, `JSON.stringify` and
 * `util.inspect` all yield "[redacted]" — so an accidental `${key}` prints a
 * marker instead of a secret. `toString('hex')` still works, because
 * serialising a key is something we deliberately do.
 *
 * It copies rather than marking in place for two reasons: marking the caller's
 * buffer would silently change the behaviour of a value they still hold, and a
 * later mutation of the source must not be able to change a derived key.
 */
export function secret(bytes: Buffer | Uint8Array): Secret {
  const buf = Buffer.from(bytes) as Secret;
  Object.defineProperties(buf, {
    [IS_SECRET]: { value: true, enumerable: false },
    toString: {
      value(this: Buffer, ...args: [BufferEncoding?, number?, number?]): string {
        return args.length === 0 ? REDACTED : bufferToString.apply(this, args);
      },
      enumerable: false,
    },
    toJSON: { value: (): string => REDACTED, enumerable: false },
    [inspect.custom]: { value: (): string => REDACTED, enumerable: false },
  });
  return buf;
}

export function isSecret(value: unknown): boolean {
  return Boolean(
    value !== null &&
      value !== undefined &&
      (value as Record<symbol, unknown>)[IS_SECRET],
  );
}

/**
 * The form of a path that enters a derivation. Windows and POSIX checkouts of
 * the same repository must derive the same key, so separators are folded and
 * the result is compared as raw UTF-8. `null` means "unbound" — the path does
 * not participate at all.
 */
export function normalizePath(path: string | null | undefined): string | null {
  if (path === null || path === undefined) return null;
  let s = String(path).replace(/\\/g, '/').replace(/\/{2,}/g, '/');
  while (s.startsWith('./')) s = s.slice(2);
  return s;
}

function requireBytes(value: Buffer, len: number, what: string): void {
  if (!Buffer.isBuffer(value)) {
    throw new CryptoError(`${what} must be a Buffer`);
  }
  if (value.length !== len) {
    throw new CryptoError(`${what} must be ${len} bytes, got ${value.length}`);
  }
}

/** K_tag — the secret behind the content tag. Never leaves the process. */
export function deriveTagKey(rmk: Buffer): Secret {
  requireBytes(rmk, KEY_LEN, 'master key');
  return secret(Buffer.from(hkdfSync('sha256', rmk, NO_SALT, INFO_TAG, KEY_LEN)));
}

/**
 * HMAC of the plaintext under K_tag. Supplies both the nonce (its first 12
 * bytes) and the DEK salt, which is what makes the scheme deterministic
 * without ever reusing a (key, nonce) pair across distinct plaintexts.
 *
 * Keyed rather than a bare hash: an adversary who guesses a plaintext cannot
 * confirm the guess without K_tag.
 */
export function contentTag(
  tagKey: Buffer,
  plaintext: Buffer,
  path: string | null,
): Buffer {
  requireBytes(tagKey, KEY_LEN, 'tag key');
  const h = createHmac('sha256', tagKey);
  const p = normalizePath(path);
  if (p !== null) {
    h.update(Buffer.from(p, 'utf8'));
    h.update(SEP);
  }
  h.update(plaintext);
  return h.digest();
}

/** Per-content data encryption key. Derived, never stored — see spec 05. */
export function deriveFileKey(
  rmk: Buffer,
  tag: Buffer,
  path: string | null,
): Secret {
  requireBytes(rmk, KEY_LEN, 'master key');
  requireBytes(tag, CONTENT_TAG_LEN, 'content tag');
  const p = normalizePath(path);
  const info =
    p === null ? INFO_DEK : Buffer.concat([INFO_DEK, SEP, Buffer.from(p, 'utf8')]);
  return secret(Buffer.from(hkdfSync('sha256', rmk, tag, info, KEY_LEN)));
}

/**
 * Public, truncated one-way function of a master key. Exists so a wrong-key
 * failure is diagnosable ("blob wants 9f0c…, your keyring has a1b2…") rather
 * than an unexplained authentication error.
 */
export function keyFingerprint(rmk: Buffer): string {
  requireBytes(rmk, KEY_LEN, 'master key');
  return createHash('sha256')
    .update(PREFIX_KEYID)
    .update(rmk)
    .digest()
    .subarray(0, 8)
    .toString('hex');
}

export interface Sealed {
  ciphertext: Buffer;
  authTag: Buffer;
}

export function aeadEncrypt(
  key: Buffer,
  nonce: Buffer,
  plaintext: Buffer,
  aad: Buffer | null,
): Sealed {
  requireBytes(key, KEY_LEN, 'key');
  requireBytes(nonce, NONCE_LEN, 'nonce');
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  if (aad !== null) cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { ciphertext, authTag: cipher.getAuthTag() };
}

export function aeadDecrypt(
  key: Buffer,
  nonce: Buffer,
  ciphertext: Buffer,
  authTag: Buffer,
  aad: Buffer | null,
): Buffer {
  requireBytes(key, KEY_LEN, 'key');
  requireBytes(nonce, NONCE_LEN, 'nonce');
  requireBytes(authTag, TAG_LEN, 'authentication tag');
  const decipher = createDecipheriv('aes-256-gcm', key, nonce);
  if (aad !== null) decipher.setAAD(aad);
  decipher.setAuthTag(authTag);
  try {
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    // Deliberately opaque: never echo key material or content into an error.
    throw new CryptoError('authentication failed');
  }
}

/** Constant-time comparison for anything not already covered by an AEAD tag. */
export function equalCt(a: Buffer, b: Buffer): boolean {
  if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b) || a.length !== b.length) {
    return false;
  }
  return timingSafeEqual(a, b);
}
