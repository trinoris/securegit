// A person's or machine's X25519 identity: the keypair `recipients.ts` wraps
// a repository master key against, its checksummed public-key encoding, its
// fingerprint, and the on-disk `~/.securegit/identity.json` that protects the
// private half with the same KeyProvider port ([06](06-key-provider-port.md))
// that protects a repository's own master key.
// See specs/securegit/08-multi-recipient.md.

import {
  generateKeyPairSync,
  createHash,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  randomBytes,
} from 'node:crypto';
import { mkdir, readFile, rename, writeFile, unlink } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import type { KeyProvider, ProviderState, WrappedKey } from './provider.js';

export class IdentityError extends Error {
  readonly code = 'IDENTITY';

  constructor(message: string) {
    super(message);
    this.name = 'IdentityError';
  }
}

export const IDENTITY_PUBKEY_LEN = 32;
const CHECKSUM_LEN = 4;
const PUBKEY_PREFIX = 'SGPUB1';
const FINGERPRINT_LABEL = Buffer.from('securegit/identity/v1', 'utf8');

/** Crockford base32 — excludes I, L, O, U to avoid transcription confusion. */
const CROCKFORD_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

export interface X25519KeyPair {
  publicKey: Buffer;
  privateKey: Buffer;
}

/** A fresh X25519 keypair, as raw 32-byte values (not DER/PEM). */
export function generateX25519KeyPair(): X25519KeyPair {
  const { publicKey, privateKey } = generateKeyPairSync('x25519');
  const pub = publicKey.export({ format: 'jwk' }) as { x: string };
  const priv = privateKey.export({ format: 'jwk' }) as { d: string };
  return {
    publicKey: Buffer.from(pub.x, 'base64url'),
    privateKey: Buffer.from(priv.d, 'base64url'),
  };
}

/**
 * X25519(own.privateKey, peerPublicKey) — the shared secret `recipients.ts`
 * derives a wrap key from. Takes the *full* own keypair, not just the
 * private half: reconstructing a Node private KeyObject from raw JWK fields
 * requires the public half (`x`) alongside `d`, per the JWK spec.
 */
export function x25519SharedSecret(own: X25519KeyPair, peerPublicKey: Buffer): Buffer {
  const privateKeyObject = createPrivateKey({
    key: { kty: 'OKP', crv: 'X25519', x: own.publicKey.toString('base64url'), d: own.privateKey.toString('base64url') },
    format: 'jwk',
  });
  const publicKeyObject = createPublicKey({
    key: { kty: 'OKP', crv: 'X25519', x: peerPublicKey.toString('base64url') },
    format: 'jwk',
  });
  return diffieHellman({ privateKey: privateKeyObject, publicKey: publicKeyObject });
}

/** Exported so `recovery.ts` shares this codec rather than duplicating it. */
export function crockfordEncode(bytes: Buffer): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += CROCKFORD_ALPHABET[(value >>> (bits - 5)) & 0x1f];
      bits -= 5;
    }
  }
  if (bits > 0) {
    out += CROCKFORD_ALPHABET[(value << (5 - bits)) & 0x1f];
  }
  return out;
}

export function crockfordDecode(text: string): Buffer {
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of text) {
    const digit = CROCKFORD_ALPHABET.indexOf(ch);
    if (digit === -1) {
      throw new IdentityError(`invalid character in public key encoding: '${ch}'`);
    }
    value = (value << 5) | digit;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

/**
 * The checksum is a plain, un-namespaced hash of the public key alone —
 * deliberately a different domain from `identityFingerprint`'s
 * "securegit/identity/v1"-prefixed hash, so a corrupted key's checksum can
 * never coincidentally read back as a valid fingerprint.
 */
function checksum(pubkey: Buffer): Buffer {
  return createHash('sha256').update(pubkey).digest().subarray(0, CHECKSUM_LEN);
}

/** `SGPUB1<Crockford base32 of the 32 key bytes + a 4-byte checksum>`. */
export function encodePublicKey(pubkey: Buffer): string {
  if (pubkey.length !== IDENTITY_PUBKEY_LEN) {
    throw new IdentityError(`public key must be ${IDENTITY_PUBKEY_LEN} bytes, got ${pubkey.length}`);
  }
  return PUBKEY_PREFIX + crockfordEncode(Buffer.concat([pubkey, checksum(pubkey)]));
}

/** Reverses `encodePublicKey`, verifying the checksum before returning the raw key. */
export function decodePublicKey(encoded: string): Buffer {
  if (!encoded.startsWith(PUBKEY_PREFIX)) {
    throw new IdentityError(`public key must start with '${PUBKEY_PREFIX}'`);
  }
  const decoded = crockfordDecode(encoded.slice(PUBKEY_PREFIX.length));
  if (decoded.length !== IDENTITY_PUBKEY_LEN + CHECKSUM_LEN) {
    throw new IdentityError(
      `public key is the wrong length: expected ${IDENTITY_PUBKEY_LEN + CHECKSUM_LEN} bytes, got ${decoded.length}`,
    );
  }
  const pubkey = decoded.subarray(0, IDENTITY_PUBKEY_LEN);
  const given = decoded.subarray(IDENTITY_PUBKEY_LEN);
  if (!checksum(pubkey).equals(given)) {
    throw new IdentityError('public key checksum does not match — likely a transcription error');
  }
  return pubkey;
}

/** `SHA-256("securegit/identity/v1" ‖ pubkey)[0..8]`, as 16 hex characters. */
export function identityFingerprint(pubkey: Buffer): string {
  return createHash('sha256')
    .update(Buffer.concat([FINGERPRINT_LABEL, pubkey]))
    .digest()
    .subarray(0, 8)
    .toString('hex');
}

export interface IdentityFile {
  version: 1;
  fingerprint: string;
  publicKey: string;
  label: string;
  wrapped: { provider: string; state: ProviderState; payload: WrappedKey['payload'] };
}

/**
 * Identities aren't scoped to any one repository or generation, unlike an
 * RMK — this fixed context is what `wrap`/`unwrap` bind into their AAD for
 * an identity's private key, so it can never be confused with (or replayed
 * against) a repository's own wrapped master key.
 */
const IDENTITY_CONTEXT = { repoId: 'identity', generation: 0 } as const;

/** Generates a keypair and wraps the private half. Does not write to disk. */
export async function createIdentity(
  label: string,
  provider: KeyProvider,
): Promise<{ file: IdentityFile; keyPair: X25519KeyPair }> {
  const keyPair = generateX25519KeyPair();
  const state = await provider.init(IDENTITY_CONTEXT);
  const wrapped = await provider.wrap(keyPair.privateKey, { ...IDENTITY_CONTEXT, state, interactive: true });
  const file: IdentityFile = {
    version: 1,
    fingerprint: identityFingerprint(keyPair.publicKey),
    publicKey: encodePublicKey(keyPair.publicKey),
    label,
    wrapped: { provider: wrapped.provider, state, payload: wrapped.payload },
  };
  return { file, keyPair };
}

/** The identity's private key, or `null` if no given provider can unwrap it — never throws. */
export async function unlockIdentity(file: IdentityFile, providers: KeyProvider[]): Promise<Buffer | null> {
  const provider = providers.find((p) => p.id === file.wrapped.provider);
  if (!provider) return null;
  try {
    return await provider.unwrap(
      { provider: file.wrapped.provider, payload: file.wrapped.payload },
      { ...IDENTITY_CONTEXT, state: file.wrapped.state, interactive: true },
    );
  } catch {
    return null;
  }
}

export function identityPath(home: string): string {
  return join(home, '.securegit', 'identity.json');
}

/** Atomic (temp + rename) write, mode 0600 — the same discipline as `keyring.ts`'s master key. */
export async function writeIdentityFile(path: string, file: IdentityFile): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const tmp = `${path}.tmp-${process.pid}-${randomBytes(4).toString('hex')}`;
  await writeFile(tmp, JSON.stringify(file, null, 2), { mode: 0o600 });
  try {
    await rename(tmp, path);
  } catch (e) {
    await unlink(tmp).catch(() => {});
    throw e;
  }
}

export async function readIdentityFile(path: string): Promise<IdentityFile> {
  const raw = await readFile(path, 'utf8');
  return JSON.parse(raw) as IdentityFile;
}
