import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PassphraseFileProvider } from './provider.js';
import {
  IdentityError,
  IDENTITY_PUBKEY_LEN,
  generateX25519KeyPair,
  x25519SharedSecret,
  encodePublicKey,
  decodePublicKey,
  identityFingerprint,
  createIdentity,
  unlockIdentity,
  identityPath,
  writeIdentityFile,
  readIdentityFile,
  type IdentityFile,
} from './identity.js';

const FAST_COST = { N: 2 ** 10, r: 8, p: 1 };
const PASSPHRASE = 'correct horse battery staple';

function passphraseProvider(pass = PASSPHRASE): PassphraseFileProvider {
  return new PassphraseFileProvider(() => pass, FAST_COST);
}

describe('generateX25519KeyPair()', () => {
  it('produces 32-byte public and private keys', () => {
    const { publicKey, privateKey } = generateX25519KeyPair();
    expect(publicKey.length).toBe(IDENTITY_PUBKEY_LEN);
    expect(privateKey.length).toBe(IDENTITY_PUBKEY_LEN);
  });

  it('two calls produce different keypairs', () => {
    const a = generateX25519KeyPair();
    const b = generateX25519KeyPair();
    expect(a.publicKey.equals(b.publicKey)).toBe(false);
    expect(a.privateKey.equals(b.privateKey)).toBe(false);
  });
});

describe('x25519SharedSecret()', () => {
  it('agrees from both sides — a real ECDH bridge to recipients.ts', () => {
    const alice = generateX25519KeyPair();
    const bob = generateX25519KeyPair();

    const sharedAtAlice = x25519SharedSecret(alice, bob.publicKey);
    const sharedAtBob = x25519SharedSecret(bob, alice.publicKey);

    expect(sharedAtAlice.equals(sharedAtBob)).toBe(true);
  });

  it('differs for a different peer', () => {
    const alice = generateX25519KeyPair();
    const bob = generateX25519KeyPair();
    const carol = generateX25519KeyPair();
    expect(x25519SharedSecret(alice, bob.publicKey).equals(x25519SharedSecret(alice, carol.publicKey))).toBe(
      false,
    );
  });
});

describe('encodePublicKey() / decodePublicKey()', () => {
  it('round-trips', () => {
    const { publicKey } = generateX25519KeyPair();
    const encoded = encodePublicKey(publicKey);
    expect(decodePublicKey(encoded).equals(publicKey)).toBe(true);
  });

  it('starts with the SGPUB1 prefix', () => {
    const { publicKey } = generateX25519KeyPair();
    expect(encodePublicKey(publicKey).startsWith('SGPUB1')).toBe(true);
  });

  it('uses only the Crockford base32 alphabet after the prefix', () => {
    const { publicKey } = generateX25519KeyPair();
    const encoded = encodePublicKey(publicKey);
    expect(encoded.slice('SGPUB1'.length)).toMatch(/^[0-9A-HJKMNP-TV-Z]+$/);
  });

  it('rejects a one-character corruption via the checksum', () => {
    const { publicKey } = generateX25519KeyPair();
    const encoded = encodePublicKey(publicKey);
    const bodyStart = 'SGPUB1'.length;
    // Flip one character in the body to something else valid in the alphabet.
    const original = encoded[bodyStart]!;
    const replacement = original === '0' ? '1' : '0';
    const corrupted = encoded.slice(0, bodyStart) + replacement + encoded.slice(bodyStart + 1);
    expect(corrupted).not.toBe(encoded);
    expect(() => decodePublicKey(corrupted)).toThrow(IdentityError);
  });

  it('rejects a missing or wrong prefix', () => {
    const { publicKey } = generateX25519KeyPair();
    const encoded = encodePublicKey(publicKey);
    expect(() => decodePublicKey(encoded.slice('SGPUB1'.length))).toThrow(IdentityError);
    expect(() => decodePublicKey(`WRONG1${encoded.slice('SGPUB1'.length)}`)).toThrow(IdentityError);
  });

  it('rejects a truncated body', () => {
    const { publicKey } = generateX25519KeyPair();
    const encoded = encodePublicKey(publicKey);
    expect(() => decodePublicKey(encoded.slice(0, -4))).toThrow(IdentityError);
  });

  it('rejects characters outside the Crockford alphabet', () => {
    expect(() => decodePublicKey('SGPUB1@@@@invalid')).toThrow(IdentityError);
  });
});

describe('identityFingerprint()', () => {
  it('is derived from the public key, not the rest of the file', () => {
    const { publicKey } = generateX25519KeyPair();
    const a = identityFingerprint(publicKey);
    const b = identityFingerprint(publicKey);
    expect(a).toBe(b); // pure function of the key alone
    expect(a).toMatch(/^[0-9a-f]{16}$/);
  });

  it('differs for different public keys', () => {
    const a = generateX25519KeyPair();
    const b = generateX25519KeyPair();
    expect(identityFingerprint(a.publicKey)).not.toBe(identityFingerprint(b.publicKey));
  });

  it('is not the same value as the checksum used in public-key encoding', () => {
    // Different domains (fingerprint is namespaced with "securegit/identity/v1",
    // the encoding checksum is not) — collapsing them would let a corrupted
    // key's checksum accidentally still "look like" a valid fingerprint.
    const { publicKey } = generateX25519KeyPair();
    const fingerprint = identityFingerprint(publicKey);
    const encoded = encodePublicKey(publicKey);
    expect(encoded).not.toContain(fingerprint.toUpperCase());
  });
});

describe('createIdentity() / unlockIdentity()', () => {
  it('round-trips the private key through a real KeyProvider', async () => {
    const provider = passphraseProvider();
    const { file, keyPair } = await createIdentity('laptop', provider);

    expect(file.label).toBe('laptop');
    expect(file.fingerprint).toBe(identityFingerprint(keyPair.publicKey));
    expect(decodePublicKey(file.publicKey).equals(keyPair.publicKey)).toBe(true);

    const recovered = await unlockIdentity(file, [provider]);
    expect(recovered).not.toBeNull();
    expect(recovered!.equals(keyPair.privateKey)).toBe(true);
  });

  it('returns null for the wrong passphrase, never throws', async () => {
    const { file } = await createIdentity('laptop', passphraseProvider());
    const wrong = passphraseProvider('a totally different passphrase');
    await expect(unlockIdentity(file, [wrong])).resolves.toBeNull();
  });

  it('returns null when no provider matches the one the file was wrapped with', async () => {
    const { file } = await createIdentity('laptop', passphraseProvider());
    await expect(unlockIdentity(file, [])).resolves.toBeNull();
  });

  it('never puts the private key or passphrase in the file', async () => {
    const provider = passphraseProvider();
    const { file, keyPair } = await createIdentity('laptop', provider);
    const serialized = JSON.stringify(file);
    expect(serialized).not.toContain(keyPair.privateKey.toString('hex'));
    expect(serialized).not.toContain(PASSPHRASE);
  });
});

let dir: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'securegit-identity-'));
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe('identityPath() / writeIdentityFile() / readIdentityFile()', () => {
  it('resolves to ~/.securegit/identity.json', () => {
    expect(identityPath(dir)).toBe(join(dir, '.securegit', 'identity.json'));
  });

  it('round-trips through disk', async () => {
    const { file } = await createIdentity('laptop', passphraseProvider());
    const path = identityPath(dir);
    await writeIdentityFile(path, file);
    const read = await readIdentityFile(path);
    expect(read).toEqual(file satisfies IdentityFile);
  });

  it('is written with mode 0600', async () => {
    const { file } = await createIdentity('laptop', passphraseProvider());
    const path = identityPath(dir);
    await writeIdentityFile(path, file);
    const mode = (await stat(path)).mode & 0o777;
    expect(mode).toBe(0o600);
  });

  it('creates missing parent directories', async () => {
    const { file } = await createIdentity('laptop', passphraseProvider());
    const path = join(dir, 'nested', 'deeper', 'identity.json');
    await writeIdentityFile(path, file);
    expect(await readIdentityFile(path)).toEqual(file);
  });

  it('reading a missing file throws', async () => {
    await expect(readIdentityFile(identityPath(dir))).rejects.toThrow();
  });
});
