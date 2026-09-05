import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { execFile as execFileCb } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, rm, stat, readFile } from 'node:fs/promises';
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
  resolveSigningKeyRef,
  detectLocalSigningKey,
  generateSigningKeyPair,
  signingKeyFingerprint,
  type IdentityFile,
} from './identity.js';

const execFile = promisify(execFileCb);

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

describe('resolveSigningKeyRef()', () => {
  const home = '/home/whoever';

  it('null in, null out — nothing configured', async () => {
    await expect(resolveSigningKeyRef(null, home)).resolves.toBeNull();
  });

  it('empty string resolves to null, same as unconfigured', async () => {
    await expect(resolveSigningKeyRef('', home)).resolves.toBeNull();
  });

  it('the inline key:: form is returned verbatim, trimmed, no filesystem access', async () => {
    const readFileImpl = async () => {
      throw new Error('should never be called for an inline key');
    };
    await expect(
      resolveSigningKeyRef('key::ssh-ed25519 AAAAtest ', home, readFileImpl),
    ).resolves.toBe('ssh-ed25519 AAAAtest');
  });

  it('a ~/-relative path is expanded against home before reading', async () => {
    const seen: string[] = [];
    const readFileImpl = async (p: string) => {
      seen.push(p);
      return 'ssh-ed25519 AAAAhome\n';
    };
    const result = await resolveSigningKeyRef('~/.ssh/id_ed25519.pub', home, readFileImpl);
    expect(seen).toEqual([join(home, '.ssh', 'id_ed25519.pub')]);
    expect(result).toBe('ssh-ed25519 AAAAhome');
  });

  it('a plain absolute path is read as-is', async () => {
    const seen: string[] = [];
    const readFileImpl = async (p: string) => {
      seen.push(p);
      return 'ssh-ed25519 AAAAabs\n';
    };
    await resolveSigningKeyRef('/etc/keys/signing.pub', home, readFileImpl);
    expect(seen).toEqual(['/etc/keys/signing.pub']);
  });

  it('a configured path that cannot be read resolves to null, not a throw', async () => {
    const readFileImpl = async () => {
      throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' });
    };
    await expect(resolveSigningKeyRef('~/.ssh/gone.pub', home, readFileImpl)).resolves.toBeNull();
  });
});

describe('detectLocalSigningKey()', () => {
  let repoDir: string;
  let home: string;

  beforeEach(async () => {
    repoDir = await mkdtemp(join(tmpdir(), 'securegit-identity-repo-'));
    home = await mkdtemp(join(tmpdir(), 'securegit-identity-home-'));
    await execFile('git', ['init', '-q', repoDir]);
  });

  afterEach(async () => {
    await rm(repoDir, { recursive: true, force: true });
    await rm(home, { recursive: true, force: true });
  });

  it('returns null when user.signingkey is not configured', async () => {
    await expect(detectLocalSigningKey(repoDir, home)).resolves.toBeNull();
  });

  it('reads a real, locally-configured signing key path, isolated to this repo only', async () => {
    const { publicKey } = await generateSigningKeyPair(join(home, 'id_ed25519'));
    await execFile('git', ['config', 'user.signingkey', join(home, 'id_ed25519.pub')], { cwd: repoDir });
    await expect(detectLocalSigningKey(repoDir, home)).resolves.toBe(publicKey);
  });

  it('reads the inline key:: form too', async () => {
    await execFile('git', ['config', 'user.signingkey', 'key::ssh-ed25519 AAAAinline'], { cwd: repoDir });
    await expect(detectLocalSigningKey(repoDir, home)).resolves.toBe('ssh-ed25519 AAAAinline');
  });
});

describe('generateSigningKeyPair()', () => {
  let dir: string;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), 'securegit-identity-signing-'));
  });

  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it('generates a real Ed25519 SSH-format keypair', async () => {
    const path = join(dir, 'id_ed25519');
    const { publicKey } = await generateSigningKeyPair(path);
    expect(publicKey).toMatch(/^ssh-ed25519 /);
    const onDisk = (await readFile(`${path}.pub`, 'utf8')).trim();
    expect(onDisk).toBe(publicKey);
    // The private half exists and is a real OpenSSH private key, not a stub.
    const privateKey = await readFile(path, 'utf8');
    expect(privateKey).toContain('BEGIN OPENSSH PRIVATE KEY');
  });

  it('two calls produce different keypairs', async () => {
    const a = await generateSigningKeyPair(join(dir, 'a'));
    const b = await generateSigningKeyPair(join(dir, 'b'));
    expect(a.publicKey).not.toBe(b.publicKey);
  });

  it('creates missing parent directories', async () => {
    const path = join(dir, 'nested', 'deeper', 'id_ed25519');
    const { publicKey } = await generateSigningKeyPair(path);
    expect(publicKey).toMatch(/^ssh-ed25519 /);
  });

  it('refuses to overwrite an existing key at the same path', async () => {
    const path = join(dir, 'id_ed25519');
    await generateSigningKeyPair(path);
    await expect(generateSigningKeyPair(path)).rejects.toThrow(IdentityError);
  });
});

describe('signingKeyFingerprint()', () => {
  let dir: string;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), 'securegit-identity-fp-'));
  });

  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it('matches ssh-keygen -lf exactly, for a real generated key', async () => {
    const path = join(dir, 'id_ed25519');
    const { publicKey } = await generateSigningKeyPair(path);
    const { stdout } = await execFile('ssh-keygen', ['-lf', `${path}.pub`]);
    // "256 SHA256:nds3ev…KA test (ED25519)" — the fingerprint is the second field.
    const expected = stdout.trim().split(/\s+/)[1];
    expect(signingKeyFingerprint(publicKey)).toBe(expected);
  });

  it('is stable for the same key, called twice', async () => {
    const { publicKey } = await generateSigningKeyPair(join(dir, 'id_ed25519'));
    expect(signingKeyFingerprint(publicKey)).toBe(signingKeyFingerprint(publicKey));
  });

  it('differs for different keys', async () => {
    const a = await generateSigningKeyPair(join(dir, 'a'));
    const b = await generateSigningKeyPair(join(dir, 'b'));
    expect(signingKeyFingerprint(a.publicKey)).not.toBe(signingKeyFingerprint(b.publicKey));
  });

  it('ignores a trailing comment, matching only the key type and blob', async () => {
    const { publicKey } = await generateSigningKeyPair(join(dir, 'id_ed25519'));
    const withoutComment = publicKey.split(/\s+/).slice(0, 2).join(' ');
    const withDifferentComment = `${withoutComment} someone@somewhere`;
    expect(signingKeyFingerprint(withDifferentComment)).toBe(signingKeyFingerprint(publicKey));
  });

  it('is prefixed with SHA256:, matching the format git itself reports for a signer', () => {
    expect(
      signingKeyFingerprint('ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFiRUiOHgwdBMOAQXey7x3B4WS90jgI0kirS3hCm8xQF'),
    ).toMatch(/^SHA256:[A-Za-z0-9+/]+$/);
  });

  it('throws IdentityError on a malformed key line', () => {
    expect(() => signingKeyFingerprint('not-a-key-line')).toThrow(IdentityError);
    expect(() => signingKeyFingerprint('')).toThrow(IdentityError);
    expect(() => signingKeyFingerprint('ssh-ed25519 not-valid-base64!!!')).toThrow(IdentityError);
  });
});
