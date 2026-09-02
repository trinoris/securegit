import { describe, it, expect, vi, afterEach } from 'vitest';
import { mkdtemp, mkdir, rm, chmod, readdir, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { isSecret, keyFingerprint } from './crypto.js';
import { PassphraseFileProvider, type KeyProvider } from './provider.js';
import { clean, smudge, LockedError } from './filter.js';
import {
  KeyringError,
  keyIdFor,
  parseKeyId,
  createKeyring,
  rotateKeyring,
  unlockKeyring,
  writeKeyringFile,
  readKeyringFile,
  type KeyringFile,
} from './keyring.js';

const FAST_COST = { N: 2 ** 10, r: 8, p: 1 };
const REPO = 'repo-a';
const PASSPHRASE = 'correct horse battery staple';

function passphraseProvider(pass = PASSPHRASE): KeyProvider {
  return new PassphraseFileProvider(() => pass, FAST_COST);
}

describe('keyIdFor() / parseKeyId()', () => {
  it('round-trips', () => {
    const id = keyIdFor(3, 'a1b2c3d4e5f60718');
    expect(id).toBe('3.a1b2c3d4e5f60718');
    expect(parseKeyId(id)).toEqual({ generation: 3, fingerprint: 'a1b2c3d4e5f60718' });
  });

  it('rejects a malformed keyId rather than throwing', () => {
    expect(parseKeyId('not-a-keyid')).toBeNull();
    expect(parseKeyId('3.tooShort')).toBeNull();
    expect(parseKeyId('.a1b2c3d4e5f60718')).toBeNull();
  });
});

describe('createKeyring()', () => {
  it('creates generation 1 and makes it current', async () => {
    const { file } = await createKeyring(REPO, [passphraseProvider()]);
    expect(file.repoId).toBe(REPO);
    expect(file.current).toBe(1);
    expect(file.generations).toHaveLength(1);
    expect(file.generations[0]?.generation).toBe(1);
  });

  it("records the new key's real fingerprint", async () => {
    const { file, rmk } = await createKeyring(REPO, [passphraseProvider()]);
    expect(file.generations[0]?.fingerprint).toBe(keyFingerprint(rmk));
  });

  it('returns secret-marked key material', async () => {
    const { rmk } = await createKeyring(REPO, [passphraseProvider()]);
    expect(isSecret(rmk)).toBe(true);
  });

  it('wraps generation 1 with every configured provider', async () => {
    const a = new PassphraseFileProvider(() => 'passphrase for provider a!', FAST_COST);
    const b = new PassphraseFileProvider(() => 'passphrase for provider b!', FAST_COST);
    Object.defineProperty(b, 'id', { value: 'passphrase-file-b' });
    const { file } = await createKeyring(REPO, [a, b]);
    const providerIds = file.generations[0]?.wrapped.map((w) => w.provider);
    expect(providerIds).toEqual(['passphrase-file', 'passphrase-file-b']);
  });

  it('refuses to create a keyring with no providers', async () => {
    await expect(createKeyring(REPO, [])).rejects.toBeInstanceOf(KeyringError);
  });

  it('stamps createdAt as an ISO timestamp', async () => {
    const { file } = await createKeyring(REPO, [passphraseProvider()]);
    expect(() => new Date(file.generations[0]?.createdAt ?? '')).not.toThrow();
    expect(new Date(file.generations[0]?.createdAt ?? '').toISOString()).toBe(
      file.generations[0]?.createdAt,
    );
  });

  it('produces an unrelated key on every call', async () => {
    const a = await createKeyring(REPO, [passphraseProvider()]);
    const b = await createKeyring(REPO, [passphraseProvider()]);
    expect(a.rmk.equals(b.rmk)).toBe(false);
  });
});

describe('rotateKeyring()', () => {
  it('adds a new generation and advances current', async () => {
    const { file } = await createKeyring(REPO, [passphraseProvider()]);
    const { file: rotated } = await rotateKeyring(file, [passphraseProvider()]);
    expect(rotated.current).toBe(2);
    expect(rotated.generations.map((g) => g.generation)).toEqual([1, 2]);
  });

  it('keeps every earlier generation exactly as it was', async () => {
    const { file } = await createKeyring(REPO, [passphraseProvider()]);
    const before = file.generations[0];
    const { file: rotated } = await rotateKeyring(file, [passphraseProvider()]);
    expect(rotated.generations[0]).toEqual(before);
  });

  it('the new generation holds a different key from the one before it', async () => {
    const { file } = await createKeyring(REPO, [passphraseProvider()]);
    const { rmk: rmk1 } = await createKeyring(REPO, [passphraseProvider()]); // unrelated, sanity
    const { file: rotated, rmk: rmk2 } = await rotateKeyring(file, [passphraseProvider()]);
    expect(rotated.generations[1]?.fingerprint).not.toBe(file.generations[0]?.fingerprint);
    expect(rmk2.equals(rmk1)).toBe(false);
  });

  it('two rotations produce three distinct, sequential generations', async () => {
    const gen1 = await createKeyring(REPO, [passphraseProvider()]);
    const gen2 = await rotateKeyring(gen1.file, [passphraseProvider()]);
    const gen3 = await rotateKeyring(gen2.file, [passphraseProvider()]);
    expect(gen3.file.generations.map((g) => g.generation)).toEqual([1, 2, 3]);
    expect(gen3.file.current).toBe(3);
  });

  it('refuses to rotate with no providers', async () => {
    const { file } = await createKeyring(REPO, [passphraseProvider()]);
    await expect(rotateKeyring(file, [])).rejects.toBeInstanceOf(KeyringError);
  });
});

describe('unlockKeyring()', () => {
  it('recovers the exact key that was created', async () => {
    const { file, rmk } = await createKeyring(REPO, [passphraseProvider()]);
    const keys = await unlockKeyring(file, [passphraseProvider()]);
    expect(keys.current()?.rmk.equals(rmk)).toBe(true);
    expect(keys.current()?.keyId).toBe(keyIdFor(1, file.generations[0]!.fingerprint));
  });

  it('find() resolves by keyId; unknown keyIds resolve to null', async () => {
    const { file } = await createKeyring(REPO, [passphraseProvider()]);
    const keyId = keyIdFor(1, file.generations[0]!.fingerprint);
    const keys = await unlockKeyring(file, [passphraseProvider()]);
    expect(keys.find(keyId)).not.toBeNull();
    expect(keys.find('9.0000000000000000')).toBeNull();
  });

  it('available() lists exactly the keyIds it could unwrap', async () => {
    const { file } = await createKeyring(REPO, [passphraseProvider()]);
    const keyId = keyIdFor(1, file.generations[0]!.fingerprint);
    const keys = await unlockKeyring(file, [passphraseProvider()]);
    expect(keys.available()).toEqual([keyId]);
  });

  it('recovers every generation across two rotations, current() is the newest', async () => {
    const gen1 = await createKeyring(REPO, [passphraseProvider()]);
    const gen2 = await rotateKeyring(gen1.file, [passphraseProvider()]);
    const gen3 = await rotateKeyring(gen2.file, [passphraseProvider()]);

    const keys = await unlockKeyring(gen3.file, [passphraseProvider()]);
    expect(keys.available()).toHaveLength(3);
    expect(keys.current()?.rmk.equals(gen3.rmk)).toBe(true);
    expect(keys.find(keyIdFor(1, gen1.file.generations[0]!.fingerprint))?.equals(gen1.rmk)).toBe(true);
    expect(keys.find(keyIdFor(2, gen2.file.generations[1]!.fingerprint))?.equals(gen2.rmk)).toBe(true);
  });

  it('is fully locked when the passphrase is wrong', async () => {
    const { file } = await createKeyring(REPO, [passphraseProvider()]);
    const keys = await unlockKeyring(file, [passphraseProvider('a totally different passphrase')]);
    expect(keys.current()).toBeNull();
    expect(keys.available()).toEqual([]);
  });

  it('unwraps a generation via a second provider when the first fails', async () => {
    const good = new PassphraseFileProvider(() => 'the correct one, twelve+', FAST_COST);
    const alsoGood = new PassphraseFileProvider(() => 'also correct, twelve+ ok', FAST_COST);
    Object.defineProperty(alsoGood, 'id', { value: 'passphrase-file-2' });
    const { file } = await createKeyring(REPO, [good, alsoGood]);

    const wrongFirst = new PassphraseFileProvider(() => 'wrong wrong wrong wrong', FAST_COST);
    const rightSecond = new PassphraseFileProvider(() => 'also correct, twelve+ ok', FAST_COST);
    Object.defineProperty(rightSecond, 'id', { value: 'passphrase-file-2' });

    const keys = await unlockKeyring(file, [wrongFirst, rightSecond]);
    expect(keys.current()).not.toBeNull();
  });

  it('unlocks only the generations a partial keyring can reach', async () => {
    // A recipient added only from generation 2 onward.
    const original = passphraseProvider();
    const gen1 = await createKeyring(REPO, [original]);

    const late = new PassphraseFileProvider(() => 'a late-joining passphrase!!', FAST_COST);
    Object.defineProperty(late, 'id', { value: 'passphrase-file-late' });
    const gen2 = await rotateKeyring(gen1.file, [original, late]);

    const lateOnly = new PassphraseFileProvider(() => 'a late-joining passphrase!!', FAST_COST);
    Object.defineProperty(lateOnly, 'id', { value: 'passphrase-file-late' });

    const keys = await unlockKeyring(gen2.file, [lateOnly]);
    expect(keys.find(keyIdFor(1, gen1.file.generations[0]!.fingerprint))).toBeNull();
    expect(keys.find(keyIdFor(2, gen2.file.generations[1]!.fingerprint))).not.toBeNull();
    expect(keys.current()?.rmk.equals(gen2.rmk)).toBe(true);
  });

  it('reports a fingerprint mismatch as a diagnostic, not silently', async () => {
    const { file } = await createKeyring(REPO, [passphraseProvider()]);
    const corrupt: KeyringFile = {
      ...file,
      generations: [{ ...file.generations[0]!, fingerprint: '0000000000000000' }],
    };
    const warn = vi.fn();
    const keys = await unlockKeyring(corrupt, [passphraseProvider()], { warn });
    expect(keys.current()).toBeNull();
    expect(warn).toHaveBeenCalledOnce();
    const message = String(warn.mock.calls[0]?.[0]);
    expect(message).toContain('0000000000000000');
    expect(message).toContain(file.generations[0]!.fingerprint);
  });

  it('never puts the passphrase or the master key in a warning', async () => {
    const { file } = await createKeyring(REPO, [passphraseProvider()]);
    const warn = vi.fn();
    await unlockKeyring(file, [passphraseProvider('a totally different passphrase')], { warn });
    // No warning is expected here — a wrong passphrase is silent (locked),
    // this just guards against a future implementation that logs the attempt.
    for (const call of warn.mock.calls) {
      expect(String(call[0])).not.toContain(PASSPHRASE);
      expect(String(call[0])).not.toContain('a totally different passphrase');
    }
  });

  it('current() is null when the current generation cannot be unwrapped, even if others can', async () => {
    const gen1 = await createKeyring(REPO, [passphraseProvider()]);
    const different = passphraseProvider('a different passphrase entirely');
    const gen2 = await rotateKeyring(gen1.file, [different]);

    // Holds only the generation-1 provider's passphrase.
    const keys = await unlockKeyring(gen2.file, [passphraseProvider()]);
    expect(keys.current()).toBeNull();
    expect(keys.find(keyIdFor(1, gen1.file.generations[0]!.fingerprint))).not.toBeNull();
  });

  it('rejects a keyring written for a different repository, naming both ids (F19)', async () => {
    const { file } = await createKeyring(REPO, [passphraseProvider()]);
    await expect(
      unlockKeyring(file, [passphraseProvider()], { expectedRepoId: 'a-different-repo-id' }),
    ).rejects.toThrow(KeyringError);

    try {
      await unlockKeyring(file, [passphraseProvider()], { expectedRepoId: 'a-different-repo-id' });
      expect.unreachable();
    } catch (e) {
      const message = (e as Error).message;
      expect(message).toContain(REPO);
      expect(message).toContain('a-different-repo-id');
    }
  });

  it('does not attempt to unwrap anything when the repoId check fails', async () => {
    const { file } = await createKeyring(REPO, [passphraseProvider()]);
    const warn = vi.fn();
    await expect(
      unlockKeyring(file, [passphraseProvider()], { expectedRepoId: 'a-different-repo-id', warn }),
    ).rejects.toThrow();
    // A fingerprint-mismatch warning, or any provider call, would mean it
    // tried to unwrap before checking the repository — the check must come first.
    expect(warn).not.toHaveBeenCalled();
  });

  it('skips the repoId check when no expectedRepoId is given', async () => {
    const { file, rmk } = await createKeyring(REPO, [passphraseProvider()]);
    const keys = await unlockKeyring(file, [passphraseProvider()]);
    expect(keys.current()?.rmk.equals(rmk)).toBe(true);
  });
});

describe('bridges to filter.ts\'s KeySource contract', () => {
  it('clean/smudge round-trip through a real unlocked keyring', async () => {
    const { file } = await createKeyring(REPO, [passphraseProvider()]);
    const keys = await unlockKeyring(file, [passphraseProvider()]);
    const pt = Buffer.from('{"timeout":30}\n');
    const path = 'config/production.json';
    const out = clean(pt, { keys, path });
    expect(smudge(out, { keys, path }).equals(pt)).toBe(true);
  });

  it('clean fails closed against a locked keyring', async () => {
    const { file } = await createKeyring(REPO, [passphraseProvider()]);
    const keys = await unlockKeyring(file, [passphraseProvider('wrong wrong wrong wrong')]);
    expect(() => clean(Buffer.from('x'), { keys, path: 'a.env' })).toThrow(LockedError);
  });

  it('smudge fails open against a locked keyring, decrypting nothing', async () => {
    const { file } = await createKeyring(REPO, [passphraseProvider()]);
    const unlocked = await unlockKeyring(file, [passphraseProvider()]);
    const envelope = clean(Buffer.from('secret'), { keys: unlocked, path: 'a.env' });

    const locked = await unlockKeyring(file, [passphraseProvider('wrong wrong wrong wrong')]);
    const warn = vi.fn();
    expect(smudge(envelope, { keys: locked, path: 'a.env', warn }).equals(envelope)).toBe(true);
    expect(warn).toHaveBeenCalled();
  });

  it('an old envelope survives two rotations', async () => {
    const gen1 = await createKeyring(REPO, [passphraseProvider()]);
    const path = 'config/production.json';
    const keys1 = await unlockKeyring(gen1.file, [passphraseProvider()]);
    const envelope = clean(Buffer.from('original secret'), { keys: keys1, path });

    const gen2 = await rotateKeyring(gen1.file, [passphraseProvider()]);
    const gen3 = await rotateKeyring(gen2.file, [passphraseProvider()]);
    const keysFinal = await unlockKeyring(gen3.file, [passphraseProvider()]);

    expect(smudge(envelope, { keys: keysFinal, path }).equals(Buffer.from('original secret'))).toBe(true);
  });
});

describe('writeKeyringFile() / readKeyringFile()', () => {
  let dir: string;

  afterEach(async () => {
    if (dir) await rm(dir, { recursive: true, force: true });
  });

  it('round-trips through disk', async () => {
    dir = await mkdtemp(join(tmpdir(), 'securegit-keyring-'));
    const { file } = await createKeyring(REPO, [passphraseProvider()]);
    const path = join(dir, 'keyring.json');
    await writeKeyringFile(path, file);
    expect(await readKeyringFile(path)).toEqual(file);
  });

  it('creates the file with mode 0600', async () => {
    dir = await mkdtemp(join(tmpdir(), 'securegit-keyring-'));
    const { file } = await createKeyring(REPO, [passphraseProvider()]);
    const path = join(dir, 'keyring.json');
    await writeKeyringFile(path, file);
    const mode = (await stat(path)).mode & 0o777;
    expect(mode).toBe(0o600);
  });

  it('creates missing parent directories', async () => {
    dir = await mkdtemp(join(tmpdir(), 'securegit-keyring-'));
    const { file } = await createKeyring(REPO, [passphraseProvider()]);
    const path = join(dir, 'nested', 'deeper', 'keyring.json');
    await writeKeyringFile(path, file);
    expect(await readKeyringFile(path)).toEqual(file);
  });

  it('fully overwrites existing content rather than merging', async () => {
    dir = await mkdtemp(join(tmpdir(), 'securegit-keyring-'));
    const a = await createKeyring(REPO, [passphraseProvider()]);
    const b = await createKeyring('repo-b', [passphraseProvider()]);
    const path = join(dir, 'keyring.json');
    await writeKeyringFile(path, a.file);
    await writeKeyringFile(path, b.file);
    expect(await readKeyringFile(path)).toEqual(b.file);
  });

  it('leaves no stray temp file behind after a successful write', async () => {
    dir = await mkdtemp(join(tmpdir(), 'securegit-keyring-'));
    const { file } = await createKeyring(REPO, [passphraseProvider()]);
    await writeKeyringFile(join(dir, 'keyring.json'), file);
    const entries = await readdir(dir);
    expect(entries).toEqual(['keyring.json']);
  });

  it('reading a missing file throws rather than returning an empty keyring', async () => {
    dir = await mkdtemp(join(tmpdir(), 'securegit-keyring-'));
    await expect(readKeyringFile(join(dir, 'nope.json'))).rejects.toThrow();
  });

  it('a write failure leaves the previously written file untouched (F11)', async () => {
    dir = await mkdtemp(join(tmpdir(), 'securegit-keyring-'));
    const good = await createKeyring(REPO, [passphraseProvider()]);
    const bad = await createKeyring('repo-b', [passphraseProvider()]);
    const path = join(dir, 'keyring.json');
    await writeKeyringFile(path, good.file);

    // Read-only directory: the temp file can't even be created, simulating
    // a write failure before anything about `path` itself is touched.
    await chmod(dir, 0o500);
    try {
      await expect(writeKeyringFile(path, bad.file)).rejects.toThrow();
    } finally {
      await chmod(dir, 0o700); // restore so afterEach can remove it
    }

    expect(await readKeyringFile(path)).toEqual(good.file);
  });

  it('cleans up its temp file when the final rename fails', async () => {
    dir = await mkdtemp(join(tmpdir(), 'securegit-keyring-'));
    const path = join(dir, 'keyring.json');
    await mkdir(path); // occupies the target path itself, so rename onto it fails
    const { file } = await createKeyring(REPO, [passphraseProvider()]);

    await expect(writeKeyringFile(path, file)).rejects.toThrow();

    const entries = await readdir(dir);
    expect(entries).toEqual(['keyring.json']); // only the directory — no leftover tmp-*
  });
});
