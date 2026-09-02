import { describe, it, expect } from 'vitest';
import { mkdtemp, rm, readFile, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { keyFingerprint } from './crypto.js';
import { generateX25519KeyPair, type X25519KeyPair } from './identity.js';
import type { KeySource } from './filter.js';
import {
  RecipientError,
  wrapForRecipient,
  unwrapForRecipient,
  wrapAllGenerations,
  unlockFromRecipientFile,
  recipientsDir,
  recipientPath,
  writeRecipientFile,
  readRecipientFile,
  removedRecipientsLogPath,
  appendRemovedRecipientLogEntry,
  readRemovedRecipientsLog,
  type RecipientFile,
} from './recipients.js';

const REPO_ID = 'repo-a';
const RMK = Buffer.alloc(32, 0xa5);
const RMK_FINGERPRINT = keyFingerprint(RMK);

describe('wrapForRecipient() / unwrapForRecipient()', () => {
  it('round-trips the master key', () => {
    const recipient = generateX25519KeyPair();
    const wrapped = wrapForRecipient({
      recipientPublicKey: recipient.publicKey,
      repoId: REPO_ID,
      generation: 1,
      fingerprint: RMK_FINGERPRINT,
      rmk: RMK,
    });

    const recovered = unwrapForRecipient({
      identityKeyPair: recipient,
      wrapped,
      repoId: REPO_ID,
      generation: 1,
      fingerprint: RMK_FINGERPRINT,
    });
    expect(recovered.equals(RMK)).toBe(true);
  });

  it('a different identity cannot unwrap', () => {
    const recipient = generateX25519KeyPair();
    const attacker = generateX25519KeyPair();
    const wrapped = wrapForRecipient({
      recipientPublicKey: recipient.publicKey,
      repoId: REPO_ID,
      generation: 1,
      fingerprint: RMK_FINGERPRINT,
      rmk: RMK,
    });

    expect(() =>
      unwrapForRecipient({
        identityKeyPair: attacker,
        wrapped,
        repoId: REPO_ID,
        generation: 1,
        fingerprint: RMK_FINGERPRINT,
      }),
    ).toThrow(RecipientError);
  });

  it('wrapping bound to repoId fails elsewhere', () => {
    const recipient = generateX25519KeyPair();
    const wrapped = wrapForRecipient({
      recipientPublicKey: recipient.publicKey,
      repoId: REPO_ID,
      generation: 1,
      fingerprint: RMK_FINGERPRINT,
      rmk: RMK,
    });

    expect(() =>
      unwrapForRecipient({
        identityKeyPair: recipient,
        wrapped,
        repoId: 'a-different-repo',
        generation: 1,
        fingerprint: RMK_FINGERPRINT,
      }),
    ).toThrow(RecipientError);
  });

  it('wrapping bound to generation fails on another generation', () => {
    const recipient = generateX25519KeyPair();
    const wrapped = wrapForRecipient({
      recipientPublicKey: recipient.publicKey,
      repoId: REPO_ID,
      generation: 1,
      fingerprint: RMK_FINGERPRINT,
      rmk: RMK,
    });

    expect(() =>
      unwrapForRecipient({
        identityKeyPair: recipient,
        wrapped,
        repoId: REPO_ID,
        generation: 2,
        fingerprint: RMK_FINGERPRINT,
      }),
    ).toThrow(RecipientError);
  });

  it('wrapping bound to fingerprint fails if the fingerprint is wrong', () => {
    const recipient = generateX25519KeyPair();
    const wrapped = wrapForRecipient({
      recipientPublicKey: recipient.publicKey,
      repoId: REPO_ID,
      generation: 1,
      fingerprint: RMK_FINGERPRINT,
      rmk: RMK,
    });

    expect(() =>
      unwrapForRecipient({
        identityKeyPair: recipient,
        wrapped,
        repoId: REPO_ID,
        generation: 1,
        fingerprint: '0000000000000000',
      }),
    ).toThrow(RecipientError);
  });

  it('two wraps for one recipient use different ephemeral keys', () => {
    const recipient = generateX25519KeyPair();
    const a = wrapForRecipient({
      recipientPublicKey: recipient.publicKey,
      repoId: REPO_ID,
      generation: 1,
      fingerprint: RMK_FINGERPRINT,
      rmk: RMK,
    });
    const b = wrapForRecipient({
      recipientPublicKey: recipient.publicKey,
      repoId: REPO_ID,
      generation: 1,
      fingerprint: RMK_FINGERPRINT,
      rmk: RMK,
    });
    expect(a.ephemeral).not.toBe(b.ephemeral);
    expect(a.payload).not.toBe(b.payload);
  });

  it('never puts the master key in the wrapped payload in the clear', () => {
    const recipient = generateX25519KeyPair();
    const wrapped = wrapForRecipient({
      recipientPublicKey: recipient.publicKey,
      repoId: REPO_ID,
      generation: 1,
      fingerprint: RMK_FINGERPRINT,
      rmk: RMK,
    });
    expect(wrapped.payload).not.toContain(RMK.toString('hex'));
  });
});

describe('wrapAllGenerations()', () => {
  const KEY_ID_1 = '1.aaaaaaaaaaaaaaaa';
  const KEY_ID_2 = '2.bbbbbbbbbbbbbbbb';
  const RMK_1 = Buffer.alloc(32, 0x11);
  const RMK_2 = Buffer.alloc(32, 0x22);

  function fakeKeys(): KeySource {
    const held = new Map([
      [KEY_ID_1, RMK_1],
      [KEY_ID_2, RMK_2],
    ]);
    return {
      current: () => ({ keyId: KEY_ID_2, rmk: RMK_2 }),
      find: (keyId) => held.get(keyId) ?? null,
      available: () => [...held.keys()],
    };
  }

  it('wraps every generation the caller currently holds', () => {
    const recipient = generateX25519KeyPair();
    const wrapped = wrapAllGenerations(fakeKeys(), fakeKeys().available(), recipient.publicKey, REPO_ID);

    expect(Object.keys(wrapped).sort()).toEqual(['1', '2']);
    expect(
      unwrapForRecipient({
        identityKeyPair: recipient,
        wrapped: wrapped['1']!,
        repoId: REPO_ID,
        generation: 1,
        fingerprint: 'aaaaaaaaaaaaaaaa',
      }).equals(RMK_1),
    ).toBe(true);
    expect(
      unwrapForRecipient({
        identityKeyPair: recipient,
        wrapped: wrapped['2']!,
        repoId: REPO_ID,
        generation: 2,
        fingerprint: 'bbbbbbbbbbbbbbbb',
      }).equals(RMK_2),
    ).toBe(true);
  });

  it('skips a keyId it does not actually hold', () => {
    const recipient = generateX25519KeyPair();
    const keys = fakeKeys();
    const wrapped = wrapAllGenerations(keys, [...keys.available(), '9.cccccccccccccccc'], recipient.publicKey, REPO_ID);
    expect(Object.keys(wrapped).sort()).toEqual(['1', '2']);
  });

  it('skips a malformed keyId rather than throwing', () => {
    const recipient = generateX25519KeyPair();
    const keys = fakeKeys();
    const wrapped = wrapAllGenerations(keys, [...keys.available(), 'not-a-keyid'], recipient.publicKey, REPO_ID);
    expect(Object.keys(wrapped).sort()).toEqual(['1', '2']);
  });
});

describe('unlockFromRecipientFile()', () => {
  function fileFor(recipient: X25519KeyPair, generations: Record<string, Buffer>): RecipientFile {
    const owner = generateX25519KeyPair();
    const keys: RecipientFile['keys'] = {};
    for (const [gen, rmk] of Object.entries(generations)) {
      keys[gen] = wrapForRecipient({
        recipientPublicKey: recipient.publicKey,
        repoId: REPO_ID,
        generation: Number(gen),
        fingerprint: keyFingerprint(rmk),
        rmk,
      });
    }
    return {
      version: 1,
      fingerprint: 'irrelevant-here',
      publicKey: 'SGPUB1irrelevant',
      label: 'laptop',
      addedAt: new Date().toISOString(),
      addedBy: keyFingerprint(owner.publicKey),
      keys,
    };
  }

  it('unwraps every generation it holds, current() is the highest', () => {
    const recipient = generateX25519KeyPair();
    const rmk1 = Buffer.alloc(32, 0x11);
    const rmk2 = Buffer.alloc(32, 0x22);
    const file = fileFor(recipient, { '1': rmk1, '2': rmk2 });

    const keys = unlockFromRecipientFile(file, recipient, REPO_ID);
    expect(keys.available()).toHaveLength(2);
    expect(keys.current()?.rmk.equals(rmk2)).toBe(true);
    expect(keys.find(`1.${keyFingerprint(rmk1)}`)?.equals(rmk1)).toBe(true);
    expect(keys.find(`2.${keyFingerprint(rmk2)}`)?.equals(rmk2)).toBe(true);
  });

  it('a partial file (joined late) only unlocks the generations it was given', () => {
    const recipient = generateX25519KeyPair();
    const rmk2 = Buffer.alloc(32, 0x22);
    const file = fileFor(recipient, { '2': rmk2 });

    const keys = unlockFromRecipientFile(file, recipient, REPO_ID);
    expect(keys.available()).toHaveLength(1);
    expect(keys.current()?.rmk.equals(rmk2)).toBe(true);
  });

  it('the wrong identity unlocks nothing, without throwing', () => {
    const recipient = generateX25519KeyPair();
    const impostor = generateX25519KeyPair();
    const rmk1 = Buffer.alloc(32, 0x11);
    const file = fileFor(recipient, { '1': rmk1 });

    const keys = unlockFromRecipientFile(file, impostor, REPO_ID);
    expect(keys.available()).toEqual([]);
    expect(keys.current()).toBeNull();
  });

  it('a mismatched repoId unlocks nothing', () => {
    const recipient = generateX25519KeyPair();
    const rmk1 = Buffer.alloc(32, 0x11);
    const file = fileFor(recipient, { '1': rmk1 });

    const keys = unlockFromRecipientFile(file, recipient, 'a-different-repo');
    expect(keys.available()).toEqual([]);
  });
});

describe('recipientsDir() / recipientPath() / writeRecipientFile() / readRecipientFile()', () => {
  it('resolves the path under .securegit/recipients/<fingerprint>.json', () => {
    expect(recipientsDir('/repo')).toBe(join('/repo', '.securegit', 'recipients'));
    expect(recipientPath('/repo', '7c1e4a09b2d5f836')).toBe(
      join('/repo', '.securegit', 'recipients', '7c1e4a09b2d5f836.json'),
    );
  });

  it('round-trips through disk with ordinary (non-0600) permissions — these files are meant to be committed', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'securegit-recipients-'));
    try {
      const recipient = generateX25519KeyPair();
      const rmk = Buffer.alloc(32, 0x11);
      const file: RecipientFile = {
        version: 1,
        fingerprint: 'abc',
        publicKey: 'SGPUB1x',
        label: 'laptop',
        addedAt: new Date().toISOString(),
        addedBy: 'def',
        keys: {
          '1': wrapForRecipient({
            recipientPublicKey: recipient.publicKey,
            repoId: REPO_ID,
            generation: 1,
            fingerprint: keyFingerprint(rmk),
            rmk,
          }),
        },
      };
      const path = recipientPath(dir, 'abc');
      await writeRecipientFile(path, file);
      expect(await readRecipientFile(path)).toEqual(file);

      const mode = (await stat(path)).mode & 0o777;
      expect(mode).not.toBe(0o600); // not secret — ordinary umask-governed permissions
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe('removedRecipientsLogPath() / appendRemovedRecipientLogEntry() / readRemovedRecipientsLog()', () => {
  it('resolves to .securegit/removed-recipients.json', () => {
    expect(removedRecipientsLogPath('/repo')).toBe(join('/repo', '.securegit', 'removed-recipients.json'));
  });

  it('records the event, never the still-wrapped keys', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'securegit-removed-recipients-log-'));
    try {
      const path = removedRecipientsLogPath(dir);
      const entry = {
        fingerprint: 'abc123',
        label: 'contractor',
        removedAt: new Date().toISOString(),
        removedBy: '',
        generations: [1, 2],
      };
      const log = await appendRemovedRecipientLogEntry(path, entry);
      expect(log).toEqual([entry]);
      expect(await readRemovedRecipientsLog(path)).toEqual([entry]);

      const raw = await readFile(path, 'utf8');
      expect(raw).not.toContain('payload'); // never a WrappedGeneration's ciphertext
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('appends rather than overwriting', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'securegit-removed-recipients-log-'));
    try {
      const path = removedRecipientsLogPath(dir);
      const first = {
        fingerprint: 'abc123',
        label: 'contractor',
        removedAt: new Date().toISOString(),
        removedBy: '',
        generations: [1],
      };
      const second = {
        fingerprint: 'def456',
        label: 'temp-hire',
        removedAt: new Date().toISOString(),
        removedBy: 'abc123',
        generations: [1, 2, 3],
      };
      await appendRemovedRecipientLogEntry(path, first);
      const log = await appendRemovedRecipientLogEntry(path, second);
      expect(log).toEqual([first, second]);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('reading a missing log returns an empty array, not an error', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'securegit-removed-recipients-log-'));
    try {
      expect(await readRemovedRecipientsLog(removedRecipientsLogPath(dir))).toEqual([]);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

