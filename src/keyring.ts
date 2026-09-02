// Generations, persistence, and the bridge from KeyProvider to KeySource.
//
// A keyring is a list of generations, each holding the same master key
// wrapped by every provider configured for it. Unlocking tries every wrapped
// slot a generation has and returns whichever the caller's providers can
// open — the filter never needs to know how many providers exist or which
// one succeeded.
// See specs/securegit/05-key-hierarchy.md and 06-key-provider-port.md.

import { mkdir, readFile, rename, writeFile, unlink } from 'node:fs/promises';
import { dirname } from 'node:path';
import { randomBytes } from 'node:crypto';
import { equalCt, keyFingerprint, secret, type Secret } from './crypto.js';
import type { KeyProvider, ProviderState, WrappedKey } from './provider.js';
import type { KeySource } from './filter.js';

export class KeyringError extends Error {
  readonly code = 'KEYRING';

  constructor(message: string) {
    super(message);
    this.name = 'KeyringError';
  }
}

export interface WrappedKeySlot {
  provider: string;
  /** The provider's own state for this generation — e.g. a scrypt salt. */
  state: ProviderState;
  payload: WrappedKey['payload'];
}

export interface KeyringGeneration {
  generation: number;
  fingerprint: string;
  createdAt: string;
  wrapped: WrappedKeySlot[];
}

export interface KeyringFile {
  version: 1;
  repoId: string;
  current: number;
  generations: KeyringGeneration[];
}

const KEY_ID_RE = /^([0-9]+)\.([0-9a-f]{16})$/;

export function keyIdFor(generation: number, fingerprint: string): string {
  return `${generation}.${fingerprint}`;
}

export function parseKeyId(keyId: string): { generation: number; fingerprint: string } | null {
  const m = KEY_ID_RE.exec(keyId);
  if (!m) return null;
  return { generation: Number(m[1]), fingerprint: m[2]! };
}

async function wrapForEveryProvider(
  rmk: Buffer,
  repoId: string,
  generation: number,
  providers: KeyProvider[],
): Promise<WrappedKeySlot[]> {
  const slots: WrappedKeySlot[] = [];
  for (const provider of providers) {
    const state = await provider.init({ repoId, generation });
    const wrapped = await provider.wrap(rmk, { repoId, generation, state, interactive: true });
    slots.push({ provider: provider.id, state, payload: wrapped.payload });
  }
  return slots;
}

function requireProviders(providers: KeyProvider[]): void {
  if (providers.length === 0) {
    throw new KeyringError('at least one key provider is required');
  }
}

/** Generates generation 1 and wraps it with every given provider. */
export async function createKeyring(
  repoId: string,
  providers: KeyProvider[],
): Promise<{ file: KeyringFile; rmk: Secret }> {
  requireProviders(providers);
  const rmk = secret(randomBytes(32));
  const generation = 1;
  const wrapped = await wrapForEveryProvider(rmk, repoId, generation, providers);

  const file: KeyringFile = {
    version: 1,
    repoId,
    current: generation,
    generations: [
      {
        generation,
        fingerprint: keyFingerprint(rmk),
        createdAt: new Date().toISOString(),
        wrapped,
      },
    ],
  };
  return { file, rmk };
}

/**
 * Adds a new generation on top of `file`. Every earlier generation is kept
 * verbatim — rotation changes who can read what is committed *next*, never
 * what already exists.
 */
export async function rotateKeyring(
  file: KeyringFile,
  providers: KeyProvider[],
): Promise<{ file: KeyringFile; rmk: Secret }> {
  requireProviders(providers);
  const rmk = secret(randomBytes(32));
  const generation = file.current + 1;
  const wrapped = await wrapForEveryProvider(rmk, file.repoId, generation, providers);

  const next: KeyringFile = {
    ...file,
    current: generation,
    generations: [
      ...file.generations,
      {
        generation,
        fingerprint: keyFingerprint(rmk),
        createdAt: new Date().toISOString(),
        wrapped,
      },
    ],
  };
  return { file: next, rmk };
}

export interface UnlockOptions {
  /** Never receives plaintext or key material. Defaults to a no-op. */
  warn?: (message: string) => void;
  /**
   * The repository being unlocked, when known. A mismatch here (F19,
   * 15-failure-modes.md) means this keyring file was written for a different
   * repository — a manual copy, a moved directory, the wrong `repoId`
   * resolved — and every provider would fail to unwrap it anyway, since each
   * one binds `repoId` into its wrap AAD. Checking first turns that into one
   * clear message naming both ids, instead of "wrong passphrase" everywhere.
   */
  expectedRepoId?: string;
}

/**
 * Tries every wrapped slot of every generation against the given providers,
 * and returns whatever `filter.ts` needs — nothing more. A provider that
 * fails to unwrap a slot (wrong passphrase, wrong machine) is not an error
 * here: the next slot, or the next generation, may still succeed.
 */
export async function unlockKeyring(
  file: KeyringFile,
  providers: KeyProvider[],
  opts: UnlockOptions = {},
): Promise<KeySource> {
  if (opts.expectedRepoId !== undefined && file.repoId !== opts.expectedRepoId) {
    throw new KeyringError(
      `securegit: this keyring belongs to repository ${file.repoId}\n` +
        `  this repository is ${opts.expectedRepoId}\n` +
        `  action: use the keyring for ${opts.expectedRepoId}, or \`securegit key import-recovery\``,
    );
  }

  const warn = opts.warn ?? ((): void => {});
  const byId = new Map(providers.map((p) => [p.id, p]));
  const held = new Map<string, Secret>();

  for (const gen of file.generations) {
    const keyId = keyIdFor(gen.generation, gen.fingerprint);
    for (const slot of gen.wrapped) {
      const provider = byId.get(slot.provider);
      if (!provider) continue;

      let rmk: Buffer;
      try {
        rmk = await provider.unwrap(
          { provider: slot.provider, payload: slot.payload },
          { repoId: file.repoId, generation: gen.generation, state: slot.state, interactive: true },
        );
      } catch {
        continue;
      }

      const fingerprint = keyFingerprint(rmk);
      if (!equalCt(Buffer.from(fingerprint, 'hex'), Buffer.from(gen.fingerprint, 'hex'))) {
        warn(
          `securegit: keyring inconsistency at generation ${gen.generation}\n` +
            `  expected fingerprint ${gen.fingerprint}, unwrapped key has ${fingerprint}\n` +
            `  action: this keyring file may be corrupted; verify it came from a trusted source`,
        );
        continue;
      }

      held.set(keyId, secret(rmk));
      break; // this generation is unlocked; no need to try remaining slots
    }
  }

  const currentGen = file.generations.find((g) => g.generation === file.current) ?? null;
  const currentKeyId = currentGen ? keyIdFor(currentGen.generation, currentGen.fingerprint) : null;

  return {
    current(): { keyId: string; rmk: Buffer } | null {
      if (currentKeyId === null) return null;
      const rmk = held.get(currentKeyId);
      return rmk ? { keyId: currentKeyId, rmk } : null;
    },
    find(keyId: string): Buffer | null {
      return held.get(keyId) ?? null;
    },
    available(): string[] {
      return [...held.keys()];
    },
  };
}

/**
 * Writes the keyring atomically (temp file + rename, so a crash mid-write
 * cannot leave a half-written file) with mode 0600, creating parent
 * directories as needed.
 */
export async function writeKeyringFile(path: string, file: KeyringFile): Promise<void> {
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

export async function readKeyringFile(path: string): Promise<KeyringFile> {
  const raw = await readFile(path, 'utf8');
  return JSON.parse(raw) as KeyringFile;
}
