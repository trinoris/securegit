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
import { DEFAULT_SCRYPT_N, type KeyProvider, type ProviderState, type WrappedKey } from './provider.js';
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

export interface RecoveredGeneration {
  generation: number;
  rmk: Buffer;
}

/**
 * Builds a full keyring from already-known generations — e.g. recovered via
 * `recovery.ts`'s `importRecovery`. Unlike `createKeyring` (always a fresh
 * generation 1) or `rotateKeyring` (always exactly one new generation on top
 * of an existing file), this wraps an arbitrary, already-determined set of
 * generations for a brand-new provider, which is what makes a machine that
 * just imported a recovery file "a full holder" — able to rotate, add
 * recipients, and re-export from here on.
 */
export async function keyringFromRecoveredGenerations(
  repoId: string,
  recovered: RecoveredGeneration[],
  providers: KeyProvider[],
): Promise<KeyringFile> {
  requireProviders(providers);
  if (recovered.length === 0) {
    throw new KeyringError('no generations to build a keyring from');
  }

  const generations: KeyringGeneration[] = [];
  let current = 0;
  for (const { generation, rmk } of recovered) {
    const wrapped = await wrapForEveryProvider(rmk, repoId, generation, providers);
    generations.push({
      generation,
      fingerprint: keyFingerprint(rmk),
      createdAt: new Date().toISOString(),
      wrapped,
    });
    if (generation > current) current = generation;
  }
  generations.sort((a, b) => a.generation - b.generation);

  return { version: 1, repoId, current, generations };
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
 * "Parameters are stored in the keyring so they can be raised later without
 * breaking existing keyrings; a keyring wrapped at 2^16 is re-wrapped at
 * the new cost on the next successful unlock" (06-key-provider-port.md).
 * Deliberately separate from `unlockKeyring()` itself, which stays a pure
 * read — every filter-time unwrap (`loadKeys()`'s `SECUREGIT_PASSPHRASE`
 * source included) goes through that same function, and a filter must
 * never write to disk. Only `cmdUnlock`, the one place a real `unlock`
 * happens, calls this, and only after a successful unlock already produced
 * `keys`.
 *
 * Only `passphrase-file` has a cost to raise (`state.N`); slots from any
 * other provider are left untouched — there's nothing generic about "raise
 * the cost" across providers yet, and only one provider exists to prove it
 * against. A generation this unlock didn't actually hold (`keys.find()`
 * returns `null`) is left as-is too — there is no RMK on hand to re-wrap.
 */
export async function rewrapOutdatedGenerations(
  file: KeyringFile,
  providers: KeyProvider[],
  keys: KeySource,
): Promise<{ file: KeyringFile; changed: boolean }> {
  const byId = new Map(providers.map((p) => [p.id, p]));
  let changed = false;

  const generations = await Promise.all(
    file.generations.map(async (gen) => {
      const keyId = keyIdFor(gen.generation, gen.fingerprint);
      const rmk = keys.find(keyId);
      if (!rmk) return gen;

      const wrapped = await Promise.all(
        gen.wrapped.map(async (slot) => {
          if (slot.provider !== 'passphrase-file') return slot;
          const n = slot.state.N;
          if (typeof n !== 'number' || n >= DEFAULT_SCRYPT_N) return slot;

          const provider = byId.get(slot.provider);
          if (!provider) return slot;

          const state = await provider.init({ repoId: file.repoId, generation: gen.generation });
          const rewrapped = await provider.wrap(rmk, {
            repoId: file.repoId,
            generation: gen.generation,
            state,
            interactive: true,
          });
          changed = true;
          return { provider: rewrapped.provider, state, payload: rewrapped.payload };
        }),
      );
      return { ...gen, wrapped };
    }),
  );

  return { file: { ...file, generations }, changed };
}

/**
 * `key add-provider` (06-key-provider-port.md): wraps every generation
 * for a new provider, alongside whatever already wraps it. Refuses if
 * `provider.id` already has a slot anywhere in the keyring — `unlockKeyring()`
 * looks providers up by id, so a second provider sharing one would
 * silently shadow the first during unlock rather than genuinely offering
 * an independent way in. Refuses just as hard if `keys` doesn't hold every
 * generation — a partial add would leave the keyring in a state where the
 * new provider unlocks some generations but not others, which is worse
 * than not adding it at all.
 */
export async function addProvider(
  file: KeyringFile,
  provider: KeyProvider,
  keys: KeySource,
): Promise<KeyringFile> {
  const alreadyPresent = file.generations.some((gen) => gen.wrapped.some((w) => w.provider === provider.id));
  if (alreadyPresent) {
    throw new KeyringError(
      `securegit: a provider with id '${provider.id}' is already wrapped in this keyring\n` +
        `  action: choose a different id (e.g. a distinct --label)`,
    );
  }

  const generations = await Promise.all(
    file.generations.map(async (gen) => {
      const keyId = keyIdFor(gen.generation, gen.fingerprint);
      const rmk = keys.find(keyId);
      if (!rmk) {
        throw new KeyringError(
          `securegit: cannot add a provider — this session does not hold generation ${gen.generation}\n` +
            `  action: \`securegit unlock\` first, holding every generation`,
        );
      }
      const state = await provider.init({ repoId: file.repoId, generation: gen.generation });
      const wrapped = await provider.wrap(rmk, {
        repoId: file.repoId,
        generation: gen.generation,
        state,
        interactive: true,
      });
      return {
        ...gen,
        wrapped: [...gen.wrapped, { provider: wrapped.provider, state, payload: wrapped.payload }],
      };
    }),
  );

  return { ...file, generations };
}

/**
 * `key remove-provider` (06-key-provider-port.md): deletes `id`'s wrapped
 * slot from every generation. Refuses (per-generation) if doing so would
 * leave that generation with no provider at all — the last way to unlock
 * a generation must never be removed — and refuses outright if `id` was
 * never present anywhere in the keyring.
 */
export function removeProvider(file: KeyringFile, id: string): KeyringFile {
  const everPresent = file.generations.some((gen) => gen.wrapped.some((w) => w.provider === id));
  if (!everPresent) {
    throw new KeyringError(`securegit: no provider with id '${id}' found in this keyring`);
  }

  const generations = file.generations.map((gen) => {
    const remaining = gen.wrapped.filter((w) => w.provider !== id);
    if (remaining.length === gen.wrapped.length) return gen;
    if (remaining.length === 0) {
      throw new KeyringError(
        `securegit: refusing to remove '${id}' — it is the only provider that can unlock generation ${gen.generation}`,
      );
    }
    return { ...gen, wrapped: remaining };
  });

  return { ...file, generations };
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
