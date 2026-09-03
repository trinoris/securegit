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
import { equalCt, keyFingerprint, secret } from './crypto.js';
import { DEFAULT_SCRYPT_N } from './provider.js';
export class KeyringError extends Error {
    code = 'KEYRING';
    constructor(message) {
        super(message);
        this.name = 'KeyringError';
    }
}
const KEY_ID_RE = /^([0-9]+)\.([0-9a-f]{16})$/;
export function keyIdFor(generation, fingerprint) {
    return `${generation}.${fingerprint}`;
}
export function parseKeyId(keyId) {
    const m = KEY_ID_RE.exec(keyId);
    if (!m)
        return null;
    return { generation: Number(m[1]), fingerprint: m[2] };
}
async function wrapForEveryProvider(rmk, repoId, generation, providers) {
    const slots = [];
    for (const provider of providers) {
        const state = await provider.init({ repoId, generation });
        const wrapped = await provider.wrap(rmk, { repoId, generation, state, interactive: true });
        slots.push({ provider: provider.id, state, payload: wrapped.payload });
    }
    return slots;
}
function requireProviders(providers) {
    if (providers.length === 0) {
        throw new KeyringError('at least one key provider is required');
    }
}
/** Generates generation 1 and wraps it with every given provider. */
export async function createKeyring(repoId, providers) {
    requireProviders(providers);
    const rmk = secret(randomBytes(32));
    const generation = 1;
    const wrapped = await wrapForEveryProvider(rmk, repoId, generation, providers);
    const file = {
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
export async function rotateKeyring(file, providers) {
    requireProviders(providers);
    const rmk = secret(randomBytes(32));
    const generation = file.current + 1;
    const wrapped = await wrapForEveryProvider(rmk, file.repoId, generation, providers);
    const next = {
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
/**
 * Builds a full keyring from already-known generations — e.g. recovered via
 * `recovery.ts`'s `importRecovery`. Unlike `createKeyring` (always a fresh
 * generation 1) or `rotateKeyring` (always exactly one new generation on top
 * of an existing file), this wraps an arbitrary, already-determined set of
 * generations for a brand-new provider, which is what makes a machine that
 * just imported a recovery file "a full holder" — able to rotate, add
 * recipients, and re-export from here on.
 */
export async function keyringFromRecoveredGenerations(repoId, recovered, providers) {
    requireProviders(providers);
    if (recovered.length === 0) {
        throw new KeyringError('no generations to build a keyring from');
    }
    const generations = [];
    let current = 0;
    for (const { generation, rmk } of recovered) {
        const wrapped = await wrapForEveryProvider(rmk, repoId, generation, providers);
        generations.push({
            generation,
            fingerprint: keyFingerprint(rmk),
            createdAt: new Date().toISOString(),
            wrapped,
        });
        if (generation > current)
            current = generation;
    }
    generations.sort((a, b) => a.generation - b.generation);
    return { version: 1, repoId, current, generations };
}
/**
 * Tries every wrapped slot of every generation against the given providers,
 * and returns whatever `filter.ts` needs — nothing more. A provider that
 * fails to unwrap a slot (wrong passphrase, wrong machine) is not an error
 * here: the next slot, or the next generation, may still succeed.
 */
export async function unlockKeyring(file, providers, opts = {}) {
    if (opts.expectedRepoId !== undefined && file.repoId !== opts.expectedRepoId) {
        throw new KeyringError(`securegit: this keyring belongs to repository ${file.repoId}\n` +
            `  this repository is ${opts.expectedRepoId}\n` +
            `  action: use the keyring for ${opts.expectedRepoId}, or \`securegit key import-recovery\``);
    }
    const warn = opts.warn ?? (() => { });
    const byId = new Map(providers.map((p) => [p.id, p]));
    const held = new Map();
    for (const gen of file.generations) {
        const keyId = keyIdFor(gen.generation, gen.fingerprint);
        for (const slot of gen.wrapped) {
            const provider = byId.get(slot.provider);
            if (!provider)
                continue;
            let rmk;
            try {
                rmk = await provider.unwrap({ provider: slot.provider, payload: slot.payload }, { repoId: file.repoId, generation: gen.generation, state: slot.state, interactive: true });
            }
            catch {
                continue;
            }
            const fingerprint = keyFingerprint(rmk);
            if (!equalCt(Buffer.from(fingerprint, 'hex'), Buffer.from(gen.fingerprint, 'hex'))) {
                warn(`securegit: keyring inconsistency at generation ${gen.generation}\n` +
                    `  expected fingerprint ${gen.fingerprint}, unwrapped key has ${fingerprint}\n` +
                    `  action: this keyring file may be corrupted; verify it came from a trusted source`);
                continue;
            }
            held.set(keyId, secret(rmk));
            break; // this generation is unlocked; no need to try remaining slots
        }
    }
    const currentGen = file.generations.find((g) => g.generation === file.current) ?? null;
    const currentKeyId = currentGen ? keyIdFor(currentGen.generation, currentGen.fingerprint) : null;
    return {
        current() {
            if (currentKeyId === null)
                return null;
            const rmk = held.get(currentKeyId);
            return rmk ? { keyId: currentKeyId, rmk } : null;
        },
        find(keyId) {
            return held.get(keyId) ?? null;
        },
        available() {
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
export async function rewrapOutdatedGenerations(file, providers, keys) {
    const byId = new Map(providers.map((p) => [p.id, p]));
    let changed = false;
    const generations = await Promise.all(file.generations.map(async (gen) => {
        const keyId = keyIdFor(gen.generation, gen.fingerprint);
        const rmk = keys.find(keyId);
        if (!rmk)
            return gen;
        const wrapped = await Promise.all(gen.wrapped.map(async (slot) => {
            if (slot.provider !== 'passphrase-file')
                return slot;
            const n = slot.state.N;
            if (typeof n !== 'number' || n >= DEFAULT_SCRYPT_N)
                return slot;
            const provider = byId.get(slot.provider);
            if (!provider)
                return slot;
            const state = await provider.init({ repoId: file.repoId, generation: gen.generation });
            const rewrapped = await provider.wrap(rmk, {
                repoId: file.repoId,
                generation: gen.generation,
                state,
                interactive: true,
            });
            changed = true;
            return { provider: rewrapped.provider, state, payload: rewrapped.payload };
        }));
        return { ...gen, wrapped };
    }));
    return { file: { ...file, generations }, changed };
}
/**
 * Writes the keyring atomically (temp file + rename, so a crash mid-write
 * cannot leave a half-written file) with mode 0600, creating parent
 * directories as needed.
 */
export async function writeKeyringFile(path, file) {
    await mkdir(dirname(path), { recursive: true });
    const tmp = `${path}.tmp-${process.pid}-${randomBytes(4).toString('hex')}`;
    await writeFile(tmp, JSON.stringify(file, null, 2), { mode: 0o600 });
    try {
        await rename(tmp, path);
    }
    catch (e) {
        await unlink(tmp).catch(() => { });
        throw e;
    }
}
export async function readKeyringFile(path) {
    const raw = await readFile(path, 'utf8');
    return JSON.parse(raw);
}
//# sourceMappingURL=keyring.js.map