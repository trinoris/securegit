// Sharing a repository master key with a recipient's X25519 identity, and
// the committed, tracked `.securegit/recipients/<fingerprint>.json` files
// that carry the wrapped result. No key server: the wrapped key travels
// inside the repository itself.
// See specs/securegit/08-multi-recipient.md.
import { hkdfSync, randomBytes } from 'node:crypto';
import { mkdir, readFile, rename, unlink, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { TAG_LEN, aeadDecrypt, aeadEncrypt } from './crypto.js';
import { generateX25519KeyPair, x25519SharedSecret } from './identity.js';
import { keyIdFor, parseKeyId } from './keyring.js';
export class RecipientError extends Error {
    code = 'RECIPIENT';
    constructor(message) {
        super(message);
        this.name = 'RecipientError';
    }
}
const WRAP_INFO = Buffer.from('securegit/recipient/v1', 'utf8');
const AAD_LABEL = Buffer.from('securegit/recipient-wrap/v1', 'utf8');
const SEP = Buffer.from([0x00]);
const ZERO_NONCE = Buffer.alloc(12);
const WRAP_KEY_LEN = 32;
function buildAad(repoId, generation, fingerprint) {
    const genBuf = Buffer.alloc(4);
    genBuf.writeUInt32BE(generation >>> 0, 0);
    return Buffer.concat([
        AAD_LABEL,
        SEP,
        Buffer.from(repoId, 'utf8'),
        SEP,
        genBuf,
        SEP,
        Buffer.from(fingerprint, 'utf8'),
    ]);
}
/**
 * Wraps `rmk` for one recipient, one generation. A fresh ephemeral X25519
 * keypair every call — this is what makes the zero nonce below safe: each
 * `wrapKey` is derived from a shared secret nobody else will ever derive
 * again, so it is used for exactly one AEAD message, and a random nonce
 * would add a field without adding security.
 */
export function wrapForRecipient(opts) {
    const eph = generateX25519KeyPair();
    const shared = x25519SharedSecret(eph, opts.recipientPublicKey);
    const salt = Buffer.concat([eph.publicKey, opts.recipientPublicKey]);
    const wrapKey = Buffer.from(hkdfSync('sha256', shared, salt, WRAP_INFO, WRAP_KEY_LEN));
    const aad = buildAad(opts.repoId, opts.generation, opts.fingerprint);
    const { ciphertext, authTag } = aeadEncrypt(wrapKey, ZERO_NONCE, opts.rmk, aad);
    return {
        fingerprint: opts.fingerprint,
        ephemeral: eph.publicKey.toString('hex'),
        payload: Buffer.concat([ciphertext, authTag]).toString('hex'),
    };
}
/** Throws `RecipientError` on any mismatch — wrong identity, repoId, generation, fingerprint, or a corrupted payload. */
export function unwrapForRecipient(opts) {
    let ephPublicKey;
    let raw;
    try {
        ephPublicKey = Buffer.from(opts.wrapped.ephemeral, 'hex');
        raw = Buffer.from(opts.wrapped.payload, 'hex');
    }
    catch {
        throw new RecipientError('malformed wrapped generation');
    }
    if (ephPublicKey.length !== 32 || raw.length < TAG_LEN) {
        throw new RecipientError('malformed wrapped generation');
    }
    const shared = x25519SharedSecret(opts.identityKeyPair, ephPublicKey);
    const salt = Buffer.concat([ephPublicKey, opts.identityKeyPair.publicKey]);
    const wrapKey = Buffer.from(hkdfSync('sha256', shared, salt, WRAP_INFO, WRAP_KEY_LEN));
    const aad = buildAad(opts.repoId, opts.generation, opts.fingerprint);
    const ciphertext = raw.subarray(0, raw.length - TAG_LEN);
    const authTag = raw.subarray(raw.length - TAG_LEN);
    try {
        return aeadDecrypt(wrapKey, ZERO_NONCE, ciphertext, authTag, aad);
    }
    catch (e) {
        throw new RecipientError(`cannot unwrap: ${e.message}`);
    }
}
/**
 * Wraps every `keyId` the caller's `keys` actually holds — the primitive
 * behind `key add-recipient`, which shares every existing generation with a
 * new recipient in one commit. A `keyId` the caller doesn't hold, or one
 * that doesn't parse, is silently skipped rather than failing the whole
 * operation: `keyIds` is typically `keys.available()` from the same
 * `KeySource`, so in practice nothing is ever actually skipped.
 */
export function wrapAllGenerations(keys, keyIds, recipientPublicKey, repoId) {
    const out = {};
    for (const keyId of keyIds) {
        const parsed = parseKeyId(keyId);
        if (!parsed)
            continue;
        const rmk = keys.find(keyId);
        if (!rmk)
            continue;
        out[String(parsed.generation)] = wrapForRecipient({
            recipientPublicKey,
            repoId,
            generation: parsed.generation,
            fingerprint: parsed.fingerprint,
            rmk,
        });
    }
    return out;
}
/**
 * Bootstraps a `KeySource` from a recipient file alone — what `unlock` uses
 * on a machine with no keyring yet. Never throws: a generation this
 * identity can't unwrap (wrong identity entirely, or a `keys` entry it was
 * never given) is simply absent from the result, exactly like
 * `keyring.ts`'s `unlockKeyring`. `current()` is the highest generation
 * number actually recovered — the file has no separate "current" pointer of
 * its own the way a keyring does, and a recipient who joined before the
 * latest rotation naturally caps out below it.
 */
export function unlockFromRecipientFile(file, identityKeyPair, repoId) {
    const held = new Map();
    let highest = null;
    for (const [genStr, wrapped] of Object.entries(file.keys)) {
        const generation = Number(genStr);
        if (!Number.isInteger(generation))
            continue;
        let rmk;
        try {
            rmk = unwrapForRecipient({
                identityKeyPair,
                wrapped,
                repoId,
                generation,
                fingerprint: wrapped.fingerprint,
            });
        }
        catch {
            continue;
        }
        const keyId = keyIdFor(generation, wrapped.fingerprint);
        held.set(keyId, rmk);
        if (highest === null || generation > highest.generation) {
            highest = { generation, keyId };
        }
    }
    return {
        current() {
            if (highest === null)
                return null;
            const rmk = held.get(highest.keyId);
            return rmk ? { keyId: highest.keyId, rmk } : null;
        },
        find(keyId) {
            return held.get(keyId) ?? null;
        },
        available() {
            return [...held.keys()];
        },
    };
}
export function recipientsDir(repoDir) {
    return join(repoDir, '.securegit', 'recipients');
}
export function recipientPath(repoDir, fingerprint) {
    return join(recipientsDir(repoDir), `${fingerprint}.json`);
}
/**
 * Atomic (temp + rename) write, ordinary permissions — unlike the keyring
 * or an identity file, a recipient file holds nothing secret (an ephemeral
 * public key and a ciphertext only the intended recipient can open) and is
 * meant to be committed and tracked, so it gets no `0600` restriction.
 */
export async function writeRecipientFile(path, file) {
    await mkdir(dirname(path), { recursive: true });
    const tmp = `${path}.tmp-${process.pid}-${randomBytes(4).toString('hex')}`;
    await writeFile(tmp, JSON.stringify(file, null, 2));
    try {
        await rename(tmp, path);
    }
    catch (e) {
        await unlink(tmp).catch(() => { });
        throw e;
    }
}
export async function readRecipientFile(path) {
    const raw = await readFile(path, 'utf8');
    return JSON.parse(raw);
}
export function removedRecipientsLogPath(repoDir) {
    return join(repoDir, '.securegit', 'removed-recipients.json');
}
export async function readRemovedRecipientsLog(path) {
    try {
        return JSON.parse(await readFile(path, 'utf8'));
    }
    catch {
        return [];
    }
}
/** Records that a recipient was removed — never their wrapped keys, which cease to exist once the file itself is deleted. */
export async function appendRemovedRecipientLogEntry(path, entry) {
    const log = await readRemovedRecipientsLog(path);
    log.push(entry);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, JSON.stringify(log, null, 2));
    return log;
}
//# sourceMappingURL=recipients.js.map