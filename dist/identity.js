// A person's or machine's X25519 identity: the keypair `recipients.ts` wraps
// a repository master key against, its checksummed public-key encoding, its
// fingerprint, and the on-disk `~/.securegit/identity.json` that protects the
// private half with the same KeyProvider port ([06](06-key-provider-port.md))
// that protects a repository's own master key.
// See specs/securegit/08-multi-recipient.md.
import { generateKeyPairSync, createHash, createPrivateKey, createPublicKey, diffieHellman, randomBytes, } from 'node:crypto';
import { execFile as execFileCb, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdir, readFile, rename, writeFile, unlink } from 'node:fs/promises';
import { join, dirname } from 'node:path';
const execFile = promisify(execFileCb);
export class IdentityError extends Error {
    code = 'IDENTITY';
    constructor(message) {
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
/** A fresh X25519 keypair, as raw 32-byte values (not DER/PEM). */
export function generateX25519KeyPair() {
    const { publicKey, privateKey } = generateKeyPairSync('x25519');
    const pub = publicKey.export({ format: 'jwk' });
    const priv = privateKey.export({ format: 'jwk' });
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
export function x25519SharedSecret(own, peerPublicKey) {
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
export function crockfordEncode(bytes) {
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
export function crockfordDecode(text) {
    let bits = 0;
    let value = 0;
    const out = [];
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
function checksum(pubkey) {
    return createHash('sha256').update(pubkey).digest().subarray(0, CHECKSUM_LEN);
}
/** `SGPUB1<Crockford base32 of the 32 key bytes + a 4-byte checksum>`. */
export function encodePublicKey(pubkey) {
    if (pubkey.length !== IDENTITY_PUBKEY_LEN) {
        throw new IdentityError(`public key must be ${IDENTITY_PUBKEY_LEN} bytes, got ${pubkey.length}`);
    }
    return PUBKEY_PREFIX + crockfordEncode(Buffer.concat([pubkey, checksum(pubkey)]));
}
/** Reverses `encodePublicKey`, verifying the checksum before returning the raw key. */
export function decodePublicKey(encoded) {
    if (!encoded.startsWith(PUBKEY_PREFIX)) {
        throw new IdentityError(`public key must start with '${PUBKEY_PREFIX}'`);
    }
    const decoded = crockfordDecode(encoded.slice(PUBKEY_PREFIX.length));
    if (decoded.length !== IDENTITY_PUBKEY_LEN + CHECKSUM_LEN) {
        throw new IdentityError(`public key is the wrong length: expected ${IDENTITY_PUBKEY_LEN + CHECKSUM_LEN} bytes, got ${decoded.length}`);
    }
    const pubkey = decoded.subarray(0, IDENTITY_PUBKEY_LEN);
    const given = decoded.subarray(IDENTITY_PUBKEY_LEN);
    if (!checksum(pubkey).equals(given)) {
        throw new IdentityError('public key checksum does not match — likely a transcription error');
    }
    return pubkey;
}
/** `SHA-256("securegit/identity/v1" ‖ pubkey)[0..8]`, as 16 hex characters. */
export function identityFingerprint(pubkey) {
    return createHash('sha256')
        .update(Buffer.concat([FINGERPRINT_LABEL, pubkey]))
        .digest()
        .subarray(0, 8)
        .toString('hex');
}
/**
 * Identities aren't scoped to any one repository or generation, unlike an
 * RMK — this fixed context is what `wrap`/`unwrap` bind into their AAD for
 * an identity's private key, so it can never be confused with (or replayed
 * against) a repository's own wrapped master key.
 */
const IDENTITY_CONTEXT = { repoId: 'identity', generation: 0 };
/** Generates a keypair and wraps the private half. Does not write to disk. */
export async function createIdentity(label, provider) {
    const keyPair = generateX25519KeyPair();
    const state = await provider.init(IDENTITY_CONTEXT);
    const wrapped = await provider.wrap(keyPair.privateKey, { ...IDENTITY_CONTEXT, state, interactive: true });
    const file = {
        version: 1,
        fingerprint: identityFingerprint(keyPair.publicKey),
        publicKey: encodePublicKey(keyPair.publicKey),
        label,
        wrapped: { provider: wrapped.provider, state, payload: wrapped.payload },
    };
    return { file, keyPair };
}
/** The identity's private key, or `null` if no given provider can unwrap it — never throws. */
export async function unlockIdentity(file, providers) {
    const provider = providers.find((p) => p.id === file.wrapped.provider);
    if (!provider)
        return null;
    try {
        return await provider.unwrap({ provider: file.wrapped.provider, payload: file.wrapped.payload }, { ...IDENTITY_CONTEXT, state: file.wrapped.state, interactive: true });
    }
    catch {
        return null;
    }
}
export function identityPath(home) {
    return join(home, '.securegit', 'identity.json');
}
/** Atomic (temp + rename) write, mode 0600 — the same discipline as `keyring.ts`'s master key. */
export async function writeIdentityFile(path, file) {
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
export async function readIdentityFile(path) {
    const raw = await readFile(path, 'utf8');
    return JSON.parse(raw);
}
// ---------------------------------------------------------------------------
// Commit signing key — detection and generation.
// specs/securegit/08-multi-recipient.md, "Commit signing".
// ---------------------------------------------------------------------------
async function gitConfigGet(repoDir, key) {
    try {
        const { stdout } = await execFile('git', ['config', '--get', key], { cwd: repoDir });
        return stdout.replace(/\n$/, '');
    }
    catch (e) {
        const err = e;
        if (err.code === 1)
            return null; // unset
        throw new IdentityError(`could not read git config in ${repoDir}: ${e.message}`);
    }
}
/**
 * Resolves a raw `user.signingkey` config value to the actual public key
 * line, without touching the filesystem or git itself — split out from
 * `detectLocalSigningKey()` below purely so the three shapes git accepts
 * (inline `key::…`, `~`-relative path, plain path) are each testable
 * directly, no real git repo or `$HOME` needed.
 *
 * `null` in, `null` out: no key configured, nothing to resolve.
 * A configured-but-unreadable path also resolves to `null`, not a throw —
 * `identity init` treats "found a reference but couldn't read it" the same
 * as "found nothing": either way, there is no key to record yet, and the
 * reason (a stale config entry, a moved file) belongs in a warning the
 * caller prints, not an exception this pure function raises.
 */
export async function resolveSigningKeyRef(value, home, readFileImpl = (p) => readFile(p, 'utf8')) {
    if (value === null || value.length === 0)
        return null;
    if (value.startsWith('key::'))
        return value.slice('key::'.length).trim();
    const path = value.startsWith('~/') ? join(home, value.slice(2)) : value;
    try {
        return (await readFileImpl(path)).trim();
    }
    catch {
        return null;
    }
}
/**
 * Whatever `git commit -S` would already sign with in `repoDir`, right
 * now — reads the *effective* `user.signingkey` (local overrides global
 * overrides system, same as git's own resolution), resolved to the actual
 * public key content via `resolveSigningKeyRef()`. Read-only: this never
 * writes anything, generates anything, or prompts — see `identity init`'s
 * own contract for why detecting an existing key is unconditional but
 * recording/generating one is not.
 */
export async function detectLocalSigningKey(repoDir, home) {
    const value = await gitConfigGet(repoDir, 'user.signingkey');
    return resolveSigningKeyRef(value, home);
}
/**
 * Generates a fresh Ed25519 SSH-format signing keypair at `path` (and
 * `path.pub`) via the real `ssh-keygen` binary — deliberately not
 * hand-rolled: the OpenSSH private-key file format is a specific,
 * non-trivial on-disk encoding, and generating a *signing* key by
 * reimplementing that format is exactly the kind of unforced complexity
 * this package avoids elsewhere too. No passphrase (`-N ''`) — this key
 * signs commits, it never wraps an RMK, so it doesn't carry the same
 * stakes as the identity/keyring material a `KeyProvider` protects
 * elsewhere in this codebase.  Refuses (does not overwrite) if a key
 * already exists at `path` — `identity init --generate-signing-key`'s own
 * contract is "only when none is already recorded", enforced by the
 * caller checking `identity.json` first, and `ssh-keygen` itself refusing
 * an existing file first is a second, independent backstop against ever
 * clobbering one by accident.
 *
 * Runs via `spawn`, not `execFile` — `execFile` always leaves the child's
 * stdin as an open, never-closed pipe, and `ssh-keygen` asking "Overwrite
 * (y/n)?" on an existing path then blocks on that pipe forever instead of
 * failing (confirmed directly: `execFile` hangs past any reasonable
 * timeout here, `spawn` with stdin explicitly `'ignore'` — mapped to
 * `/dev/null`, real EOF — exits 1 immediately). The "refuses to overwrite"
 * guarantee above depends on this, not just on ssh-keygen's own default
 * behaviour.
 */
export async function generateSigningKeyPair(path) {
    await mkdir(dirname(path), { recursive: true });
    await new Promise((resolve, reject) => {
        const child = spawn('ssh-keygen', ['-t', 'ed25519', '-f', path, '-N', '', '-C', 'securegit'], {
            stdio: ['ignore', 'pipe', 'pipe'],
        });
        let stderr = '';
        child.stderr.on('data', (d) => (stderr += d.toString('utf8')));
        child.on('error', (e) => reject(new IdentityError(`could not run ssh-keygen: ${e.message}`)));
        child.on('exit', (code) => {
            if (code === 0)
                resolve();
            else
                reject(new IdentityError(`could not generate a signing key at ${path}: ${stderr.trim() || `ssh-keygen exited ${code}`}`));
        });
    });
    const publicKey = (await readFile(`${path}.pub`, 'utf8')).trim();
    return { publicKey };
}
//# sourceMappingURL=identity.js.map