// The KeyProvider port, and the `passphrase-file` implementation.
//
// A provider wraps and unwraps a 32-byte master key. It never sees a
// plaintext file, a DEK, or a repository path — if a provider's
// implementation is wrong, the blast radius is the master key's
// confidentiality, not the correctness of any blob.
// See specs/securegit/06-key-provider-port.md.
import { randomBytes, scryptSync } from 'node:crypto';
import { aeadDecrypt, aeadEncrypt, secret } from './crypto.js';
export class ProviderError extends Error {
    code = 'PROVIDER';
    constructor(message) {
        super(message);
        this.name = 'ProviderError';
    }
}
export const MIN_PASSPHRASE_LEN = 12;
/** ~64 MiB, a few hundred ms — tuned for a once-per-session unlock. */
export const DEFAULT_SCRYPT_N = 2 ** 16;
const DEFAULT_SCRYPT_R = 8;
const DEFAULT_SCRYPT_P = 1;
const SCRYPT_SALT_LEN = 16;
const WRAP_AAD_LABEL = Buffer.from('securegit/keywrap/v1', 'utf8');
const SEP = Buffer.from([0x00]);
/**
 * `RMK` wrapped by a passphrase: scrypt → KEK, AES-256-GCM(KEK, random nonce).
 * Randomness in the nonce is correct here — the wrapped key lives in
 * `~/.securegit`, never in a Git blob, so the determinism constraint that
 * governs the envelope format does not apply.
 */
export class PassphraseFileProvider {
    id;
    getPassphrase;
    cost;
    /**
     * `id` defaults to the provider type's own name, matching every existing
     * caller that only ever needs one passphrase-file secret. A second,
     * independent secret on the same keyring (`key add-provider`,
     * 06-key-provider-port.md) needs its own distinct id — `unlockKeyring()`
     * looks providers up by `id`, so two instances sharing one would silently
     * shadow each other during unlock, the same reasoning
     * `rewrapOutdatedGenerations()` already leans on to compare only
     * same-provider slots.
     */
    constructor(getPassphrase, cost = { N: DEFAULT_SCRYPT_N, r: DEFAULT_SCRYPT_R, p: DEFAULT_SCRYPT_P }, id = 'passphrase-file') {
        this.getPassphrase = getPassphrase;
        this.cost = cost;
        this.id = id;
    }
    describe() {
        return {
            id: this.id,
            label: 'Passphrase (local file)',
            custodial: false,
            requiresHardware: false,
        };
    }
    async available() {
        return true;
    }
    async init(ctx) {
        void ctx;
        const passphrase = await this.getPassphrase();
        if (passphrase.length < MIN_PASSPHRASE_LEN) {
            throw new ProviderError(`passphrase must be at least ${MIN_PASSPHRASE_LEN} characters`);
        }
        return {
            salt: randomBytes(SCRYPT_SALT_LEN).toString('hex'),
            N: this.cost.N,
            r: this.cost.r,
            p: this.cost.p,
        };
    }
    async wrap(key, ctx) {
        const kek = await this.deriveKek(ctx.state);
        const nonce = randomBytes(12);
        const aad = buildAad(ctx.repoId, ctx.generation);
        const { ciphertext, authTag } = aeadEncrypt(kek, nonce, key, aad);
        return {
            provider: this.id,
            payload: {
                nonce: nonce.toString('hex'),
                ciphertext: ciphertext.toString('hex'),
                authTag: authTag.toString('hex'),
            },
        };
    }
    async unwrap(wrapped, ctx) {
        const { nonce, ciphertext, authTag } = wrapped.payload;
        if (nonce === undefined || ciphertext === undefined || authTag === undefined) {
            throw new ProviderError('wrapped key is missing a required field');
        }
        const kek = await this.deriveKek(ctx.state);
        const aad = buildAad(ctx.repoId, ctx.generation);
        try {
            const key = aeadDecrypt(kek, Buffer.from(nonce, 'hex'), Buffer.from(ciphertext, 'hex'), Buffer.from(authTag, 'hex'), aad);
            return secret(key);
        }
        catch {
            // Deliberately opaque: never reveal whether the passphrase, the repo
            // binding, or the generation binding was the part that was wrong.
            throw new ProviderError('could not unwrap: wrong passphrase, or key belongs elsewhere');
        }
    }
    async deriveKek(state) {
        const salt = state.salt;
        const N = state.N;
        const r = state.r;
        const p = state.p;
        if (typeof salt !== 'string' ||
            typeof N !== 'number' ||
            typeof r !== 'number' ||
            typeof p !== 'number') {
            throw new ProviderError('provider state is missing scrypt parameters');
        }
        const passphrase = await this.getPassphrase();
        const maxmem = 256 * N * r; // headroom above scrypt's ~128*N*r working set
        // Synchronous: scrypt is meant to cost real wall-clock time once per
        // unlock, and Node's async scrypt still saturates a single UV thread-pool
        // slot for that whole duration — sync keeps the cost visible rather than
        // hidden behind a Promise that blocks the same amount of concurrency.
        return scryptSync(passphrase, Buffer.from(salt, 'hex'), 32, { N, r, p, maxmem });
    }
}
function buildAad(repoId, generation) {
    const genBuf = Buffer.alloc(4);
    genBuf.writeUInt32BE(generation >>> 0);
    return Buffer.concat([WRAP_AAD_LABEL, SEP, Buffer.from(repoId, 'utf8'), SEP, genBuf]);
}
//# sourceMappingURL=provider.js.map