// The KeyProvider port, and the `passphrase-file` implementation.
//
// A provider wraps and unwraps a 32-byte master key. It never sees a
// plaintext file, a DEK, or a repository path — if a provider's
// implementation is wrong, the blast radius is the master key's
// confidentiality, not the correctness of any blob.
// See specs/securegit/06-key-provider-port.md.

import { randomBytes, scryptSync } from 'node:crypto';
import { aeadDecrypt, aeadEncrypt, secret, type Secret } from './crypto.js';

export class ProviderError extends Error {
  readonly code = 'PROVIDER';

  constructor(message: string) {
    super(message);
    this.name = 'ProviderError';
  }
}

/** Provider-specific state persisted in the keyring — salts, params, handles. */
export type ProviderState = Record<string, string | number>;

export interface ProviderContext {
  /** Bound into the AAD so a wrapped key cannot be moved between repos. */
  readonly repoId: string;
  readonly generation: number;
  readonly state: ProviderState;
  /** How the caller may reach the operator. `false` inside a Git filter. */
  readonly interactive: boolean;
}

export interface WrappedKey {
  provider: string;
  /** Opaque to everything above this port; must be JSON-serialisable. */
  payload: Record<string, string>;
}

export interface ProviderInfo {
  id: string;
  label: string;
  /** Can the party operating this provider be compelled to produce the key? */
  custodial: boolean;
  requiresHardware: boolean;
}

export interface KeyProvider {
  readonly id: string;
  describe(): ProviderInfo;
  /** Is this provider usable on this machine right now? Must not prompt. */
  available(): Promise<boolean>;
  /** Called once when a repository or identity is created. */
  init(ctx: { repoId: string; generation: number }): Promise<ProviderState>;
  wrap(key: Buffer, ctx: ProviderContext): Promise<WrappedKey>;
  /** Throws ProviderError if the operator did not authorise, or on any mismatch. */
  unwrap(wrapped: WrappedKey, ctx: ProviderContext): Promise<Buffer>;
}

export const MIN_PASSPHRASE_LEN = 12;
/** ~64 MiB, a few hundred ms — tuned for a once-per-session unlock. */
export const DEFAULT_SCRYPT_N = 2 ** 16;
const DEFAULT_SCRYPT_R = 8;
const DEFAULT_SCRYPT_P = 1;
const SCRYPT_SALT_LEN = 16;
const WRAP_AAD_LABEL = Buffer.from('securegit/keywrap/v1', 'utf8');
const SEP = Buffer.from([0x00]);

export interface ScryptCost {
  N: number;
  r: number;
  p: number;
}

/**
 * `RMK` wrapped by a passphrase: scrypt → KEK, AES-256-GCM(KEK, random nonce).
 * Randomness in the nonce is correct here — the wrapped key lives in
 * `~/.securegit`, never in a Git blob, so the determinism constraint that
 * governs the envelope format does not apply.
 */
export class PassphraseFileProvider implements KeyProvider {
  readonly id = 'passphrase-file';

  private readonly getPassphrase: () => Promise<string> | string;
  private readonly cost: ScryptCost;

  constructor(
    getPassphrase: () => Promise<string> | string,
    cost: ScryptCost = { N: DEFAULT_SCRYPT_N, r: DEFAULT_SCRYPT_R, p: DEFAULT_SCRYPT_P },
  ) {
    this.getPassphrase = getPassphrase;
    this.cost = cost;
  }

  describe(): ProviderInfo {
    return {
      id: this.id,
      label: 'Passphrase (local file)',
      custodial: false,
      requiresHardware: false,
    };
  }

  async available(): Promise<boolean> {
    return true;
  }

  async init(ctx: { repoId: string; generation: number }): Promise<ProviderState> {
    void ctx;
    const passphrase = await this.getPassphrase();
    if (passphrase.length < MIN_PASSPHRASE_LEN) {
      throw new ProviderError(
        `passphrase must be at least ${MIN_PASSPHRASE_LEN} characters`,
      );
    }
    return {
      salt: randomBytes(SCRYPT_SALT_LEN).toString('hex'),
      N: this.cost.N,
      r: this.cost.r,
      p: this.cost.p,
    };
  }

  async wrap(key: Buffer, ctx: ProviderContext): Promise<WrappedKey> {
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

  async unwrap(wrapped: WrappedKey, ctx: ProviderContext): Promise<Secret> {
    const { nonce, ciphertext, authTag } = wrapped.payload;
    if (nonce === undefined || ciphertext === undefined || authTag === undefined) {
      throw new ProviderError('wrapped key is missing a required field');
    }
    const kek = await this.deriveKek(ctx.state);
    const aad = buildAad(ctx.repoId, ctx.generation);
    try {
      const key = aeadDecrypt(
        kek,
        Buffer.from(nonce, 'hex'),
        Buffer.from(ciphertext, 'hex'),
        Buffer.from(authTag, 'hex'),
        aad,
      );
      return secret(key);
    } catch {
      // Deliberately opaque: never reveal whether the passphrase, the repo
      // binding, or the generation binding was the part that was wrong.
      throw new ProviderError('could not unwrap: wrong passphrase, or key belongs elsewhere');
    }
  }

  private async deriveKek(state: ProviderState): Promise<Buffer> {
    const salt = state.salt;
    const N = state.N;
    const r = state.r;
    const p = state.p;
    if (
      typeof salt !== 'string' ||
      typeof N !== 'number' ||
      typeof r !== 'number' ||
      typeof p !== 'number'
    ) {
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

function buildAad(repoId: string, generation: number): Buffer {
  const genBuf = Buffer.alloc(4);
  genBuf.writeUInt32BE(generation >>> 0);
  return Buffer.concat([WRAP_AAD_LABEL, SEP, Buffer.from(repoId, 'utf8'), SEP, genBuf]);
}
