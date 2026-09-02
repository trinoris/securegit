import { describe, it, expect, vi } from 'vitest';
import { isSecret } from './crypto.js';
import {
  ProviderError,
  PassphraseFileProvider,
  DEFAULT_SCRYPT_N,
  MIN_PASSPHRASE_LEN,
  type ProviderContext,
  type ProviderState,
} from './provider.js';

const RMK = Buffer.alloc(32, 0xa5);

// Real N (2^16) costs real time; tests use a small cost so the suite stays
// fast, and a single test below pins the production default separately.
const FAST_COST = { N: 2 ** 10, r: 8, p: 1 };

function providerWith(passphrase: string, cost = FAST_COST) {
  return new PassphraseFileProvider(() => passphrase, cost);
}

async function ctxFor(
  provider: PassphraseFileProvider,
  repoId: string,
  generation: number,
): Promise<ProviderContext> {
  const state = await provider.init({ repoId, generation });
  return { repoId, generation, state, interactive: true };
}

describe('describe()', () => {
  it('identifies as a non-custodial, no-hardware provider', () => {
    const info = providerWith('correct horse battery staple').describe();
    expect(info.id).toBe('passphrase-file');
    expect(info.custodial).toBe(false);
    expect(info.requiresHardware).toBe(false);
    expect(info.label.length).toBeGreaterThan(0);
  });
});

describe('available()', () => {
  it('resolves without prompting', async () => {
    const getPassphrase = vi.fn(() => 'correct horse battery staple');
    const provider = new PassphraseFileProvider(getPassphrase, FAST_COST);
    await expect(provider.available()).resolves.toBe(true);
    expect(getPassphrase).not.toHaveBeenCalled();
  });
});

describe('init()', () => {
  it('produces scrypt parameters and a fresh salt', async () => {
    const provider = providerWith('correct horse battery staple');
    const state = await provider.init({ repoId: 'repo-a', generation: 1 });
    expect(state.N).toBe(FAST_COST.N);
    expect(state.r).toBe(FAST_COST.r);
    expect(state.p).toBe(FAST_COST.p);
    expect(typeof state.salt).toBe('string');
    expect(state.salt as string).toMatch(/^[0-9a-f]{32}$/);
  });

  it('generates a different salt each call', async () => {
    const provider = providerWith('correct horse battery staple');
    const a = await provider.init({ repoId: 'repo-a', generation: 1 });
    const b = await provider.init({ repoId: 'repo-a', generation: 1 });
    expect(a.salt).not.toBe(b.salt);
  });

  it('refuses a passphrase under 12 characters', async () => {
    const provider = providerWith('short1234ab'); // 11 chars
    await expect(provider.init({ repoId: 'repo-a', generation: 1 })).rejects.toThrow(
      new RegExp(`${MIN_PASSPHRASE_LEN}`),
    );
  });

  it('accepts a passphrase at exactly the floor', async () => {
    const provider = providerWith('123456789012'); // 12 chars
    await expect(provider.init({ repoId: 'repo-a', generation: 1 })).resolves.toBeDefined();
  });

  it('the error names the requirement without ever containing the passphrase', async () => {
    const provider = providerWith('short');
    try {
      await provider.init({ repoId: 'repo-a', generation: 1 });
      expect.unreachable('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(ProviderError);
      expect((e as Error).message).not.toContain('short');
    }
  });
});

describe('wrap() / unwrap() round-trip', () => {
  it('unwrap recovers exactly the wrapped key', async () => {
    const provider = providerWith('correct horse battery staple');
    const ctx = await ctxFor(provider, 'repo-a', 1);
    const wrapped = await provider.wrap(RMK, ctx);
    const back = await provider.unwrap(wrapped, ctx);
    expect(back.equals(RMK)).toBe(true);
  });

  it('the recovered key is marked as secret material', async () => {
    const provider = providerWith('correct horse battery staple');
    const ctx = await ctxFor(provider, 'repo-a', 1);
    const wrapped = await provider.wrap(RMK, ctx);
    expect(isSecret(await provider.unwrap(wrapped, ctx))).toBe(true);
  });

  it('names the provider on the wrapped output', async () => {
    const provider = providerWith('correct horse battery staple');
    const ctx = await ctxFor(provider, 'repo-a', 1);
    const wrapped = await provider.wrap(RMK, ctx);
    expect(wrapped.provider).toBe('passphrase-file');
  });

  it('two wraps of the same key produce different payloads', async () => {
    const provider = providerWith('correct horse battery staple');
    const ctx = await ctxFor(provider, 'repo-a', 1);
    const a = await provider.wrap(RMK, ctx);
    const b = await provider.wrap(RMK, ctx);
    expect(a.payload.ciphertext).not.toBe(b.payload.ciphertext);
    // ... but both still unwrap to the same key.
    expect((await provider.unwrap(a, ctx)).equals(await provider.unwrap(b, ctx))).toBe(true);
  });

  it('payload is JSON-serialisable string data, safe to write to disk', async () => {
    const provider = providerWith('correct horse battery staple');
    const ctx = await ctxFor(provider, 'repo-a', 1);
    const wrapped = await provider.wrap(RMK, ctx);
    const round = JSON.parse(JSON.stringify(wrapped)) as typeof wrapped;
    expect((await provider.unwrap(round, ctx)).equals(RMK)).toBe(true);
    for (const v of Object.values(wrapped.payload)) expect(typeof v).toBe('string');
  });

  it('rejects the wrong passphrase with a distinguishable error, not a crash', async () => {
    const provider = providerWith('correct horse battery staple');
    const ctx = await ctxFor(provider, 'repo-a', 1);
    const wrapped = await provider.wrap(RMK, ctx);
    const wrong = new PassphraseFileProvider(() => 'a totally different passphrase', FAST_COST);
    await expect(wrong.unwrap(wrapped, ctx)).rejects.toBeInstanceOf(ProviderError);
  });

  it('unwrap fails when repoId does not match what was wrapped', async () => {
    const provider = providerWith('correct horse battery staple');
    const ctx = await ctxFor(provider, 'repo-a', 1);
    const wrapped = await provider.wrap(RMK, ctx);
    const otherRepo: ProviderContext = { ...ctx, repoId: 'repo-b' };
    await expect(provider.unwrap(wrapped, otherRepo)).rejects.toBeInstanceOf(ProviderError);
  });

  it('unwrap fails when generation does not match what was wrapped', async () => {
    const provider = providerWith('correct horse battery staple');
    const ctx = await ctxFor(provider, 'repo-a', 1);
    const wrapped = await provider.wrap(RMK, ctx);
    const otherGen: ProviderContext = { ...ctx, generation: 2 };
    await expect(provider.unwrap(wrapped, otherGen)).rejects.toBeInstanceOf(ProviderError);
  });

  it('a wrapped key copied into another keyring state fails rather than decrypting garbage', async () => {
    const provider = providerWith('correct horse battery staple');
    const ctxA = await ctxFor(provider, 'repo-a', 1);
    const ctxB = await ctxFor(provider, 'repo-a', 1); // fresh salt, same repo/gen
    const wrapped = await provider.wrap(RMK, ctxA);
    await expect(provider.unwrap(wrapped, ctxB)).rejects.toBeInstanceOf(ProviderError);
  });

  it('the error message never contains the master key or the passphrase', async () => {
    const provider = providerWith('correct horse battery staple');
    const ctx = await ctxFor(provider, 'repo-a', 1);
    const wrapped = await provider.wrap(RMK, ctx);
    const wrong = new PassphraseFileProvider(() => 'a totally different passphrase', FAST_COST);
    try {
      await wrong.unwrap(wrapped, ctx);
      expect.unreachable('should have thrown');
    } catch (e) {
      const message = (e as Error).message;
      expect(message).not.toContain(RMK.toString('hex'));
      expect(message).not.toContain('a totally different passphrase');
    }
  });

  it('carries the scrypt cost forward through the wrapped state, not hardcoded', async () => {
    const cost = { N: 2 ** 11, r: 8, p: 1 };
    const provider = providerWith('correct horse battery staple', cost);
    const ctx = await ctxFor(provider, 'repo-a', 1);
    const wrapped = await provider.wrap(RMK, ctx);
    // A fresh provider instance with a *different* configured cost still
    // unwraps correctly, because the cost travels in ctx.state, not the
    // provider's own constructor arguments.
    const otherInstance = providerWith('correct horse battery staple', FAST_COST);
    expect((await otherInstance.unwrap(wrapped, ctx)).equals(RMK)).toBe(true);
  });
});

describe('production default', () => {
  it('is scrypt N = 2^16, matching the 64 MiB / few-hundred-ms target', () => {
    expect(DEFAULT_SCRYPT_N).toBe(2 ** 16);
  });

  it('a provider built with no explicit cost uses the default', async () => {
    const provider = new PassphraseFileProvider(() => 'correct horse battery staple');
    const state = await provider.init({ repoId: 'repo-a', generation: 1 });
    expect(state.N).toBe(DEFAULT_SCRYPT_N);
  });
});
