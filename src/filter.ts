// clean / smudge / textconv — the Git filter contract.
//
// The one rule that shapes everything here: `clean` fails closed, `smudge`
// fails open. A locked repository must never let plaintext into the object
// database, and a keyless clone must still be able to check out the 95% of
// the tree that isn't protected.
// See specs/securegit/02-git-integration.md and 07-unlock-session.md.

import {
  EnvelopeError,
  looksLikeEnvelope,
  parseEnvelope,
  seal,
  unseal,
} from './envelope.js';

export class LockedError extends Error {
  readonly code = 'LOCKED';

  constructor(message: string) {
    super(message);
    this.name = 'LockedError';
  }
}

export interface KeyGeneration {
  keyId: string;
  rmk: Buffer;
}

/**
 * What the filter needs from the keyring. Injected rather than imported, so
 * the filter's contract — the asymmetry above all — is testable without a
 * real keyring, session cache or key provider. The real keyring implements
 * exactly this shape.
 */
export interface KeySource {
  /** The generation `clean` encrypts under. `null` when locked. */
  current(): KeyGeneration | null;
  /** The master key for one generation, or `null` if this keyring lacks it. */
  find(keyId: string): Buffer | null;
  /** Every keyId currently held, for diagnostics. */
  available(): string[];
}

export interface FilterContext {
  keys: KeySource;
  /** Repository-relative path. Used for key-derivation context and
   *  diagnostics only — the filter never reads this path from disk. */
  path: string;
  bindPath?: boolean;
  maxBytes?: number;
  /** `smudge --strict`: fail instead of passing ciphertext through. */
  strict?: boolean;
  /** Defaults to `console.error`. Never receives plaintext or key material. */
  warn?: (message: string) => void;
}

function defaultWarn(message: string): void {
  // eslint-disable-next-line no-console -- this is the diagnostic channel
  console.error(message);
}

function lockedMessage(path: string): string {
  return (
    `securegit: repository is locked\n` +
    `  file:   ${path}\n` +
    `  action: run \`securegit unlock\`, then retry`
  );
}

/**
 * Plaintext or (already-authenticated) ciphertext in, ciphertext out. Always.
 * Without a key this throws rather than ever emitting the input unchanged —
 * the one outcome this tool exists to prevent.
 */
export function clean(input: Buffer, ctx: FilterContext): Buffer {
  const current = ctx.keys.current();
  if (current === null) {
    throw new LockedError(lockedMessage(ctx.path));
  }

  if (looksLikeEnvelope(input)) {
    // Only a passthrough if it authenticates under a key we hold — otherwise
    // "looks like an envelope" is exactly the crafted-plaintext case that
    // must still be encrypted.
    let header;
    try {
      header = parseEnvelope(input);
    } catch {
      header = null;
    }
    if (header !== null) {
      const rmk = ctx.keys.find(header.keyId);
      if (rmk !== null) {
        try {
          unsealFor(input, rmk, ctx);
          return input;
        } catch {
          // Falls through to re-encryption below.
        }
      }
    }
  }

  return seal(input, {
    rmk: current.rmk,
    keyId: current.keyId,
    path: ctx.path,
    bindPath: ctx.bindPath ?? false,
    ...(ctx.maxBytes !== undefined ? { maxBytes: ctx.maxBytes } : {}),
  });
}

/** `unseal` with `maxBytes` included only when the caller set one. */
function unsealFor(envelope: Buffer, rmk: Buffer, ctx: FilterContext): Buffer {
  return unseal(envelope, {
    rmk,
    path: ctx.path,
    ...(ctx.maxBytes !== undefined ? { maxBytes: ctx.maxBytes } : {}),
  });
}

function missingKeyMessage(path: string, wanted: string, held: string[]): string {
  const heldList = held.length > 0 ? held.join(', ') : '(none)';
  return (
    `securegit: cannot decrypt ${path}\n` +
    `  reason: blob wants generation ${wanted}; this keyring has ${heldList}\n` +
    `  action: \`git pull\` for new recipient files, then \`securegit unlock\``
  );
}

/**
 * Ciphertext in, plaintext out — except when it can't be, in which case it
 * emits the input unchanged rather than blocking the checkout. The one
 * exception is authentication failure: that is corruption or tampering, and
 * emitting those bytes as if they were plaintext would be wrong in a
 * different way, so it throws regardless of `strict`.
 */
export function smudge(input: Buffer, ctx: FilterContext): Buffer {
  if (!looksLikeEnvelope(input)) {
    // Predates securegit, or was committed with the filter uninstalled.
    return input;
  }

  const header = parseEnvelope(input); // malformed envelope: let this throw

  const rmk = ctx.keys.find(header.keyId);
  if (rmk === null) {
    const warn = ctx.warn ?? defaultWarn;
    const message =
      ctx.keys.current() === null
        ? lockedMessage(ctx.path)
        : missingKeyMessage(ctx.path, header.keyId, ctx.keys.available());
    if (ctx.strict) {
      throw ctx.keys.current() === null
        ? new LockedError(message)
        : new EnvelopeError(message);
    }
    warn(message);
    return input;
  }

  try {
    return unsealFor(input, rmk, ctx);
  } catch (e) {
    // Authentication failure: never pass this through, strict or not.
    const err = e as Error;
    throw new EnvelopeError(
      `securegit: authentication failed for ${ctx.path}\n` +
        `  reason: the blob was modified or truncated (${err.message})\n` +
        `  action: \`git fsck\`; restore from a known-good commit`,
    );
  }
}

/** Decrypt for display only. Never throws — a bad blob must not stop `git log -p`. */
export function textconv(input: Buffer, ctx: FilterContext): Buffer {
  if (!looksLikeEnvelope(input)) return input;

  let header;
  try {
    header = parseEnvelope(input);
  } catch {
    return Buffer.from(`<securegit: unreadable envelope>\n`, 'utf8');
  }

  const rmk = ctx.keys.find(header.keyId);
  if (rmk === null) {
    return Buffer.from(
      `<securegit: encrypted, ${header.ciphertext.length} bytes, keyId ${header.keyId}>\n`,
      'utf8',
    );
  }

  try {
    return unsealFor(input, rmk, ctx);
  } catch {
    return Buffer.from(
      `<securegit: authentication failed, ${header.ciphertext.length} bytes, keyId ${header.keyId}>\n`,
      'utf8',
    );
  }
}
