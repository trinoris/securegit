// The on-disk representation of an encrypted blob.
//
// This is the compatibility surface: once a byte of it has been committed to
// somebody's repository it is permanent. Version explicitly, refuse what is
// not recognised, never repurpose a field.
// See specs/securegit/04-envelope-format.md.

import {
  CONTENT_TAG_LEN,
  NONCE_LEN,
  TAG_LEN,
  aeadDecrypt,
  aeadEncrypt,
  contentTag,
  deriveFileKey,
  deriveTagKey,
  normalizePath,
} from './crypto.js';

/** Leading NUL so Git's binary detection skips CRLF conversion on the blob. */
export const MAGIC = Buffer.concat([
  Buffer.from([0x00]),
  Buffer.from('SECUREGIT', 'ascii'),
  Buffer.from([0x00]),
]);

export const FORMAT_V1 = 1;
export const ALG_AES256GCM_CONVERGENT = 1;
export const FLAG_BIND_PATH = 0x01;
/** Content is `[4-byte BE length][real content][zero padding]` — see `padContent`/`unpadContent`. */
export const FLAG_PADDED = 0x02;

const FLAGS_KNOWN = FLAG_BIND_PATH | FLAG_PADDED;
const PAD_LENGTH_PREFIX_LEN = 4;

const OFF_FORMAT = MAGIC.length;
const OFF_ALGORITHM = OFF_FORMAT + 1;
const OFF_FLAGS = OFF_ALGORITHM + 1;
const OFF_KEY_ID_LEN = OFF_FLAGS + 1;
const OFF_KEY_ID = OFF_KEY_ID_LEN + 1;

export const HEADER_FIXED_LEN = OFF_KEY_ID;
export const OVERHEAD_MIN = HEADER_FIXED_LEN + CONTENT_TAG_LEN + TAG_LEN;
export const MAX_KEY_ID_LEN = 64;
export const DEFAULT_MAX_BYTES = 512 * 1024 * 1024;

const SEP = Buffer.from([0x00]);
const PRINTABLE_ASCII = /^[\x21-\x7e]+$/;

export class EnvelopeError extends Error {
  readonly code = 'ENVELOPE';

  constructor(message: string) {
    super(message);
    this.name = 'EnvelopeError';
  }
}

export interface EnvelopeHeader {
  format: number;
  algorithm: number;
  bindPath: boolean;
  padded: boolean;
  keyId: string;
  tag: Buffer;
  authTag: Buffer;
  ciphertext: Buffer;
  headerLength: number;
}

export interface SealOptions {
  rmk: Buffer;
  /** `<generation>.<fingerprint>` — printable ASCII, 1–64 bytes. */
  keyId: string;
  path: string;
  bindPath?: boolean;
  maxBytes?: number;
  /** Pad content to a multiple of this many bytes before encryption. 0/undefined disables padding. See 14-metadata-leakage.md. */
  padTo?: number;
}

export interface UnsealOptions {
  rmk: Buffer;
  path: string;
  maxBytes?: number;
}

/**
 * Magic check only. It says nothing about authenticity, which is why `clean`
 * must authenticate before treating a buffer as already-encrypted: a plaintext
 * file that begins with the magic would otherwise pass through unencrypted.
 */
export function looksLikeEnvelope(buf: Buffer): boolean {
  return buf.length >= MAGIC.length && buf.subarray(0, MAGIC.length).equals(MAGIC);
}

function validateKeyId(keyId: string): Buffer {
  if (typeof keyId !== 'string' || keyId.length === 0) {
    throw new EnvelopeError('keyId must be a non-empty string');
  }
  if (!PRINTABLE_ASCII.test(keyId)) {
    throw new EnvelopeError('keyId must be printable ASCII');
  }
  const buf = Buffer.from(keyId, 'ascii');
  if (buf.length > MAX_KEY_ID_LEN) {
    throw new EnvelopeError(
      `keyId must be at most ${MAX_KEY_ID_LEN} bytes, got ${buf.length}`,
    );
  }
  return buf;
}

/**
 * The header, plus the bound path when there is one. Every field that changes
 * the meaning of the ciphertext is authenticated, so an adversary cannot flip
 * a flag, renumber a generation or downgrade the algorithm silently.
 */
function buildAad(header: Buffer, boundPath: string | null): Buffer {
  if (boundPath === null) return header;
  return Buffer.concat([header, SEP, Buffer.from(boundPath, 'utf8')]);
}

/**
 * Prepends a 4-byte big-endian length, then zero-pads the whole thing up to
 * the next multiple of `padTo` — the length prefix is what makes the
 * round-trip exact even when the original content itself ends in zero
 * bytes, which a "trim trailing zeros" scheme would silently corrupt.
 */
function padContent(content: Buffer, padTo: number): Buffer {
  const withLength = Buffer.alloc(PAD_LENGTH_PREFIX_LEN + content.length);
  withLength.writeUInt32BE(content.length, 0);
  content.copy(withLength, PAD_LENGTH_PREFIX_LEN);

  const targetLength = Math.ceil(withLength.length / padTo) * padTo;
  const padded = Buffer.alloc(targetLength); // zero-filled; the length prefix says how much of it is real
  withLength.copy(padded, 0);
  return padded;
}

function unpadContent(padded: Buffer): Buffer {
  if (padded.length < PAD_LENGTH_PREFIX_LEN) {
    throw new EnvelopeError('padded content is truncated: missing length prefix');
  }
  const length = padded.readUInt32BE(0);
  if (PAD_LENGTH_PREFIX_LEN + length > padded.length) {
    throw new EnvelopeError('padded content is truncated: length prefix exceeds the buffer');
  }
  return padded.subarray(PAD_LENGTH_PREFIX_LEN, PAD_LENGTH_PREFIX_LEN + length);
}

function checkSize(length: number, maxBytes: number): void {
  if (length > maxBytes) {
    throw new EnvelopeError(
      `content is too large: ${length} bytes exceeds the ${maxBytes} byte limit`,
    );
  }
}

/** Reads every header field. Needs no key, so it works in a keyless clone. */
export function parseEnvelope(buf: Buffer): EnvelopeHeader {
  if (!looksLikeEnvelope(buf)) {
    throw new EnvelopeError('not a securegit envelope');
  }
  if (buf.length < HEADER_FIXED_LEN) {
    throw new EnvelopeError(
      `envelope is truncated: ${buf.length} bytes, header needs ${HEADER_FIXED_LEN}`,
    );
  }

  const format = buf.readUInt8(OFF_FORMAT);
  if (format !== FORMAT_V1) {
    throw new EnvelopeError(
      `unsupported envelope format ${format}; this build understands ${FORMAT_V1}`,
    );
  }

  const algorithm = buf.readUInt8(OFF_ALGORITHM);
  if (algorithm !== ALG_AES256GCM_CONVERGENT) {
    throw new EnvelopeError(
      `unsupported algorithm ${algorithm}; this build understands ${ALG_AES256GCM_CONVERGENT}`,
    );
  }

  const flags = buf.readUInt8(OFF_FLAGS);
  if ((flags & ~FLAGS_KNOWN) !== 0) {
    // Reserved bits are how a future version signals something we would be
    // wrong to ignore.
    throw new EnvelopeError(`envelope sets reserved flag bits (0x${flags.toString(16)})`);
  }

  const keyIdLen = buf.readUInt8(OFF_KEY_ID_LEN);
  if (keyIdLen === 0) {
    throw new EnvelopeError('envelope has a zero-length keyId');
  }

  const headerLength = HEADER_FIXED_LEN + keyIdLen;
  const minimum = headerLength + CONTENT_TAG_LEN + TAG_LEN;
  if (buf.length < minimum) {
    throw new EnvelopeError(
      `envelope is truncated: ${buf.length} bytes, need at least ${minimum}`,
    );
  }

  const keyId = buf.subarray(OFF_KEY_ID, headerLength).toString('ascii');
  if (!PRINTABLE_ASCII.test(keyId)) {
    throw new EnvelopeError('envelope keyId is not printable ASCII');
  }

  return {
    format,
    algorithm,
    bindPath: (flags & FLAG_BIND_PATH) !== 0,
    padded: (flags & FLAG_PADDED) !== 0,
    keyId,
    tag: buf.subarray(headerLength, headerLength + CONTENT_TAG_LEN),
    authTag: buf.subarray(headerLength + CONTENT_TAG_LEN, minimum),
    ciphertext: buf.subarray(minimum),
    headerLength,
  };
}

/** Plaintext → envelope. Deterministic: same input, same bytes, always. */
export function seal(plaintext: Buffer, opts: SealOptions): Buffer {
  const bindPath = opts.bindPath ?? false;
  const maxBytes = opts.maxBytes ?? DEFAULT_MAX_BYTES;
  const padTo = opts.padTo ?? 0;
  const keyIdBuf = validateKeyId(opts.keyId);
  checkSize(plaintext.length, maxBytes);

  const content = padTo > 0 ? padContent(plaintext, padTo) : plaintext;

  const header = Buffer.alloc(HEADER_FIXED_LEN + keyIdBuf.length);
  MAGIC.copy(header, 0);
  header.writeUInt8(FORMAT_V1, OFF_FORMAT);
  header.writeUInt8(ALG_AES256GCM_CONVERGENT, OFF_ALGORITHM);
  header.writeUInt8((bindPath ? FLAG_BIND_PATH : 0) | (padTo > 0 ? FLAG_PADDED : 0), OFF_FLAGS);
  header.writeUInt8(keyIdBuf.length, OFF_KEY_ID_LEN);
  keyIdBuf.copy(header, OFF_KEY_ID);

  const boundPath = bindPath ? normalizePath(opts.path) : null;
  const tag = contentTag(deriveTagKey(opts.rmk), content, boundPath);
  const dek = deriveFileKey(opts.rmk, tag, boundPath);
  const { ciphertext, authTag } = aeadEncrypt(
    dek,
    tag.subarray(0, NONCE_LEN),
    content,
    buildAad(header, boundPath),
  );

  return Buffer.concat([header, tag, authTag, ciphertext]);
}

/**
 * Envelope → plaintext. The caller supplies the master key for the generation
 * named in the envelope's keyId; selecting it is the keyring's job.
 */
export function unseal(envelope: Buffer, opts: UnsealOptions): Buffer {
  const header = parseEnvelope(envelope);
  checkSize(header.ciphertext.length, opts.maxBytes ?? DEFAULT_MAX_BYTES);

  const boundPath = header.bindPath ? normalizePath(opts.path) : null;
  const dek = deriveFileKey(opts.rmk, header.tag, boundPath);

  const content = aeadDecrypt(
    dek,
    header.tag.subarray(0, NONCE_LEN),
    header.ciphertext,
    header.authTag,
    buildAad(envelope.subarray(0, header.headerLength), boundPath),
  );

  return header.padded ? unpadContent(content) : content;
}
