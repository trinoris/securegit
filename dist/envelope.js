// The on-disk representation of an encrypted blob.
//
// This is the compatibility surface: once a byte of it has been committed to
// somebody's repository it is permanent. Version explicitly, refuse what is
// not recognised, never repurpose a field.
// See specs/securegit/04-envelope-format.md.
import { CONTENT_TAG_LEN, NONCE_LEN, TAG_LEN, aeadDecrypt, aeadEncrypt, contentTag, deriveFileKey, deriveTagKey, normalizePath, } from './crypto.js';
/** Leading NUL so Git's binary detection skips CRLF conversion on the blob. */
export const MAGIC = Buffer.concat([
    Buffer.from([0x00]),
    Buffer.from('SECUREGIT', 'ascii'),
    Buffer.from([0x00]),
]);
export const FORMAT_V1 = 1;
export const ALG_AES256GCM_CONVERGENT = 1;
export const FLAG_BIND_PATH = 0x01;
const FLAGS_KNOWN = FLAG_BIND_PATH;
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
    code = 'ENVELOPE';
    constructor(message) {
        super(message);
        this.name = 'EnvelopeError';
    }
}
/**
 * Magic check only. It says nothing about authenticity, which is why `clean`
 * must authenticate before treating a buffer as already-encrypted: a plaintext
 * file that begins with the magic would otherwise pass through unencrypted.
 */
export function looksLikeEnvelope(buf) {
    return buf.length >= MAGIC.length && buf.subarray(0, MAGIC.length).equals(MAGIC);
}
function validateKeyId(keyId) {
    if (typeof keyId !== 'string' || keyId.length === 0) {
        throw new EnvelopeError('keyId must be a non-empty string');
    }
    if (!PRINTABLE_ASCII.test(keyId)) {
        throw new EnvelopeError('keyId must be printable ASCII');
    }
    const buf = Buffer.from(keyId, 'ascii');
    if (buf.length > MAX_KEY_ID_LEN) {
        throw new EnvelopeError(`keyId must be at most ${MAX_KEY_ID_LEN} bytes, got ${buf.length}`);
    }
    return buf;
}
/**
 * The header, plus the bound path when there is one. Every field that changes
 * the meaning of the ciphertext is authenticated, so an adversary cannot flip
 * a flag, renumber a generation or downgrade the algorithm silently.
 */
function buildAad(header, boundPath) {
    if (boundPath === null)
        return header;
    return Buffer.concat([header, SEP, Buffer.from(boundPath, 'utf8')]);
}
function checkSize(length, maxBytes) {
    if (length > maxBytes) {
        throw new EnvelopeError(`content is too large: ${length} bytes exceeds the ${maxBytes} byte limit`);
    }
}
/** Reads every header field. Needs no key, so it works in a keyless clone. */
export function parseEnvelope(buf) {
    if (!looksLikeEnvelope(buf)) {
        throw new EnvelopeError('not a securegit envelope');
    }
    if (buf.length < HEADER_FIXED_LEN) {
        throw new EnvelopeError(`envelope is truncated: ${buf.length} bytes, header needs ${HEADER_FIXED_LEN}`);
    }
    const format = buf.readUInt8(OFF_FORMAT);
    if (format !== FORMAT_V1) {
        throw new EnvelopeError(`unsupported envelope format ${format}; this build understands ${FORMAT_V1}`);
    }
    const algorithm = buf.readUInt8(OFF_ALGORITHM);
    if (algorithm !== ALG_AES256GCM_CONVERGENT) {
        throw new EnvelopeError(`unsupported algorithm ${algorithm}; this build understands ${ALG_AES256GCM_CONVERGENT}`);
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
        throw new EnvelopeError(`envelope is truncated: ${buf.length} bytes, need at least ${minimum}`);
    }
    const keyId = buf.subarray(OFF_KEY_ID, headerLength).toString('ascii');
    if (!PRINTABLE_ASCII.test(keyId)) {
        throw new EnvelopeError('envelope keyId is not printable ASCII');
    }
    return {
        format,
        algorithm,
        bindPath: (flags & FLAG_BIND_PATH) !== 0,
        keyId,
        tag: buf.subarray(headerLength, headerLength + CONTENT_TAG_LEN),
        authTag: buf.subarray(headerLength + CONTENT_TAG_LEN, minimum),
        ciphertext: buf.subarray(minimum),
        headerLength,
    };
}
/** Plaintext → envelope. Deterministic: same input, same bytes, always. */
export function seal(plaintext, opts) {
    const bindPath = opts.bindPath ?? false;
    const maxBytes = opts.maxBytes ?? DEFAULT_MAX_BYTES;
    const keyIdBuf = validateKeyId(opts.keyId);
    checkSize(plaintext.length, maxBytes);
    const header = Buffer.alloc(HEADER_FIXED_LEN + keyIdBuf.length);
    MAGIC.copy(header, 0);
    header.writeUInt8(FORMAT_V1, OFF_FORMAT);
    header.writeUInt8(ALG_AES256GCM_CONVERGENT, OFF_ALGORITHM);
    header.writeUInt8(bindPath ? FLAG_BIND_PATH : 0, OFF_FLAGS);
    header.writeUInt8(keyIdBuf.length, OFF_KEY_ID_LEN);
    keyIdBuf.copy(header, OFF_KEY_ID);
    const boundPath = bindPath ? normalizePath(opts.path) : null;
    const tag = contentTag(deriveTagKey(opts.rmk), plaintext, boundPath);
    const dek = deriveFileKey(opts.rmk, tag, boundPath);
    const { ciphertext, authTag } = aeadEncrypt(dek, tag.subarray(0, NONCE_LEN), plaintext, buildAad(header, boundPath));
    return Buffer.concat([header, tag, authTag, ciphertext]);
}
/**
 * Envelope → plaintext. The caller supplies the master key for the generation
 * named in the envelope's keyId; selecting it is the keyring's job.
 */
export function unseal(envelope, opts) {
    const header = parseEnvelope(envelope);
    checkSize(header.ciphertext.length, opts.maxBytes ?? DEFAULT_MAX_BYTES);
    const boundPath = header.bindPath ? normalizePath(opts.path) : null;
    const dek = deriveFileKey(opts.rmk, header.tag, boundPath);
    return aeadDecrypt(dek, header.tag.subarray(0, NONCE_LEN), header.ciphertext, header.authTag, buildAad(envelope.subarray(0, header.headerLength), boundPath));
}
//# sourceMappingURL=envelope.js.map