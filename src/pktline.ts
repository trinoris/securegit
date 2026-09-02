// The pkt-line framing `filter-process` speaks: a 4-digit hex length
// (including its own 4 header bytes), then that many payload bytes. `0000`
// is a flush — the protocol's way of ending a list of packets (a set of
// capabilities, one command's headers, one blob's content) without a
// length-prefixed envelope around the whole list.
// See specs/securegit/11-filter-process.md.

export class PktLineError extends Error {
  readonly code = 'PKTLINE';

  constructor(message: string) {
    super(message);
    this.name = 'PktLineError';
  }
}

/** 65520 (0xfff0) max total packet length, minus the 4-byte header. */
export const MAX_PACKET_PAYLOAD = 65516;

export const FLUSH = Buffer.from('0000', 'ascii');

const HEADER_LEN = 4;
const HEADER_RE = /^[0-9a-f]{4}$/i;

/** Encodes one packet: a 4-digit hex length (payload + 4), then the payload. */
export function encodePacket(payload: Buffer): Buffer {
  if (payload.length > MAX_PACKET_PAYLOAD) {
    throw new PktLineError(
      `pkt-line payload of ${payload.length} bytes exceeds the ${MAX_PACKET_PAYLOAD}-byte maximum`,
    );
  }
  const header = Buffer.from((payload.length + HEADER_LEN).toString(16).padStart(4, '0'), 'ascii');
  return Buffer.concat([header, payload]);
}

/** Encodes every item as a packet, terminated by one flush. */
export function encodePacketList(items: Buffer[]): Buffer {
  return Buffer.concat([...items.map(encodePacket), FLUSH]);
}

/**
 * Splits content into packet-sized payloads. AES-GCM cannot authenticate a
 * prefix, so this exists purely to fit already-whole plaintext/ciphertext
 * through pkt-line's per-packet size limit — never to stream a partial
 * decryption. An empty buffer still produces one (empty) packet, not zero:
 * "the file is empty" and "no content was sent" have to stay distinguishable
 * on the wire, and zero packets before the terminating flush is exactly what
 * "no content" looks like.
 */
export function splitContent(content: Buffer): Buffer[] {
  if (content.length === 0) return [Buffer.alloc(0)];
  const packets: Buffer[] = [];
  for (let offset = 0; offset < content.length; offset += MAX_PACKET_PAYLOAD) {
    packets.push(content.subarray(offset, offset + MAX_PACKET_PAYLOAD));
  }
  return packets;
}

/**
 * Buffers arbitrary byte chunks and reassembles complete packets from them,
 * exposing whole *lists* (packets up to and including the next flush) —
 * `filter-process`'s handshake, capability advertisement, per-command
 * headers, and content are all one such list apiece. Never assumes a chunk
 * boundary is a packet boundary: a header or a payload may arrive split
 * across any number of `push()` calls.
 */
export class PktLineReader {
  private buf: Buffer = Buffer.alloc(0);
  private queue: Array<Buffer | null> = [];

  push(chunk: Buffer): void {
    this.buf = this.buf.length === 0 ? chunk : Buffer.concat([this.buf, chunk]);
    this.drain();
  }

  private drain(): void {
    for (;;) {
      if (this.buf.length < HEADER_LEN) return;
      const header = this.buf.subarray(0, HEADER_LEN).toString('ascii');
      if (!HEADER_RE.test(header)) {
        throw new PktLineError(`malformed pkt-line length header: ${JSON.stringify(header)}`);
      }
      const len = parseInt(header, 16);
      if (len === 0) {
        this.queue.push(null); // flush marker
        this.buf = this.buf.subarray(HEADER_LEN);
        continue;
      }
      if (len < HEADER_LEN) {
        throw new PktLineError(`pkt-line length ${len} is below the ${HEADER_LEN}-byte header minimum`);
      }
      if (this.buf.length < len) return; // payload not fully arrived yet
      this.queue.push(Buffer.from(this.buf.subarray(HEADER_LEN, len)));
      this.buf = this.buf.subarray(len);
    }
  }

  /**
   * Pulls one complete list off the queue: every packet up to, and
   * consuming, the next flush. Returns `undefined` — not an error, not an
   * empty list — when no flush has arrived yet, so a caller can tell "keep
   * reading" apart from "the list was empty" (a lone flush, `[]`).
   */
  readList(): Buffer[] | undefined {
    const flushIndex = this.queue.indexOf(null);
    if (flushIndex === -1) return undefined;
    const packets = this.queue.splice(0, flushIndex) as Buffer[];
    this.queue.shift(); // drop the flush marker itself
    return packets;
  }

  /**
   * Pulls one already-decoded packet off the queue — `null` for a flush,
   * `undefined` if nothing is ready yet. The lower-level counterpart to
   * `readList()`, for a caller that needs to react to packets one at a time
   * within a list instead of waiting for the whole thing (`process.ts`'s
   * content draining, to bound memory on an oversized blob).
   */
  next(): Buffer | null | undefined {
    return this.queue.shift();
  }
}
