export declare class PktLineError extends Error {
    readonly code = "PKTLINE";
    constructor(message: string);
}
/** 65520 (0xfff0) max total packet length, minus the 4-byte header. */
export declare const MAX_PACKET_PAYLOAD = 65516;
export declare const FLUSH: Buffer<ArrayBuffer>;
/** Encodes one packet: a 4-digit hex length (payload + 4), then the payload. */
export declare function encodePacket(payload: Buffer): Buffer;
/** Encodes every item as a packet, terminated by one flush. */
export declare function encodePacketList(items: Buffer[]): Buffer;
/**
 * Splits content into packet-sized payloads. AES-GCM cannot authenticate a
 * prefix, so this exists purely to fit already-whole plaintext/ciphertext
 * through pkt-line's per-packet size limit — never to stream a partial
 * decryption. An empty buffer still produces one (empty) packet, not zero:
 * "the file is empty" and "no content was sent" have to stay distinguishable
 * on the wire, and zero packets before the terminating flush is exactly what
 * "no content" looks like.
 */
export declare function splitContent(content: Buffer): Buffer[];
/**
 * Buffers arbitrary byte chunks and reassembles complete packets from them,
 * exposing whole *lists* (packets up to and including the next flush) —
 * `filter-process`'s handshake, capability advertisement, per-command
 * headers, and content are all one such list apiece. Never assumes a chunk
 * boundary is a packet boundary: a header or a payload may arrive split
 * across any number of `push()` calls.
 */
export declare class PktLineReader {
    private buf;
    private queue;
    push(chunk: Buffer): void;
    private drain;
    /**
     * Pulls one complete list off the queue: every packet up to, and
     * consuming, the next flush. Returns `undefined` — not an error, not an
     * empty list — when no flush has arrived yet, so a caller can tell "keep
     * reading" apart from "the list was empty" (a lone flush, `[]`).
     */
    readList(): Buffer[] | undefined;
    /**
     * Pulls one already-decoded packet off the queue — `null` for a flush,
     * `undefined` if nothing is ready yet. The lower-level counterpart to
     * `readList()`, for a caller that needs to react to packets one at a time
     * within a list instead of waiting for the whole thing (`process.ts`'s
     * content draining, to bound memory on an oversized blob).
     */
    next(): Buffer | null | undefined;
}
//# sourceMappingURL=pktline.d.ts.map