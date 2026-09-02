import { describe, it, expect } from 'vitest';
import {
  PktLineError,
  MAX_PACKET_PAYLOAD,
  FLUSH,
  encodePacket,
  encodePacketList,
  splitContent,
  PktLineReader,
} from './pktline.js';

describe('encodePacket()', () => {
  it('prefixes a 4-digit hex length, including the 4 header bytes', () => {
    const packet = encodePacket(Buffer.from('version=2\n'));
    // 10 payload bytes + 4 header bytes = 14 = 0x000e
    expect(packet.subarray(0, 4).toString('ascii')).toBe('000e');
    expect(packet.subarray(4).toString('utf8')).toBe('version=2\n');
  });

  it('round-trips through PktLineReader, including the flush packet', () => {
    const reader = new PktLineReader();
    reader.push(Buffer.concat([encodePacket(Buffer.from('a')), encodePacket(Buffer.from('bb')), FLUSH]));
    const list = reader.readList();
    expect(list).toBeDefined();
    expect(list!.map((b) => b.toString('utf8'))).toEqual(['a', 'bb']);
  });

  it('refuses a payload over MAX_PACKET_PAYLOAD bytes', () => {
    expect(() => encodePacket(Buffer.alloc(MAX_PACKET_PAYLOAD + 1))).toThrow(PktLineError);
  });

  it('accepts a payload of exactly MAX_PACKET_PAYLOAD bytes', () => {
    const packet = encodePacket(Buffer.alloc(MAX_PACKET_PAYLOAD));
    expect(packet.length).toBe(MAX_PACKET_PAYLOAD + 4);
  });
});

describe('encodePacketList()', () => {
  it('encodes every item as a packet, terminated by one flush', () => {
    const encoded = encodePacketList([Buffer.from('one'), Buffer.from('two')]);
    const reader = new PktLineReader();
    reader.push(encoded);
    expect(reader.readList()!.map((b) => b.toString('utf8'))).toEqual(['one', 'two']);
  });

  it('an empty list is just a flush', () => {
    const encoded = encodePacketList([]);
    expect(encoded).toEqual(FLUSH);
  });
});

describe('PktLineReader', () => {
  it('handles a packet split across chunk boundaries', () => {
    const whole = Buffer.concat([encodePacket(Buffer.from('hello world')), FLUSH]);
    const reader = new PktLineReader();
    // Split mid-header and mid-payload, one byte at a time in the worst case.
    reader.push(whole.subarray(0, 2));
    expect(reader.readList()).toBeUndefined();
    reader.push(whole.subarray(2, 6));
    expect(reader.readList()).toBeUndefined();
    reader.push(whole.subarray(6));
    expect(reader.readList()!.map((b) => b.toString('utf8'))).toEqual(['hello world']);
  });

  it('handles several packets arriving in one chunk', () => {
    const whole = Buffer.concat([
      encodePacket(Buffer.from('first')),
      encodePacket(Buffer.from('second')),
      encodePacket(Buffer.from('third')),
      FLUSH,
    ]);
    const reader = new PktLineReader();
    reader.push(whole);
    expect(reader.readList()!.map((b) => b.toString('utf8'))).toEqual(['first', 'second', 'third']);
  });

  it('handles two lists back to back in one chunk, without losing the boundary', () => {
    const listA = encodePacketList([Buffer.from('a1'), Buffer.from('a2')]);
    const listB = encodePacketList([Buffer.from('b1')]);
    const reader = new PktLineReader();
    reader.push(Buffer.concat([listA, listB]));
    expect(reader.readList()!.map((b) => b.toString('utf8'))).toEqual(['a1', 'a2']);
    expect(reader.readList()!.map((b) => b.toString('utf8'))).toEqual(['b1']);
  });

  it('a lone flush is an empty list, distinguishable from "no list yet"', () => {
    const reader = new PktLineReader();
    reader.push(FLUSH);
    expect(reader.readList()).toEqual([]);
  });

  it('rejects a malformed length header instead of hanging', () => {
    const reader = new PktLineReader();
    expect(() => reader.push(Buffer.from('zzzzpayload'))).toThrow(PktLineError);
  });

  it('rejects a length header below the 4-byte minimum', () => {
    const reader = new PktLineReader();
    expect(() => reader.push(Buffer.from('0001x'))).toThrow(PktLineError);
  });

  it('readList() returns undefined (not an error) when no data has arrived', () => {
    const reader = new PktLineReader();
    expect(reader.readList()).toBeUndefined();
  });
});

describe('splitContent()', () => {
  it('a small buffer is a single packet payload', () => {
    const content = Buffer.from('small file contents');
    const packets = splitContent(content);
    expect(packets).toHaveLength(1);
    expect(packets[0]!.equals(content)).toBe(true);
  });

  it('content over MAX_PACKET_PAYLOAD is split into multiple packets', () => {
    const content = Buffer.alloc(MAX_PACKET_PAYLOAD * 2 + 100, 0x42);
    const packets = splitContent(content);
    expect(packets).toHaveLength(3);
    expect(packets[0]!.length).toBe(MAX_PACKET_PAYLOAD);
    expect(packets[1]!.length).toBe(MAX_PACKET_PAYLOAD);
    expect(packets[2]!.length).toBe(100);
    expect(Buffer.concat(packets).equals(content)).toBe(true);
  });

  it('round-trips through encode + PktLineReader for oversized content', () => {
    const content = Buffer.alloc(MAX_PACKET_PAYLOAD + 500, 0x7).fill(0x7);
    const encoded = encodePacketList(splitContent(content));
    const reader = new PktLineReader();
    reader.push(encoded);
    const rejoined = Buffer.concat(reader.readList()!);
    expect(rejoined.equals(content)).toBe(true);
  });

  it('an empty buffer still produces one (empty) packet, not zero', () => {
    // Distinguishes "content is the empty string" from "no content sent" —
    // both would otherwise collapse to the same empty packet list.
    const packets = splitContent(Buffer.alloc(0));
    expect(packets).toHaveLength(1);
    expect(packets[0]!.length).toBe(0);
  });
});
