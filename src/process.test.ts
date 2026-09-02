import { describe, it, expect } from 'vitest';
import { clean as filterClean, smudge as filterSmudge, type KeySource } from './filter.js';
import { encodePacketList, splitContent, PktLineReader } from './pktline.js';
import {
  FilterProcessServer,
  ProcessProtocolError,
  installStdoutGuard,
  type FilterProcessContext,
} from './process.js';

const RMK = Buffer.alloc(32, 0xa5);
const KEY_ID = '3.a1b2c3d4e5f60718';
const PATH = 'config/production.json';
const PT = Buffer.from('{"timeout":30}\n');

function unlockedKeys(): KeySource {
  return {
    current: () => ({ keyId: KEY_ID, rmk: RMK }),
    find: (keyId) => (keyId === KEY_ID ? RMK : null),
    available: () => [KEY_ID],
  };
}

function lockedKeys(): KeySource {
  return { current: () => null, find: () => null, available: () => [] };
}

function handshakeRequest(): Buffer {
  return encodePacketList([Buffer.from('git-filter-client\n'), Buffer.from('version=2\n')]);
}

function capabilitiesRequest(caps: string[] = ['clean', 'smudge', 'delay']): Buffer {
  return encodePacketList(caps.map((c) => Buffer.from(`capability=${c}\n`)));
}

function commandRequest(command: string, pathname: string, content: Buffer): Buffer {
  return Buffer.concat([
    encodePacketList([Buffer.from(`command=${command}\n`), Buffer.from(`pathname=${pathname}\n`)]),
    encodePacketList(splitContent(content)),
  ]);
}

/** Reads every complete list out of a response buffer, in order. */
function readAllLists(buf: Buffer): Buffer[][] {
  const reader = new PktLineReader();
  reader.push(buf);
  const lists: Buffer[][] = [];
  for (;;) {
    const list = reader.readList();
    if (list === undefined) break;
    lists.push(list);
  }
  return lists;
}

function textOf(list: Buffer[]): string[] {
  return list.map((b) => b.toString('utf8').replace(/\n$/, ''));
}

interface Harness {
  server: FilterProcessServer;
  setKeys: (keys: KeySource) => void;
  written: Buffer[];
  warnings: string[];
  outBuf: () => Buffer;
  reset: () => void;
}

function harness(overrides: Partial<FilterProcessContext> = {}): Harness {
  const written: Buffer[] = [];
  const warnings: string[] = [];
  let keys: KeySource = unlockedKeys();
  const ctx: FilterProcessContext = {
    keys: () => keys,
    bindPath: false,
    write: (chunk) => written.push(chunk),
    warn: (message) => warnings.push(message),
    ...overrides,
  };
  return {
    server: new FilterProcessServer(ctx),
    setKeys: (k) => {
      keys = k;
    },
    written,
    warnings,
    outBuf: () => Buffer.concat(written),
    reset: () => {
      written.length = 0;
      warnings.length = 0;
    },
  };
}

/** Drives the handshake + capability exchange and clears the response buffer after. */
async function ready(overrides: Partial<FilterProcessContext> = {}): Promise<Harness> {
  const h = harness(overrides);
  await h.server.push(handshakeRequest());
  await h.server.push(capabilitiesRequest());
  h.reset();
  return h;
}

describe('handshake and capabilities', () => {
  it('replies exactly as specified', async () => {
    const h = harness();
    await h.server.push(handshakeRequest());
    const lists = readAllLists(h.outBuf());
    expect(lists).toHaveLength(1);
    expect(textOf(lists[0]!)).toEqual(['git-filter-server', 'version=2']);
  });

  it('advertises only clean and smudge, even when the client offers delay', async () => {
    const h = harness();
    await h.server.push(handshakeRequest());
    h.reset();
    await h.server.push(capabilitiesRequest(['clean', 'smudge', 'delay']));
    const lists = readAllLists(h.outBuf());
    expect(lists).toHaveLength(1);
    expect(textOf(lists[0]!)).toEqual(['capability=clean', 'capability=smudge']);
  });

  it('rejects a malformed handshake as a protocol violation', async () => {
    const h = harness();
    await expect(h.server.push(Buffer.concat([encodePacketList([Buffer.from('nonsense\n')])]))).rejects.toThrow(
      ProcessProtocolError,
    );
  });

  it('handles the handshake split across many small chunks', async () => {
    const whole = handshakeRequest();
    const h = harness();
    for (let i = 0; i < whole.length; i++) {
      await h.server.push(whole.subarray(i, i + 1));
    }
    const lists = readAllLists(h.outBuf());
    expect(textOf(lists[0]!)).toEqual(['git-filter-server', 'version=2']);
  });
});

describe('command dispatch', () => {
  it('unsupported command yields status=error, and the process keeps serving', async () => {
    const h = await ready();
    await h.server.push(commandRequest('checkout', PATH, PT));
    let lists = readAllLists(h.outBuf());
    expect(textOf(lists[0]!)).toEqual(['status=error']);

    // The process survives: a real command right after still works.
    h.reset();
    await h.server.push(commandRequest('clean', PATH, PT));
    lists = readAllLists(h.outBuf());
    expect(textOf(lists[0]!)).toEqual(['status=success']);
  });

  it('clean while locked yields status=error, and actually warns — not a silent status change', async () => {
    // Regression: an earlier version wrote status=error/abort for the
    // locked case without ever calling `warn`, so Git could only report a
    // generic "clean filter failed" with none of our diagnostic reaching
    // the user — confirmed against real `git add` before this was fixed.
    const h = await ready({ keys: () => lockedKeys() });
    await h.server.push(commandRequest('clean', PATH, PT));
    const lists = readAllLists(h.outBuf());
    expect(lists).toHaveLength(1);
    expect(textOf(lists[0]!)).toEqual(['status=error']);
    expect(h.warnings.length).toBeGreaterThan(0);
    expect(h.warnings.join('\n')).toMatch(/locked/);
  });

  it('smudge while locked yields status=success with ciphertext passed through', async () => {
    const ciphertext = filterClean(PT, { keys: unlockedKeys(), path: PATH });
    const h = await ready({ keys: () => lockedKeys() });
    await h.server.push(commandRequest('smudge', PATH, ciphertext));
    const lists = readAllLists(h.outBuf());
    expect(textOf(lists[0]!)).toEqual(['status=success']);
    expect(Buffer.concat(lists[1]!).equals(ciphertext)).toBe(true);
    expect(lists[2]).toEqual([]); // trailing empty list: status unchanged
  });

  it('session expiry mid-run yields status=abort exactly once', async () => {
    let keys: KeySource = unlockedKeys();
    const h = await ready({ keys: () => keys });

    await h.server.push(commandRequest('clean', PATH, PT));
    expect(textOf(readAllLists(h.outBuf())[0]!)).toEqual(['status=success']);

    keys = lockedKeys(); // the session expires mid-run
    h.reset();
    await h.server.push(commandRequest('clean', PATH, PT));
    let lists = readAllLists(h.outBuf());
    expect(textOf(lists[0]!)).toEqual(['status=abort']);
    expect(h.warnings.length).toBeGreaterThan(0);

    // A repeat clean after the abort keeps reporting abort — it isn't a
    // one-shot flag that silently reverts to `error` — but never a second,
    // different signal for the same ongoing condition.
    h.reset();
    await h.server.push(commandRequest('clean', PATH, PT));
    lists = readAllLists(h.outBuf());
    expect(textOf(lists[0]!)).toEqual(['status=abort']);
  });

  it('a clean before any successful clean yields error, never abort, while locked', async () => {
    const h = await ready({ keys: () => lockedKeys() });
    await h.server.push(commandRequest('clean', PATH, PT));
    await h.server.push(commandRequest('clean', PATH, PT));
    const lists = readAllLists(h.outBuf());
    expect(textOf(lists[0]!)).toEqual(['status=error']);
    expect(textOf(lists[1]!)).toEqual(['status=error']);
  });
});

describe('content fidelity', () => {
  it('clean output is byte-identical to the direct clean() form', async () => {
    const h = await ready();
    await h.server.push(commandRequest('clean', PATH, PT));
    const lists = readAllLists(h.outBuf());
    const viaProcess = Buffer.concat(lists[1]!);
    const viaDirect = filterClean(PT, { keys: unlockedKeys(), path: PATH });
    expect(viaProcess.equals(viaDirect)).toBe(true);
  });

  it('applies padTo to clean output, matching the direct clean() form', async () => {
    const h = await ready({ padTo: 64 });
    await h.server.push(commandRequest('clean', PATH, PT));
    const lists = readAllLists(h.outBuf());
    const viaProcess = Buffer.concat(lists[1]!);
    const viaDirect = filterClean(PT, { keys: unlockedKeys(), path: PATH, padTo: 64 });
    expect(viaProcess.equals(viaDirect)).toBe(true);
  });

  it('smudge output is byte-identical to the direct smudge() form', async () => {
    const ciphertext = filterClean(PT, { keys: unlockedKeys(), path: PATH });
    const h = await ready();
    await h.server.push(commandRequest('smudge', PATH, ciphertext));
    const lists = readAllLists(h.outBuf());
    const viaProcess = Buffer.concat(lists[1]!);
    const viaDirect = filterSmudge(ciphertext, { keys: unlockedKeys(), path: PATH });
    expect(viaProcess.equals(viaDirect)).toBe(true);
  });

  it('a blob larger than one packet round-trips whole', async () => {
    const bigPlaintext = Buffer.alloc(140_000, 0x41);
    const h = await ready();
    await h.server.push(commandRequest('clean', PATH, bigPlaintext));
    const cleanLists = readAllLists(h.outBuf());
    const ciphertext = Buffer.concat(cleanLists[1]!);
    expect(ciphertext.length).toBeGreaterThan(70_000); // definitely split across packets

    h.reset();
    await h.server.push(commandRequest('smudge', PATH, ciphertext));
    const smudgeLists = readAllLists(h.outBuf());
    expect(Buffer.concat(smudgeLists[1]!).equals(bigPlaintext)).toBe(true);
  });

  it('serves 1000 sequential blobs correctly, with no cross-contamination between them', async () => {
    const h = await ready();
    for (let i = 0; i < 1000; i++) {
      const content = Buffer.from(`{"n":${i}}\n`);
      h.reset();
      await h.server.push(commandRequest('clean', `file-${i}.json`, content));
      const lists = readAllLists(h.outBuf());
      expect(textOf(lists[0]!)).toEqual(['status=success']);

      h.reset();
      await h.server.push(commandRequest('smudge', `file-${i}.json`, Buffer.concat(lists[1]!)));
      const smudgeLists = readAllLists(h.outBuf());
      expect(Buffer.concat(smudgeLists[1]!).equals(content)).toBe(true);
    }
  });
});

describe('oversized content', () => {
  it('is rejected once the running total crosses maxBytes, without ever completing a successful clean', async () => {
    const h = await ready({ maxBytes: 100 });
    const oversized = Buffer.alloc(1000, 0x58);
    await h.server.push(commandRequest('clean', PATH, oversized));
    const lists = readAllLists(h.outBuf());
    expect(lists).toHaveLength(1);
    expect(textOf(lists[0]!)).toEqual(['status=error']);
  });

  it('content at exactly maxBytes still succeeds', async () => {
    const h = await ready({ maxBytes: 100 });
    const exact = Buffer.alloc(100, 0x59);
    await h.server.push(commandRequest('clean', PATH, exact));
    const lists = readAllLists(h.outBuf());
    expect(textOf(lists[0]!)).toEqual(['status=success']);
  });

  it('the process keeps serving after rejecting an oversized blob', async () => {
    const h = await ready({ maxBytes: 100 });
    await h.server.push(commandRequest('clean', PATH, Buffer.alloc(1000, 0x58)));
    h.reset();
    await h.server.push(commandRequest('clean', PATH, Buffer.from('small')));
    const lists = readAllLists(h.outBuf());
    expect(textOf(lists[0]!)).toEqual(['status=success']);
  });
});

describe('installStdoutGuard()', () => {
  it('throws when the underlying stream is written to outside the guarded writer', () => {
    const calls: Buffer[] = [];
    const fakeStream = {
      write: (chunk: Buffer) => {
        calls.push(chunk);
        return true;
      },
    } as unknown as NodeJS.WritableStream;

    const guard = installStdoutGuard(fakeStream);
    expect(() => fakeStream.write(Buffer.from('stray console.log'))).toThrow(ProcessProtocolError);
    expect(calls).toHaveLength(0);

    guard.write(Buffer.from('protocol bytes'));
    expect(calls).toHaveLength(1);
    expect(calls[0]!.toString('utf8')).toBe('protocol bytes');

    guard.restore();
    fakeStream.write(Buffer.from('back to normal'));
    expect(calls).toHaveLength(2);
  });
});
