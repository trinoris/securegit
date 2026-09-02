// `filter.securegit.process`: one process, the same clean/smudge byte-for-byte,
// spoken over pkt-line on stdin/stdout instead of one process per blob.
// See specs/securegit/11-filter-process.md.
import { DEFAULT_MAX_BYTES } from './envelope.js';
import { LockedError, clean, smudge } from './filter.js';
import { FLUSH, PktLineReader, encodePacket, encodePacketList, splitContent } from './pktline.js';
export class ProcessProtocolError extends Error {
    code = 'PROCESS_PROTOCOL';
    constructor(message) {
        super(message);
        this.name = 'ProcessProtocolError';
    }
}
function textPacket(line) {
    return encodePacket(Buffer.from(`${line}\n`, 'utf8'));
}
function parseLines(list) {
    return list.map((p) => p.toString('utf8').replace(/\n$/, ''));
}
function parseKeyValues(lines) {
    const map = new Map();
    for (const line of lines) {
        const eq = line.indexOf('=');
        if (eq === -1)
            continue;
        map.set(line.slice(0, eq), line.slice(eq + 1));
    }
    return map;
}
/**
 * Drives the `filter-process` protocol from raw stdin bytes. Stateful and
 * incremental by necessity: a header, a command, or a blob's content may
 * each arrive split across any number of `push()` calls, and Git may start
 * sending the next command's header before this one has finished writing —
 * so no method here blocks waiting for more data; each either makes
 * progress with what has arrived or returns having changed nothing.
 */
export class FilterProcessServer {
    ctx;
    reader = new PktLineReader();
    state = 'handshake';
    pendingHeader = null;
    contentChunks = [];
    contentBytes = 0;
    contentDiscarding = false;
    /**
     * Whether `clean` has succeeded at least once this run. Distinguishes "the
     * repository has been locked the whole time" (ordinary per-blob
     * `status=error`, matching `clean`'s own exit-1 case) from "it was
     * unlocked and now the session has expired" (`status=abort` — the one
     * case worth cutting the whole checkout short over, per the error table).
     */
    everUnlockedForClean = false;
    constructor(ctx) {
        this.ctx = ctx;
    }
    /** Feed raw bytes as they arrive from stdin, in order. */
    async push(chunk) {
        this.reader.push(chunk);
        await this.pump();
    }
    async pump() {
        for (;;) {
            switch (this.state) {
                case 'handshake': {
                    const list = this.reader.readList();
                    if (list === undefined)
                        return;
                    this.handleHandshake(list);
                    this.state = 'capabilities';
                    break;
                }
                case 'capabilities': {
                    const list = this.reader.readList();
                    if (list === undefined)
                        return;
                    this.handleCapabilities();
                    this.state = 'command-header';
                    break;
                }
                case 'command-header': {
                    const list = this.reader.readList();
                    if (list === undefined)
                        return;
                    this.pendingHeader = parseKeyValues(parseLines(list));
                    this.state = 'command-content';
                    break;
                }
                case 'command-content': {
                    const done = await this.drainContent();
                    if (!done)
                        return;
                    this.state = 'command-header';
                    break;
                }
            }
        }
    }
    handleHandshake(list) {
        const lines = parseLines(list);
        if (lines[0] !== 'git-filter-client' || !lines.includes('version=2')) {
            throw new ProcessProtocolError(`unexpected filter-process handshake: ${JSON.stringify(lines)}`);
        }
        this.ctx.write(textPacket('git-filter-server'));
        this.ctx.write(textPacket('version=2'));
        this.ctx.write(FLUSH);
    }
    /**
     * `clean` and `smudge` only. `delay` is deliberately not advertised even
     * if Git offers it — it exists for filters that fetch blobs remotely
     * (Git LFS), and we have nothing to fetch; advertising it would add a
     * queue and a second state machine for no benefit.
     */
    handleCapabilities() {
        this.ctx.write(textPacket('capability=clean'));
        this.ctx.write(textPacket('capability=smudge'));
        this.ctx.write(FLUSH);
    }
    /**
     * Pulls content packets one at a time rather than reading the whole list
     * at once, so an oversized blob can be rejected as soon as the running
     * total crosses the limit — discarding each further packet immediately —
     * instead of buffering it whole first and finding out only afterward.
     * Returns `false` ("more data needed, call again") until this content
     * list's terminating flush has arrived.
     */
    async drainContent() {
        const maxBytes = this.ctx.maxBytes ?? DEFAULT_MAX_BYTES;
        for (;;) {
            const item = this.reader.next();
            if (item === undefined)
                return false;
            if (item === null)
                break; // flush: this content list is complete
            if (!this.contentDiscarding) {
                this.contentBytes += item.length;
                if (this.contentBytes > maxBytes) {
                    this.contentDiscarding = true;
                    this.contentChunks = [];
                }
                else {
                    this.contentChunks.push(item);
                }
            }
        }
        const header = this.pendingHeader;
        this.pendingHeader = null;
        const oversized = this.contentDiscarding;
        const content = oversized ? Buffer.alloc(0) : Buffer.concat(this.contentChunks);
        this.contentChunks = [];
        this.contentBytes = 0;
        this.contentDiscarding = false;
        if (oversized) {
            this.ctx.warn(`securegit: rejecting oversized content for ${header.get('pathname') ?? '(unknown path)'}` +
                ` (exceeds ${maxBytes} bytes)`);
            this.writeStatus('error');
        }
        else {
            await this.handleCommand(header, content);
        }
        return true;
    }
    async handleCommand(header, content) {
        const command = header.get('command');
        const path = header.get('pathname') ?? '';
        if (command !== 'clean' && command !== 'smudge') {
            this.writeStatus('error');
            return;
        }
        const keys = await this.ctx.keys();
        const filterCtx = {
            keys,
            path,
            bindPath: this.ctx.bindPath,
            warn: this.ctx.warn,
            ...(this.ctx.maxBytes !== undefined ? { maxBytes: this.ctx.maxBytes } : {}),
            ...(this.ctx.padTo !== undefined ? { padTo: this.ctx.padTo } : {}),
        };
        if (command === 'clean') {
            let out;
            try {
                out = clean(content, filterCtx);
            }
            catch (e) {
                // Always warn, even for the locked case — `clean` throwing
                // `LockedError` with no diagnostic reaching the user would be a
                // silent failure Git can only report as "clean filter failed",
                // exactly the corruption implementation note 1 warns against, just
                // via an omission instead of a stray write.
                this.ctx.warn(e.message);
                this.writeStatus(e instanceof LockedError && this.everUnlockedForClean ? 'abort' : 'error');
                return;
            }
            this.everUnlockedForClean = true;
            this.writeSuccess(out);
            return;
        }
        // smudge fails open, per the asymmetry (07-unlock-session.md): a
        // missing key is `status=success` carrying ciphertext through unchanged,
        // never an abort. Only genuine corruption — `smudge` throws regardless
        // of a missing key — is a per-blob `status=error`.
        let out;
        try {
            out = smudge(content, filterCtx);
        }
        catch (e) {
            this.ctx.warn(e.message);
            this.writeStatus('error');
            return;
        }
        this.writeSuccess(out);
    }
    writeStatus(status) {
        this.ctx.write(encodePacketList([Buffer.from(`status=${status}\n`, 'utf8')]));
    }
    writeSuccess(content) {
        this.writeStatus('success');
        this.ctx.write(encodePacketList(splitContent(content)));
        this.ctx.write(FLUSH); // the trailing empty list: the status is unchanged
    }
}
/**
 * Installs a guard on a writable stream's `write` so only bytes passed
 * through the returned `write` function ever reach it — a stray
 * `console.log` (which ultimately calls `process.stdout.write`) anywhere in
 * this process is a protocol violation that would otherwise corrupt
 * whichever blob is mid-flight, silently. `restore()` puts the original back;
 * callers should install this before reading any stdin and restore it only
 * on exit.
 */
export function installStdoutGuard(target) {
    const realWrite = target.write.bind(target);
    let guardOpen = false;
    target.write = ((...args) => {
        if (!guardOpen) {
            throw new ProcessProtocolError('securegit: something wrote to stdout outside the filter-process protocol writer');
        }
        return realWrite(...args);
    });
    return {
        write(chunk) {
            guardOpen = true;
            try {
                realWrite(chunk);
            }
            finally {
                guardOpen = false;
            }
        },
        restore() {
            target.write = realWrite;
        },
    };
}
//# sourceMappingURL=process.js.map