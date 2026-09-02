// The three-way merge driver: `securegit merge -- %O %A %B %L %P`.
//
// Without this, merging a protected file is a binary conflict with no option
// but to take one side whole. This decrypts all three inputs, runs Git's own
// `merge-file` over the plaintexts (conflict markers included on a conflict),
// and re-encrypts the result — which is why the driver never itself resolves
// or masks a conflict, only relocates where one is visible.
// See specs/securegit/12-diff-merge.md.
import { execFile as execFileCb } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { looksLikeEnvelope, parseEnvelope, seal, unseal } from './envelope.js';
import { LockedError } from './filter.js';
export { LockedError };
const execFile = promisify(execFileCb);
export class MergeError extends Error {
    code = 'MERGE';
    constructor(message) {
        super(message);
        this.name = 'MergeError';
    }
}
function lockedMessage(path) {
    return (`securegit: repository is locked\n` +
        `  file:   ${path}\n` +
        `  action: run \`securegit unlock\`, then retry`);
}
/**
 * Plaintext or (already-authenticated) ciphertext in, plaintext out. Unlike
 * `smudge`, this never passes ciphertext through on failure — a merge that
 * cannot see one side's real content cannot be trusted to produce anything,
 * so it fails the whole operation rather than guessing.
 */
function resolvePlaintext(content, keys, path, label) {
    if (!looksLikeEnvelope(content))
        return content; // predates protection, or filter was never installed
    let header;
    try {
        header = parseEnvelope(content);
    }
    catch (e) {
        throw new MergeError(`securegit: cannot merge ${path}: ${label} is not a valid envelope: ${e.message}`);
    }
    const rmk = keys.find(header.keyId);
    if (rmk === null) {
        throw new MergeError(`securegit: cannot merge ${path}: ${label} wants generation ${header.keyId}, which this keyring does not hold`);
    }
    try {
        return unseal(content, { rmk, path });
    }
    catch (e) {
        throw new MergeError(`securegit: cannot merge ${path}: authentication failed for ${label}: ${e.message}`);
    }
}
/**
 * Runs `git merge-file` in place over three temp files and reports whether it
 * was clean. Not `-p`: letting it rewrite `oursFile` directly, then reading
 * that back regardless of exit code, avoids depending on Node's undocumented
 * stdout-on-nonzero-exit behaviour for a subprocess result.
 */
async function runMergeFile(oursFile, baseFile, theirsFile, markerSize) {
    try {
        await execFile('git', ['merge-file', `--marker-size=${markerSize}`, oursFile, baseFile, theirsFile]);
        return true;
    }
    catch (e) {
        const err = e;
        if (typeof err.code === 'number' && err.code > 0) {
            return false; // conflicts remain; oursFile now holds markers
        }
        throw new MergeError(`securegit: git merge-file failed: ${e.message}`);
    }
}
export async function merge(opts) {
    const bindPath = opts.bindPath ?? false;
    const markerSize = opts.markerSize ?? 7;
    const basePlain = resolvePlaintext(opts.base, opts.keys, opts.path, 'the ancestor');
    const oursPlain = resolvePlaintext(opts.ours, opts.keys, opts.path, 'our side');
    const theirsPlain = resolvePlaintext(opts.theirs, opts.keys, opts.path, 'their side');
    // mkdtemp always creates its directory with mode 0700, satisfying the
    // "temporary files go in a 0700 directory" requirement without further work.
    const tmpDir = await mkdtemp(join(tmpdir(), 'securegit-merge-'));
    try {
        const baseFile = join(tmpDir, 'base');
        const oursFile = join(tmpDir, 'ours');
        const theirsFile = join(tmpDir, 'theirs');
        await writeFile(baseFile, basePlain);
        await writeFile(oursFile, oursPlain);
        await writeFile(theirsFile, theirsPlain);
        const clean = await runMergeFile(oursFile, baseFile, theirsFile, markerSize);
        const merged = await readFile(oursFile);
        const current = opts.keys.current();
        if (current === null) {
            throw new LockedError(lockedMessage(opts.path));
        }
        const output = seal(merged, {
            rmk: current.rmk,
            keyId: current.keyId,
            path: opts.path,
            bindPath,
        });
        return { clean, output };
    }
    finally {
        await rm(tmpDir, { recursive: true, force: true });
    }
}
//# sourceMappingURL=merge.js.map