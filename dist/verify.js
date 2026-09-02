// Config, attribute and content checks that catch the ways this design fails
// silently — a missing filter, a removed attribute, a plaintext blob that
// slipped past a pattern that stopped matching. See specs/securegit/13-verify.md.
//
// This module never touches a session or unwraps a key: every check works
// from public information (git config, .gitattributes, blob magic bytes), so
// `verify` runs identically whether the repository is locked or not.
//
// `historyReport()` (the `--history` walk) resolves attributes as of a given
// past commit using a temporary index (`GIT_INDEX_FILE` + `read-tree <sha>`,
// then `check-attr --cached`), not `check-attr --source <tree-ish>` — that
// flag needs Git 2.40, newer than this project can assume a real clone has.
import { execFile as execFileCb, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { readFile, readdir, stat, unlink } from 'node:fs/promises';
import { join, relative, isAbsolute, posix } from 'node:path';
import { tmpdir } from 'node:os';
import { randomBytes } from 'node:crypto';
import { readConfig, resolveKeyringPath } from './config.js';
import { readKeyringFile } from './keyring.js';
import { resolveSessionPath } from './session.js';
import { looksLikeEnvelope } from './envelope.js';
import { EXCLUSION_LINE, RESIDUE_SUFFIXES } from './install.js';
import { recipientsDir, recipientPath, readRecipientFile, removedRecipientsLogPath, readRemovedRecipientsLog, } from './recipients.js';
import { recoveryLogPath, readRecoveryLog } from './recovery.js';
const execFile = promisify(execFileCb);
export const EXIT_VERIFY_OK = 0;
export const EXIT_VERIFY_MISCONFIGURED = 2;
export const EXIT_VERIFY_LEAK = 5;
/**
 * Leak beats misconfiguration beats advice: a live plaintext exposure is
 * always the loudest thing to report. A residue finding (T12) is plaintext
 * sitting on disk rather than committed — real, but not the same severity as
 * a committed leak — so it joins failed checks at the misconfigured tier.
 */
export function verifyExitCode(report) {
    if (report.findings.some((f) => f.kind === 'leak'))
        return EXIT_VERIFY_LEAK;
    if (report.checks.some((c) => !c.ok) || report.findings.some((f) => f.kind === 'residue')) {
        return EXIT_VERIFY_MISCONFIGURED;
    }
    return EXIT_VERIFY_OK;
}
// ---------------------------------------------------------------------------
// heuristics
// ---------------------------------------------------------------------------
/** Filename patterns that suggest a file is sensitive, whether protected or not. */
export const NAME_HEURISTICS = [
    /\.env(\..+)?$/i,
    /secret/i,
    /credential/i,
    /(^|\/)id_rsa$/,
    /\.pem$/i,
    /\.p12$/i,
];
/** High-confidence content patterns — deliberately narrow, to keep false positives rare. */
export const CONTENT_HEURISTICS = [
    /AKIA[0-9A-Z]{16}/,
    /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
    /xox[baprs]-/,
];
/** Content heuristics only run on files at most this large. */
const CONTENT_SCAN_MAX_BYTES = 1024 * 1024;
function nameLooksSensitive(path) {
    return NAME_HEURISTICS.some((re) => re.test(path));
}
function contentLooksSensitive(content) {
    if (content.length > CONTENT_SCAN_MAX_BYTES)
        return false;
    const text = content.toString('utf8');
    return CONTENT_HEURISTICS.some((re) => re.test(text));
}
// ---------------------------------------------------------------------------
// git plumbing
// ---------------------------------------------------------------------------
async function gitConfigGet(repoDir, key) {
    try {
        const { stdout } = await execFile('git', ['config', '--local', '--get', key], { cwd: repoDir });
        return stdout.replace(/\n$/, '');
    }
    catch (e) {
        const err = e;
        if (err.code === 1)
            return null; // unset
        throw e;
    }
}
/** Exported for `cli.ts`'s `reencrypt`, which needs the same "which tracked paths are protected" scan. */
export async function listTrackedPaths(repoDir) {
    const { stdout } = await execFile('git', ['ls-files', '-z'], {
        cwd: repoDir,
        maxBuffer: 64 * 1024 * 1024,
    });
    return stdout.split('\0').filter((p) => p.length > 0);
}
/** `path: attribute: value` per requested attribute, parsed into a map. Exported for `cli.ts`'s `reencrypt`. */
export async function checkAttr(repoDir, path) {
    const { stdout } = await execFile('git', ['check-attr', 'filter', 'diff', 'text', 'ident', 'working-tree-encoding', '--', path], { cwd: repoDir });
    const out = {};
    for (const line of stdout.split('\n')) {
        if (!line)
            continue;
        const firstSep = line.lastIndexOf(': ');
        if (firstSep === -1)
            continue;
        const value = line.slice(firstSep + 2);
        const rest = line.slice(0, firstSep);
        const secondSep = rest.lastIndexOf(': ');
        if (secondSep === -1)
            continue;
        const attr = rest.slice(secondSep + 2);
        out[attr] = value;
    }
    return out;
}
/** The index's copy of a tracked path — what would be committed right now. Exported for `cli.ts`'s `reencrypt`. */
export async function readIndexBlob(repoDir, path) {
    const { stdout } = await execFile('git', ['cat-file', '-p', `:${path}`], {
        cwd: repoDir,
        encoding: 'buffer',
        maxBuffer: 512 * 1024 * 1024,
    });
    return stdout;
}
async function readAttributeLines(repoDir) {
    try {
        const content = await readFile(join(repoDir, '.gitattributes'), 'utf8');
        return content.split('\n').filter((_, i, arr) => !(i === arr.length - 1 && arr[i] === ''));
    }
    catch (e) {
        if (e.code === 'ENOENT')
            return [];
        throw e;
    }
}
function isInside(dir, path) {
    const rel = relative(dir, path);
    return rel !== '' && rel !== '..' && !rel.startsWith(`..${'/'}`) && !isAbsolute(rel);
}
async function pathExists(p) {
    try {
        await stat(p);
        return true;
    }
    catch {
        return false;
    }
}
/**
 * Residue file shapes (T12) beside a protected path — an editor backup, a
 * conflicted merge's `.orig`, a vim swap file — that exist in the worktree
 * and are not themselves tracked by Git. `.gitignore` (written by `protect`)
 * keeps these out of `git add -A`, but a residue file can predate `protect`,
 * or `protect` can have been run with `residuePatterns: false` — this checks
 * the filesystem directly rather than trusting the ignore rules exist.
 */
async function findResidue(repoDir, protectedPath, trackedPaths) {
    const found = [];
    for (const suffix of RESIDUE_SUFFIXES) {
        const candidate = `${protectedPath}${suffix}`;
        if (trackedPaths.has(candidate))
            continue;
        if (await pathExists(join(repoDir, candidate)))
            found.push(candidate);
    }
    // Vim's actual swap filename varies (.swp, then .swo, .swn, ...) — the
    // `.gitignore` line is the glob `.<base>.sw?`; checking the real directory
    // for anything sharing that prefix is the filesystem-level equivalent.
    const dir = posix.dirname(protectedPath);
    const base = posix.basename(protectedPath);
    const swapPrefix = `.${base}.sw`;
    let entries;
    try {
        entries = await readdir(join(repoDir, dir));
    }
    catch {
        entries = [];
    }
    for (const entry of entries) {
        if (!entry.startsWith(swapPrefix))
            continue;
        const candidate = dir === '.' ? entry : `${dir}/${entry}`;
        if (!trackedPaths.has(candidate))
            found.push(candidate);
    }
    return found;
}
// ---------------------------------------------------------------------------
export async function verify(opts) {
    const checks = [];
    const findings = [];
    let repoId = null;
    try {
        const config = await readConfig(opts.repoDir);
        repoId = config.repoId;
        checks.push({ id: 'repo-initialised', label: 'repository initialised', ok: true });
    }
    catch (e) {
        checks.push({
            id: 'repo-initialised',
            label: 'repository initialised',
            ok: false,
            detail: e.message,
        });
    }
    if (repoId !== null) {
        const keyringPath = resolveKeyringPath(repoId, opts.home);
        let providerIds = [];
        try {
            const keyring = await readKeyringFile(keyringPath);
            checks.push({ id: 'keyring-present', label: 'keyring present', ok: true });
            const current = keyring.generations.find((g) => g.generation === keyring.current);
            providerIds = current ? current.wrapped.map((w) => w.provider) : [];
        }
        catch {
            checks.push({
                id: 'keyring-present',
                label: 'keyring present',
                ok: false,
                detail: `no keyring found at ${keyringPath}`,
            });
        }
        if (providerIds.length > 0) {
            const describeById = new Map((opts.providers ?? []).map((p) => [p.id, p.describe()]));
            const known = providerIds.filter((id) => describeById.has(id));
            const nonCustodial = known.filter((id) => describeById.get(id).custodial === false);
            checks.push({
                id: 'non-custodial-unwrap-path',
                label: 'non-custodial unwrap path',
                ok: nonCustodial.length > 0,
                ...(nonCustodial.length === 0
                    ? {
                        detail: 'every provider that can unwrap the current generation could be compelled to produce the key',
                    }
                    : {}),
            });
        }
        const keyringInWorktree = isInside(opts.repoDir, keyringPath);
        const sessionPath = resolveSessionPath(repoId, opts.env ?? {}, opts.home);
        const sessionInWorktree = isInside(opts.repoDir, sessionPath);
        checks.push({
            id: 'key-material-outside-worktree',
            label: 'key material outside worktree',
            ok: !keyringInWorktree && !sessionInWorktree,
            ...(keyringInWorktree
                ? { detail: `keyring path ${keyringPath} is inside the repository` }
                : sessionInWorktree
                    ? { detail: `session path ${sessionPath} is inside the repository` }
                    : {}),
        });
    }
    const cleanCfg = await gitConfigGet(opts.repoDir, 'filter.securegit.clean');
    const processCfg = await gitConfigGet(opts.repoDir, 'filter.securegit.process');
    checks.push({
        id: 'filter-configured',
        label: 'filter configured',
        ok: cleanCfg !== null || processCfg !== null,
    });
    const requiredCfg = await gitConfigGet(opts.repoDir, 'filter.securegit.required');
    checks.push({
        id: 'filter-required',
        label: 'filter required',
        ok: requiredCfg === 'true',
        ...(requiredCfg !== 'true' ? { detail: `filter.securegit.required = ${requiredCfg ?? 'unset'}` } : {}),
    });
    const textconvCfg = await gitConfigGet(opts.repoDir, 'diff.securegit.textconv');
    checks.push({ id: 'diff-driver-configured', label: 'diff driver configured', ok: textconvCfg !== null });
    const cacheCfg = await gitConfigGet(opts.repoDir, 'diff.securegit.cachetextconv');
    checks.push({
        id: 'textconv-cache-disabled',
        label: 'textconv cache disabled',
        ok: cacheCfg !== 'true',
        ...(cacheCfg === 'true' ? { detail: 'diff.securegit.cachetextconv = true' } : {}),
    });
    const attrLines = await readAttributeLines(opts.repoDir);
    const patternCount = attrLines.filter((l) => l.includes('filter=securegit')).length;
    checks.push({ id: 'attributes-present', label: 'attributes present', ok: patternCount > 0 });
    const lastLine = attrLines[attrLines.length - 1];
    checks.push({
        id: 'metadata-exclusion',
        label: 'metadata exclusion',
        ok: lastLine === EXCLUSION_LINE,
    });
    const trackedPaths = await listTrackedPaths(opts.repoDir);
    const trackedSet = new Set(trackedPaths);
    const conflicting = [];
    for (const path of trackedPaths) {
        const attrs = await checkAttr(opts.repoDir, path);
        const isProtected = attrs.filter === 'securegit';
        if (isProtected) {
            for (const attr of ['text', 'ident', 'working-tree-encoding']) {
                const value = attrs[attr];
                if (value !== undefined && value !== 'unset' && value !== 'unspecified') {
                    conflicting.push(path);
                    break;
                }
            }
        }
        const content = await readIndexBlob(opts.repoDir, path);
        if (isProtected) {
            if (!looksLikeEnvelope(content)) {
                findings.push({
                    kind: 'leak',
                    path,
                    detail: `${path} is protected by an attribute, but its committed content is not a securegit envelope`,
                });
            }
            for (const residuePath of await findResidue(opts.repoDir, path, trackedSet)) {
                findings.push({
                    kind: 'residue',
                    path: residuePath,
                    detail: `${residuePath} is untracked plaintext residue beside the protected path ${path}`,
                });
            }
        }
        else if (nameLooksSensitive(path) || contentLooksSensitive(content)) {
            findings.push({
                kind: 'advice',
                path,
                detail: `${path} is not protected, and its name or content resembles a secret`,
            });
        }
    }
    checks.push({
        id: 'no-conflicting-attributes',
        label: 'no conflicting attributes',
        ok: conflicting.length === 0,
        ...(conflicting.length > 0 ? { detail: conflicting.join(', ') } : {}),
    });
    return { checks, findings };
}
function sortedGenerationKeys(keys) {
    return Object.keys(keys)
        .map(Number)
        .filter((n) => Number.isInteger(n))
        .sort((a, b) => a - b);
}
/**
 * "Who can read this repository, now and previously" — recipients, the
 * providers wrapping the keyring, and the two append-only logs
 * (`recovery-log.json`, `removed-recipients.json`). Like `verify()`, this
 * unwraps no key and touches no session: recipient files, the keyring's
 * `provider` field on each wrapped slot, and both logs are all public even
 * in a locked repository or on a machine with no keyring of its own.
 */
export async function accessReport(opts) {
    const recipients = [];
    let entries = [];
    try {
        entries = (await readdir(recipientsDir(opts.repoDir))).filter((f) => f.endsWith('.json'));
    }
    catch {
        // no recipients directory — nothing shared beyond the keyring itself
    }
    for (const entry of entries) {
        const file = await readRecipientFile(recipientPath(opts.repoDir, entry.replace(/\.json$/, '')));
        recipients.push({
            fingerprint: file.fingerprint,
            label: file.label,
            addedAt: file.addedAt,
            addedBy: file.addedBy,
            generations: sortedGenerationKeys(file.keys),
        });
    }
    const providers = [];
    try {
        const config = await readConfig(opts.repoDir);
        const keyring = await readKeyringFile(resolveKeyringPath(config.repoId, opts.home));
        const byProvider = new Map();
        for (const gen of keyring.generations) {
            for (const slot of gen.wrapped) {
                const list = byProvider.get(slot.provider);
                if (list)
                    list.push(gen.generation);
                else
                    byProvider.set(slot.provider, [gen.generation]);
            }
        }
        for (const [id, generations] of byProvider) {
            providers.push({ id, generations: generations.sort((a, b) => a - b) });
        }
    }
    catch {
        // no local keyring — e.g. a machine that joined purely via a recipient
        // file (08-multi-recipient.md); the providers section is simply empty.
    }
    const recoveryExports = await readRecoveryLog(recoveryLogPath(opts.repoDir));
    const removedRecipients = await readRemovedRecipientsLog(removedRecipientsLogPath(opts.repoDir));
    return { recipients, providers, recoveryExports, removedRecipients };
}
/** Exported for `cli.ts`'s `verify --history` output. */
export const TEXTCONV_NOTES_REF = 'refs/notes/textconv/securegit';
const FIELD_SEP = '\x1f'; // unit separator — safe against anything a commit subject could contain
async function execWithStdin(cmd, args, opts) {
    return new Promise((resolve, reject) => {
        const child = spawn(cmd, args, { cwd: opts.cwd, env: opts.env });
        const outChunks = [];
        const errChunks = [];
        child.stdout.on('data', (c) => outChunks.push(c));
        child.stderr.on('data', (c) => errChunks.push(c));
        child.on('error', reject);
        child.on('close', (code) => {
            if (code === 0)
                resolve(Buffer.concat(outChunks).toString('utf8'));
            else
                reject(new Error(`${cmd} ${args.join(' ')} exited ${code}: ${Buffer.concat(errChunks).toString('utf8')}`));
        });
        child.stdin.write(opts.input);
        child.stdin.end();
    });
}
/** Every commit reachable from any ref, oldest first. */
async function listAllCommits(repoDir) {
    const { stdout } = await execFile('git', ['rev-list', '--all', '--reverse'], {
        cwd: repoDir,
        maxBuffer: 64 * 1024 * 1024,
    });
    return stdout.split('\n').filter((s) => s.length > 0);
}
async function commitMeta(repoDir, sha) {
    const { stdout } = await execFile('git', ['log', '-1', `--format=%h${FIELD_SEP}%as${FIELD_SEP}%s`, sha], {
        cwd: repoDir,
    });
    const [shortSha, date, subject] = stdout.trim().split(FIELD_SEP);
    return { shortSha: shortSha ?? sha.slice(0, 7), date: date ?? '', subject: subject ?? '' };
}
/** Branches (not tags — the spec's example asks "still reachable from main") whose tip can reach `sha`. */
async function branchesContaining(repoDir, sha) {
    try {
        const { stdout } = await execFile('git', ['branch', '--contains', sha, '--format=%(refname:short)'], {
            cwd: repoDir,
        });
        return stdout.split('\n').filter((l) => l.length > 0);
    }
    catch {
        return [];
    }
}
/** `path -> blob SHA` for every tracked file at `sha`. */
async function treeEntries(repoDir, sha) {
    const { stdout } = await execFile('git', ['ls-tree', '-r', sha], {
        cwd: repoDir,
        maxBuffer: 64 * 1024 * 1024,
    });
    const out = [];
    for (const line of stdout.split('\n')) {
        if (!line)
            continue;
        const tab = line.indexOf('\t');
        if (tab === -1)
            continue;
        const meta = line.slice(0, tab).split(' ');
        if (meta[1] !== 'blob' || !meta[2])
            continue;
        out.push({ path: line.slice(tab + 1), blobSha: meta[2] });
    }
    return out;
}
/**
 * Which of `paths` were `filter=securegit` at the commit already loaded into
 * the index at `env.GIT_INDEX_FILE` — `--cached` reads `.gitattributes` from
 * that index only, never the working tree, which is what makes "as of a
 * given historical commit" possible: `git check-attr` has no `--source
 * <tree-ish>` option on the git version this project can assume (added in
 * 2.40; this project targets what a real clone is likely to have), but a
 * temporary index populated via `read-tree <sha>` gets the same resolution
 * for free, without ever materialising a worktree.
 */
async function protectedPathsAt(repoDir, env, paths) {
    if (paths.length === 0)
        return new Set();
    const input = paths.map((p) => `${p}\0`).join('');
    const stdout = await execWithStdin('git', ['check-attr', '--cached', '-z', '--stdin', 'filter'], {
        cwd: repoDir,
        env,
        input,
    });
    const fields = stdout.split('\0').filter((s) => s.length > 0);
    const out = new Set();
    for (let i = 0; i + 2 < fields.length; i += 3) {
        if (fields[i + 2] === 'securegit')
            out.add(fields[i]);
    }
    return out;
}
async function readBlob(repoDir, sha) {
    const { stdout } = await execFile('git', ['cat-file', '-p', sha], {
        cwd: repoDir,
        encoding: 'buffer',
        maxBuffer: 512 * 1024 * 1024,
    });
    return stdout;
}
async function textconvNotesRefStatus(repoDir) {
    try {
        await execFile('git', ['show-ref', '--verify', '--quiet', TEXTCONV_NOTES_REF], { cwd: repoDir });
    }
    catch {
        return { present: false, count: 0 };
    }
    try {
        const { stdout } = await execFile('git', ['notes', '--ref', 'textconv/securegit', 'list'], { cwd: repoDir });
        return { present: true, count: stdout.split('\n').filter((l) => l.trim().length > 0).length };
    }
    catch {
        return { present: true, count: 0 };
    }
}
/**
 * Walks every reachable commit (`git rev-list --all`), resolving
 * `filter=securegit` protection as it stood *at that commit* — a path
 * protected today may not have been then, and reporting it as a leak either
 * way would be wrong in one direction or the other. Every blob is read at
 * most once regardless of how many commits reference it unchanged, via a
 * plain `Map` keyed by blob SHA — content is content-addressed, so the same
 * SHA always means the same bytes.
 *
 * CI-tier speed, not pre-commit: a repository of any real size means
 * hundreds to thousands of `git` subprocess invocations. See "Use as a
 * hook" in 13-verify.md.
 */
export async function historyReport(opts) {
    const commits = await listAllCommits(opts.repoDir);
    const blobIsPlaintext = new Map();
    const perPath = new Map();
    const tmpIndex = join(tmpdir(), `securegit-verify-history-index-${randomBytes(4).toString('hex')}`);
    const env = { ...process.env, GIT_INDEX_FILE: tmpIndex };
    try {
        for (const sha of commits) {
            const entries = await treeEntries(opts.repoDir, sha);
            if (entries.length === 0)
                continue;
            await execFile('git', ['read-tree', sha], { cwd: opts.repoDir, env });
            const protectedPaths = await protectedPathsAt(opts.repoDir, env, entries.map((e) => e.path));
            for (const entry of entries) {
                if (!protectedPaths.has(entry.path))
                    continue;
                let plaintext = blobIsPlaintext.get(entry.blobSha);
                if (plaintext === undefined) {
                    const content = await readBlob(opts.repoDir, entry.blobSha);
                    plaintext = !looksLikeEnvelope(content);
                    blobIsPlaintext.set(entry.blobSha, plaintext);
                    opts.onBlobExamined?.(entry.blobSha);
                }
                if (!plaintext)
                    continue;
                const existing = perPath.get(entry.path);
                if (existing) {
                    existing.lastSha = sha;
                    existing.count += 1;
                }
                else {
                    perPath.set(entry.path, { firstSha: sha, lastSha: sha, count: 1 });
                }
            }
        }
    }
    finally {
        await unlink(tmpIndex).catch(() => { });
    }
    const findings = [];
    for (const [path, acc] of perPath) {
        const first = await commitMeta(opts.repoDir, acc.firstSha);
        const last = await commitMeta(opts.repoDir, acc.lastSha);
        const reachableFrom = await branchesContaining(opts.repoDir, acc.lastSha);
        findings.push({
            path,
            firstSha: first.shortSha,
            firstDate: first.date,
            firstSubject: first.subject,
            lastSha: last.shortSha,
            lastDate: last.date,
            lastSubject: last.subject,
            commitCount: acc.count,
            reachableFrom,
        });
    }
    const textconvNotesRef = await textconvNotesRefStatus(opts.repoDir);
    return { commitsWalked: commits.length, findings, textconvNotesRef };
}
/**
 * A static list, not a live audit: every M-code the spec catalogues, with
 * the two that respond to local config (`padTo`, `bindPath`) reflecting
 * their actual current mitigation state, and M11 (recipient metadata)
 * reporting whether it applies at all — every other observable is
 * unconditional (inherent to committing to a Git repository), so
 * `applies` is always `true` for them, and mitigation is always "no" per
 * the spec's own table.
 */
export async function metadataReport(opts) {
    const config = await readConfig(opts.repoDir);
    let recipientCount = 0;
    try {
        recipientCount = (await readdir(recipientsDir(opts.repoDir))).filter((f) => f.endsWith('.json')).length;
    }
    catch {
        // no recipients directory
    }
    const observables = [
        {
            code: 'M1',
            observable: 'Every file path and directory name',
            applies: true,
            note: 'not mitigable — tree objects are not filtered',
        },
        {
            code: 'M2',
            observable: 'File sizes, ± 63 bytes of envelope overhead',
            applies: true,
            note: config.padTo > 0
                ? `partially mitigated — padTo=${config.padTo}`
                : 'not mitigated — padTo is 0 (disabled)',
        },
        {
            code: 'M3',
            observable: 'Which commits touched which paths',
            applies: true,
            note: 'not mitigable — tree diffs',
        },
        {
            code: 'M4',
            observable: 'Commit messages',
            applies: true,
            note: 'not mitigable — commit objects are not filtered',
        },
        {
            code: 'M5',
            observable: 'Author name, email, timestamps',
            applies: true,
            note: 'not mitigable — commit objects',
        },
        {
            code: 'M6',
            observable: 'Branch and tag names',
            applies: true,
            note: 'not mitigable — refs',
        },
        {
            code: 'M7',
            observable: 'The commit graph — merges, rate, contributors',
            applies: true,
            note: 'not mitigable — commit objects',
        },
        {
            code: 'M8',
            observable: 'Blob equality across paths, commits and branches',
            applies: true,
            note: config.bindPath ? 'partially mitigated — bindPath is on' : 'not mitigated — bindPath is off',
        },
        {
            code: 'M9',
            observable: 'Whether a change reverted to an earlier state',
            applies: true,
            note: 'not mitigable — neither bindPath nor padTo removes this',
        },
        {
            code: 'M10',
            observable: 'Which files are protected at all',
            applies: true,
            note: 'not mitigable — .gitattributes is plaintext',
        },
        {
            code: 'M11',
            observable: 'Recipient count, labels, fingerprints, join dates',
            applies: recipientCount > 0,
            note: recipientCount > 0
                ? 'not mitigable — .securegit/recipients/ is plaintext'
                : 'does not apply — no recipients',
        },
        {
            code: 'M12',
            observable: 'Key generation in use per blob',
            applies: true,
            note: 'not mitigable — envelope keyId',
        },
    ];
    return { observables };
}
//# sourceMappingURL=verify.js.map