// The command surface: wires config/install/keyring/provider/session/filter/
// envelope into `securegit <command>`.
//
// Every command takes an injected CliIO rather than touching process.* — that
// is the seam that makes this testable without spawning real subprocesses.
// `bin/securegit.ts` is the thin adapter that wires process.argv/stdin/stdout
// to this function for the real executable.
// See specs/securegit/10-cli-contract.md.

import { readFile, writeFile } from 'node:fs/promises';
import { ConfigError, initConfig, readConfig, resolveKeyringPath, type RepoConfig } from './config.js';
import { InstallError, install, protect } from './install.js';
import { KeyringError, createKeyring, readKeyringFile, unlockKeyring, writeKeyringFile } from './keyring.js';
import { PassphraseFileProvider, ProviderError } from './provider.js';
import { lockSession, readSession, resolveSessionPath, writeSession } from './session.js';
import { LockedError, clean, smudge, textconv, type KeySource } from './filter.js';
import { EnvelopeError, parseEnvelope, seal, unseal } from './envelope.js';
import { verify, verifyExitCode } from './verify.js';
import { merge } from './merge.js';

export const EXIT_OK = 0;
export const EXIT_LOCKED = 1;
export const EXIT_MISCONFIGURED = 2;
export const EXIT_CRYPTO = 3;
export const EXIT_USAGE = 4;
export const EXIT_LEAK = 5;

export interface CliIO {
  /** Command and its arguments — NOT including "node" or the script path. */
  argv: string[];
  cwd: string;
  env: NodeJS.ProcessEnv;
  /** File content for clean/smudge/encrypt/decrypt/inspect; whole-buffer. */
  stdin: Buffer;
  /** Equivalent of os.homedir(), injected so tests never touch the real one. */
  home: string;
  /** The content channel. Only clean/smudge/textconv/encrypt/decrypt write here. */
  stdout: (chunk: Buffer) => void;
  /** Every diagnostic, prompt and warning. Never receives plaintext or key material. */
  stderr: (message: string) => void;
  now?: () => Date;
}

const USAGE =
  'usage: securegit <init|install|protect|unlock|lock|status|verify|clean|smudge|textconv|merge|encrypt|decrypt|inspect> ...';

function resolvePassphrase(io: CliIO): string {
  const fromEnv = io.env.SECUREGIT_PASSPHRASE;
  if (fromEnv !== undefined && fromEnv.length > 0) return fromEnv;
  return io.stdin.toString('utf8').replace(/\r?\n$/, '');
}

function sessionPathFor(config: RepoConfig, io: CliIO): string {
  return resolveSessionPath(config.repoId, io.env, io.home);
}

type Loaded = { ok: true; config: RepoConfig; keys: KeySource } | { ok: false; code: number };

/** The read side shared by clean/smudge/textconv/encrypt/decrypt: config + session. */
async function loadKeys(io: CliIO): Promise<Loaded> {
  let config: RepoConfig;
  try {
    config = await readConfig(io.cwd);
  } catch (e) {
    io.stderr((e as Error).message);
    return { ok: false, code: EXIT_MISCONFIGURED };
  }
  const keys = await readSession({
    repoId: config.repoId,
    path: sessionPathFor(config, io),
    warn: io.stderr,
    ...(io.now !== undefined ? { now: io.now } : {}),
  });
  return { ok: true, config, keys };
}

// ---------------------------------------------------------------------------
// repository lifecycle
// ---------------------------------------------------------------------------

async function cmdInit(args: string[], io: CliIO): Promise<number> {
  const bindPath = args.includes('--bind-path');

  let config: RepoConfig;
  try {
    config = await initConfig(io.cwd, { bindPath });
  } catch (e) {
    io.stderr((e as Error).message);
    return e instanceof ConfigError ? EXIT_USAGE : EXIT_USAGE;
  }

  const passphrase = resolvePassphrase(io);
  const provider = new PassphraseFileProvider(() => passphrase);

  let created;
  try {
    created = await createKeyring(config.repoId, [provider]);
  } catch (e) {
    io.stderr((e as Error).message);
    return EXIT_USAGE;
  }

  const keyringPath = resolveKeyringPath(config.repoId, io.home);
  await writeKeyringFile(keyringPath, created.file);

  io.stderr(
    `securegit: initialized repository ${config.repoId}\n` +
      `  keyring: ${keyringPath}\n` +
      `  next:    securegit protect <pattern>, then securegit unlock`,
  );
  return EXIT_OK;
}

async function cmdInstall(args: string[], io: CliIO): Promise<number> {
  const useProcess = args.includes('--process');
  const force = args.includes('--force');
  const required = !args.includes('--no-required');
  const binIdx = args.indexOf('--bin');
  const bin = binIdx !== -1 ? args[binIdx + 1] : undefined;

  try {
    await install({
      repoDir: io.cwd,
      process: useProcess,
      required,
      force,
      ...(bin !== undefined ? { bin } : {}),
    });
  } catch (e) {
    io.stderr((e as Error).message);
    return EXIT_MISCONFIGURED;
  }
  io.stderr(`securegit: filter configuration installed${useProcess ? ' (process form)' : ''}`);
  return EXIT_OK;
}

async function cmdProtect(args: string[], io: CliIO): Promise<number> {
  const patterns = args.filter((a) => !a.startsWith('--'));
  if (patterns.length === 0) {
    io.stderr('securegit: protect requires at least one pattern');
    return EXIT_USAGE;
  }
  const residuePatterns = !args.includes('--no-residue');
  try {
    await protect(io.cwd, patterns, { residuePatterns });
  } catch (e) {
    io.stderr((e as Error).message);
    return EXIT_USAGE;
  }
  io.stderr(`securegit: protecting ${patterns.join(', ')}`);
  return EXIT_OK;
}

// ---------------------------------------------------------------------------
// keys and session
// ---------------------------------------------------------------------------

async function cmdUnlock(args: string[], io: CliIO): Promise<number> {
  let config: RepoConfig;
  try {
    config = await readConfig(io.cwd);
  } catch (e) {
    io.stderr((e as Error).message);
    return EXIT_MISCONFIGURED;
  }

  const keyringPath = resolveKeyringPath(config.repoId, io.home);
  let file;
  try {
    file = await readKeyringFile(keyringPath);
  } catch {
    io.stderr(
      `securegit: no keyring found at ${keyringPath}\n` +
        `  action: run \`securegit init\`, or join via a recipient`,
    );
    return EXIT_MISCONFIGURED;
  }

  const passphrase = resolvePassphrase(io);
  const provider = new PassphraseFileProvider(() => passphrase);
  let keys;
  try {
    keys = await unlockKeyring(file, [provider], { warn: io.stderr, expectedRepoId: config.repoId });
  } catch (e) {
    io.stderr((e as Error).message);
    return EXIT_MISCONFIGURED;
  }

  const current = keys.current();
  if (current === null) {
    io.stderr(
      "securegit: could not unlock — wrong passphrase, or this keyring holds none of the repository's generations",
    );
    return EXIT_LOCKED;
  }

  const ttlIdx = args.indexOf('--ttl');
  const ttlArg = ttlIdx !== -1 ? args[ttlIdx + 1] : undefined;
  const ttlSeconds = ttlArg !== undefined ? Number(ttlArg) : undefined;

  const entries = keys.available().map((keyId) => ({ keyId, rmk: keys.find(keyId)! }));
  await writeSession({
    repoId: config.repoId,
    path: sessionPathFor(config, io),
    entries,
    current: current.keyId,
    ...(ttlSeconds !== undefined ? { ttlSeconds } : {}),
    ...(io.now !== undefined ? { now: io.now } : {}),
  });

  io.stderr(`securegit: unlocked (generation ${current.keyId})`);
  return EXIT_OK;
}

async function cmdLock(_args: string[], io: CliIO): Promise<number> {
  let config: RepoConfig;
  try {
    config = await readConfig(io.cwd);
  } catch (e) {
    io.stderr((e as Error).message);
    return EXIT_MISCONFIGURED;
  }
  await lockSession({ repoId: config.repoId, path: sessionPathFor(config, io) });
  io.stderr('securegit: locked');
  return EXIT_OK;
}

async function cmdStatus(_args: string[], io: CliIO): Promise<number> {
  const loaded = await loadKeys(io);
  if (!loaded.ok) return loaded.code;
  const current = loaded.keys.current();
  io.stderr(
    `repository   ${io.cwd}\n` +
      `repoId       ${loaded.config.repoId}\n` +
      `bindPath     ${loaded.config.bindPath}\n` +
      `session      ${current ? `unlocked, generation ${current.keyId}` : 'locked'}`,
  );
  return current ? EXIT_OK : EXIT_LOCKED;
}

/** No key required — every check here works from public information. See 13-verify.md. */
async function cmdVerify(_args: string[], io: CliIO): Promise<number> {
  // Only `describe()` is ever called on this — verify() unwraps nothing, so
  // it never needs a real passphrase.
  const provider = new PassphraseFileProvider(() => '');

  let report;
  try {
    report = await verify({ repoDir: io.cwd, home: io.home, env: io.env, providers: [provider] });
  } catch (e) {
    io.stderr((e as Error).message);
    return EXIT_MISCONFIGURED;
  }

  const lines: string[] = [];
  for (const check of report.checks) {
    const mark = check.ok ? '✓' : '✗';
    lines.push(check.detail ? `  ${mark}  ${check.label} — ${check.detail}` : `  ${mark}  ${check.label}`);
  }
  for (const finding of report.findings) {
    const mark = finding.kind === 'leak' ? '✗' : '⚠';
    lines.push(`  ${mark}  ${finding.kind}: ${finding.path} — ${finding.detail}`);
  }
  io.stderr(lines.join('\n'));
  return verifyExitCode(report);
}

// ---------------------------------------------------------------------------
// Git filters — stdin/stdout are content channels here, not diagnostics
// ---------------------------------------------------------------------------

interface ParsedPathArg {
  path: string;
  flags: Set<string>;
}

function parsePathArg(args: string[]): ParsedPathArg | null {
  const sepIdx = args.indexOf('--');
  if (sepIdx === -1) return null;
  const rest = args.slice(sepIdx + 1);
  const path = rest[0];
  if (!path) return null;
  return { path, flags: new Set(args.slice(0, sepIdx)) };
}

async function cmdClean(args: string[], io: CliIO): Promise<number> {
  const parsed = parsePathArg(args);
  if (!parsed) {
    io.stderr('usage: securegit clean -- <path>');
    return EXIT_USAGE;
  }
  const loaded = await loadKeys(io);
  if (!loaded.ok) return loaded.code;

  try {
    const out = clean(io.stdin, {
      keys: loaded.keys,
      path: parsed.path,
      bindPath: loaded.config.bindPath,
    });
    io.stdout(out);
    return EXIT_OK;
  } catch (e) {
    io.stderr((e as Error).message);
    return e instanceof LockedError ? EXIT_LOCKED : EXIT_CRYPTO;
  }
}

async function cmdSmudge(args: string[], io: CliIO): Promise<number> {
  const parsed = parsePathArg(args);
  if (!parsed) {
    io.stderr('usage: securegit smudge -- <path>');
    return EXIT_USAGE;
  }
  const loaded = await loadKeys(io);
  if (!loaded.ok) return loaded.code;

  try {
    const out = smudge(io.stdin, {
      keys: loaded.keys,
      path: parsed.path,
      bindPath: loaded.config.bindPath,
      strict: parsed.flags.has('--strict'),
      warn: io.stderr,
    });
    io.stdout(out);
    return EXIT_OK;
  } catch (e) {
    io.stderr((e as Error).message);
    return e instanceof LockedError ? EXIT_LOCKED : EXIT_CRYPTO;
  }
}

async function cmdTextconv(args: string[], io: CliIO): Promise<number> {
  const parsed = parsePathArg(args);
  if (!parsed) {
    io.stderr('usage: securegit textconv -- <file>');
    return EXIT_USAGE;
  }
  const loaded = await loadKeys(io);
  if (!loaded.ok) return loaded.code;

  // Git gives textconv a real file path (a temp copy of the blob), not stdin.
  const content = await readFile(parsed.path);
  const out = textconv(content, {
    keys: loaded.keys,
    path: parsed.path,
    bindPath: loaded.config.bindPath,
  });
  io.stdout(out);
  return EXIT_OK;
}

interface ParsedMergeArgs {
  basePath: string;
  oursPath: string;
  theirsPath: string;
  markerSize: number;
  path: string;
}

/** `securegit merge -- %O %A %B %L %P` — base, ours, theirs, marker size, path. */
function parseMergeArgs(args: string[]): ParsedMergeArgs | null {
  const sepIdx = args.indexOf('--');
  if (sepIdx === -1) return null;
  const [basePath, oursPath, theirsPath, markerSizeArg, path] = args.slice(sepIdx + 1);
  if (!basePath || !oursPath || !theirsPath || !markerSizeArg || !path) return null;
  const markerSize = Number(markerSizeArg);
  if (!Number.isInteger(markerSize)) return null;
  return { basePath, oursPath, theirsPath, markerSize, path };
}

async function cmdMerge(args: string[], io: CliIO): Promise<number> {
  const parsed = parseMergeArgs(args);
  if (!parsed) {
    io.stderr('usage: securegit merge -- <base> <ours> <theirs> <markerSize> <path>');
    return EXIT_USAGE;
  }
  const loaded = await loadKeys(io);
  if (!loaded.ok) return loaded.code;

  const [base, ours, theirs] = await Promise.all([
    readFile(parsed.basePath),
    readFile(parsed.oursPath),
    readFile(parsed.theirsPath),
  ]);

  try {
    const result = await merge({
      keys: loaded.keys,
      path: parsed.path,
      bindPath: loaded.config.bindPath,
      markerSize: parsed.markerSize,
      base,
      ours,
      theirs,
    });
    // %A must always be overwritten, clean or not — that's how Git knows what
    // to show in the worktree, and `smudge` decrypts it either way.
    await writeFile(parsed.oursPath, result.output);
    // 1 here means "conflict", mirroring `git merge-file` — the same numeric
    // code the catch block below returns for `LockedError`. Deliberately not
    // disambiguated: Git's merge-driver protocol only distinguishes zero from
    // nonzero, and a caller that needs to tell them apart still can — a
    // locked failure always writes a diagnostic to stderr; a conflict (not a
    // failure — Git shows it on its own) never does. See 10-cli-contract.md.
    return result.clean ? EXIT_OK : 1;
  } catch (e) {
    io.stderr((e as Error).message);
    return e instanceof LockedError ? EXIT_LOCKED : EXIT_CRYPTO;
  }
}

// ---------------------------------------------------------------------------
// ad hoc — exist so the cryptography is testable without a repository
// ---------------------------------------------------------------------------

async function readInput(path: string, io: CliIO): Promise<Buffer> {
  return path === '-' ? io.stdin : readFile(path);
}

async function writeOutput(path: string, data: Buffer, io: CliIO): Promise<void> {
  if (path === '-') {
    io.stdout(data);
    return;
  }
  await writeFile(path, data);
}

function outArg(args: string[]): string {
  const idx = args.indexOf('--out');
  return idx !== -1 ? (args[idx + 1] ?? '-') : '-';
}

async function cmdEncrypt(args: string[], io: CliIO): Promise<number> {
  const input = args.find((a) => !a.startsWith('--'));
  if (!input) {
    io.stderr('usage: securegit encrypt <file|-> [--out <file|->]');
    return EXIT_USAGE;
  }
  const loaded = await loadKeys(io);
  if (!loaded.ok) return loaded.code;

  const current = loaded.keys.current();
  if (!current) {
    io.stderr('securegit: repository is locked; run `securegit unlock`');
    return EXIT_LOCKED;
  }

  const data = await readInput(input, io);
  const out = seal(data, {
    rmk: current.rmk,
    keyId: current.keyId,
    path: input === '-' ? 'stdin' : input,
    bindPath: loaded.config.bindPath,
  });
  await writeOutput(outArg(args), out, io);
  return EXIT_OK;
}

async function cmdDecrypt(args: string[], io: CliIO): Promise<number> {
  const input = args.find((a) => !a.startsWith('--'));
  if (!input) {
    io.stderr('usage: securegit decrypt <file|-> [--out <file|->]');
    return EXIT_USAGE;
  }
  const loaded = await loadKeys(io);
  if (!loaded.ok) return loaded.code;

  const data = await readInput(input, io);
  let header;
  try {
    header = parseEnvelope(data);
  } catch (e) {
    io.stderr((e as Error).message);
    return EXIT_CRYPTO;
  }

  const rmk = loaded.keys.find(header.keyId);
  if (!rmk) {
    io.stderr(`securegit: this keyring does not hold generation ${header.keyId}`);
    return EXIT_LOCKED;
  }

  try {
    const out = unseal(data, { rmk, path: input === '-' ? 'stdin' : input });
    await writeOutput(outArg(args), out, io);
    return EXIT_OK;
  } catch (e) {
    io.stderr((e as Error).message);
    return EXIT_CRYPTO;
  }
}

async function cmdInspect(args: string[], io: CliIO): Promise<number> {
  const input = args.find((a) => !a.startsWith('--'));
  if (!input) {
    io.stderr('usage: securegit inspect <file|->');
    return EXIT_USAGE;
  }
  const data = await readInput(input, io);
  let header;
  try {
    header = parseEnvelope(data);
  } catch (e) {
    io.stderr((e as Error).message);
    return EXIT_CRYPTO;
  }
  io.stderr(
    `format      ${header.format}\n` +
      `algorithm   ${header.algorithm}\n` +
      `flags       bindPath=${header.bindPath}\n` +
      `keyId       ${header.keyId}\n` +
      `ciphertext  ${header.ciphertext.length} bytes`,
  );
  return EXIT_OK;
}

// ---------------------------------------------------------------------------

export async function runCli(io: CliIO): Promise<number> {
  const [cmd, ...rest] = io.argv;
  try {
    switch (cmd) {
      case 'init':
        return await cmdInit(rest, io);
      case 'install':
        return await cmdInstall(rest, io);
      case 'protect':
        return await cmdProtect(rest, io);
      case 'unlock':
        return await cmdUnlock(rest, io);
      case 'lock':
        return await cmdLock(rest, io);
      case 'status':
        return await cmdStatus(rest, io);
      case 'verify':
        return await cmdVerify(rest, io);
      case 'clean':
        return await cmdClean(rest, io);
      case 'smudge':
        return await cmdSmudge(rest, io);
      case 'textconv':
        return await cmdTextconv(rest, io);
      case 'merge':
        return await cmdMerge(rest, io);
      case 'encrypt':
        return await cmdEncrypt(rest, io);
      case 'decrypt':
        return await cmdDecrypt(rest, io);
      case 'inspect':
        return await cmdInspect(rest, io);
      case '--help':
      case '-h':
        io.stderr(USAGE);
        return EXIT_OK;
      default:
        io.stderr(cmd ? `securegit: unknown command '${cmd}'\n${USAGE}` : USAGE);
        return EXIT_USAGE;
    }
  } catch (e) {
    if (e instanceof KeyringError || e instanceof ProviderError || e instanceof InstallError) {
      io.stderr((e as Error).message);
      return EXIT_USAGE;
    }
    if (e instanceof EnvelopeError) {
      io.stderr((e as Error).message);
      return EXIT_CRYPTO;
    }
    io.stderr(`securegit: unexpected error: ${(e as Error).message}`);
    return EXIT_USAGE;
  }
}
