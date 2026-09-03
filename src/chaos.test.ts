// C1: real subprocess kills at randomized delays during a keyring/session/
// config write, proving the temp-file-plus-rename pattern never leaves a
// torn file live at the real path. See specs/chaotests/00-test-plan.md.
//
// Real chaos, not simulated: `node <BIN> <args>` is spawned as an actual OS
// process and SIGKILL'd from here, so the kill lands wherever the process
// genuinely was at that instant — which async step, which syscall — not
// wherever a mock decided to throw. The delay sweep below spans "before the
// process has done anything" through "almost certainly already finished",
// on the theory that the real interesting window (mid file-write) is
// somewhere in between and narrow; many points across a wide range beats
// guessing the one right number.

import { describe, it, expect, beforeAll, beforeEach, afterEach } from 'vitest';
import { spawn, execFile as execFileCb } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { readConfig, resolveKeyringPath, ConfigError } from './config.js';
import { readKeyringFile } from './keyring.js';
import { readSession, resolveSessionPath } from './session.js';

const execFile = promisify(execFileCb);

const REPO_ROOT = join(import.meta.dirname, '..');
const BIN = join(REPO_ROOT, 'dist', 'bin', 'securegit.js');
const PASSPHRASE = 'correct horse battery staple';

// A hardcoded millisecond sweep can't work here: cold Node/ESM startup
// alone is ~250ms on this machine, and `init`/`unlock`/`key rotate` each
// add their own scrypt cost on top (deliberately expensive, DEFAULT_SCRYPT_N
// — see 06-key-provider-port.md) — a delay short enough to matter on a fast
// CI runner would land before a slow one has even loaded its modules, and
// vice versa. Instead, each test measures its own command's *natural*
// duration once, then sweeps delays as fractions of that — self-calibrating
// to whatever machine actually runs it.
const DELAY_FRACTIONS = [0.05, 0.15, 0.3, 0.45, 0.6, 0.75, 0.85, 0.95, 1.05, 1.2];

function fractionDelays(naturalDurationMs: number): number[] {
  return DELAY_FRACTIONS.map((f) => Math.max(0, Math.round(naturalDurationMs * f)));
}

/** Runs `args` to completion once, unkilled, and reports how long it took. */
async function measureNaturalDuration(
  args: string[],
  opts: { cwd: string; env: NodeJS.ProcessEnv },
): Promise<number> {
  const start = Date.now();
  const code = await runToCompletion(args, opts);
  if (code !== 0) {
    throw new Error(`calibration run of ${JSON.stringify(args)} exited ${code}, expected 0`);
  }
  return Date.now() - start;
}

beforeAll(async () => {
  await execFile('npm', ['run', 'build'], { cwd: REPO_ROOT });
}, 60_000);

function baseEnv(home: string): NodeJS.ProcessEnv {
  return { PATH: process.env.PATH, HOME: home, SECUREGIT_PASSPHRASE: PASSPHRASE };
}

/** Runs a real `node BIN <args>` subprocess and SIGKILLs it after `delayMs`. */
async function spawnAndKill(
  args: string[],
  delayMs: number,
  opts: { cwd: string; env: NodeJS.ProcessEnv },
): Promise<{ killed: boolean; code: number | null; signal: NodeJS.Signals | null }> {
  const child = spawn('node', [BIN, ...args], { cwd: opts.cwd, env: opts.env, stdio: 'ignore' });
  let killed = false;
  const timer = setTimeout(() => {
    killed = true;
    child.kill('SIGKILL');
  }, delayMs);
  const result = await new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve) => {
    child.on('exit', (code, signal) => resolve({ code, signal }));
  });
  clearTimeout(timer);
  return { killed, ...result };
}

/**
 * Runs a real `node BIN <args>` subprocess to completion, no kill. Uses
 * `spawn` with stdin ignored (not `execFile`, whose default piped stdin
 * never closes — the real binary's `readStdin()` waits for an EOF that
 * would then never come, hanging the whole run).
 */
async function runToCompletion(args: string[], opts: { cwd: string; env: NodeJS.ProcessEnv }): Promise<number> {
  const child = spawn('node', [BIN, ...args], { cwd: opts.cwd, env: opts.env, stdio: 'ignore' });
  const { code } = await new Promise<{ code: number | null }>((resolve) => {
    child.on('exit', (code) => resolve({ code }));
  });
  return code ?? 1;
}

describe('C1: killed mid-write', () => {
  let dir: string;
  let home: string;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), 'securegit-chaos-'));
    home = await mkdtemp(join(tmpdir(), 'securegit-chaos-home-'));
    await execFile('git', ['init', '--quiet'], { cwd: dir });
    await execFile('git', ['config', 'user.name', 'Test'], { cwd: dir });
    await execFile('git', ['config', 'user.email', 'test@example.com'], { cwd: dir });
  });

  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
    await rm(home, { recursive: true, force: true });
  });

  it(
    "`init` killed at a random point never leaves config.json torn — absent or fully valid, never a fragment readConfig() can't cleanly classify",
    async () => {
      // A throwaway repo purely to time an unkilled run — `init` can only
      // succeed once per repo, so this can't reuse any repo the sweep below
      // also uses.
      const calibDir = await mkdtemp(join(tmpdir(), 'securegit-chaos-init-calib-'));
      let naturalMs: number;
      try {
        await execFile('git', ['init', '--quiet'], { cwd: calibDir });
        await execFile('git', ['config', 'user.name', 'Test'], { cwd: calibDir });
        await execFile('git', ['config', 'user.email', 'test@example.com'], { cwd: calibDir });
        naturalMs = await measureNaturalDuration(['init'], { cwd: calibDir, env: baseEnv(home) });
      } finally {
        await rm(calibDir, { recursive: true, force: true });
      }

      for (const delayMs of fractionDelays(naturalMs)) {
        const iterDir = await mkdtemp(join(tmpdir(), 'securegit-chaos-init-'));
        try {
          await execFile('git', ['init', '--quiet'], { cwd: iterDir });
          await execFile('git', ['config', 'user.name', 'Test'], { cwd: iterDir });
          await execFile('git', ['config', 'user.email', 'test@example.com'], { cwd: iterDir });

          await spawnAndKill(['init'], delayMs, { cwd: iterDir, env: baseEnv(home) });

          let config: Awaited<ReturnType<typeof readConfig>> | undefined;
          let configError: unknown;
          try {
            config = await readConfig(iterDir);
          } catch (e) {
            configError = e;
          }

          if (configError !== undefined) {
            // Only "nothing written yet" is an acceptable failure shape —
            // anything else (a torn file readConfig can't parse) would mean
            // the write isn't actually atomic.
            expect(configError).toBeInstanceOf(ConfigError);
            expect((configError as ConfigError).message).toContain('no repository configuration found');
            // Recoverable: a fresh init on the same, still-uninitialised repo works.
            expect(await runToCompletion(['init'], { cwd: iterDir, env: baseEnv(home) })).toBe(0);
          } else {
            expect(config!.version).toBe(1);
            expect(config!.repoId).toMatch(/^[0-9a-f]{32}$/);
            expect(typeof config!.bindPath).toBe('boolean');
            expect(typeof config!.padTo).toBe('number');
          }
        } finally {
          await rm(iterDir, { recursive: true, force: true });
        }
      }
    },
    60_000,
  );

  it(
    '`unlock` killed at a random point never leaves the session torn — absent (locked) or fully valid, never a fragment readSession() has to guess about',
    async () => {
      await runToCompletion(['init'], { cwd: dir, env: baseEnv(home) });
      const repoId = (await readConfig(dir)).repoId;
      const sessionPath = resolveSessionPath(repoId, {}, home);
      const naturalMs = await measureNaturalDuration(['unlock'], { cwd: dir, env: baseEnv(home) });

      for (const delayMs of fractionDelays(naturalMs)) {
        await spawnAndKill(['unlock'], delayMs, { cwd: dir, env: baseEnv(home) });

        const source = await readSession({ repoId, path: sessionPath });
        const current = source.current();
        if (current !== null) {
          // keyId is `<generation>.<fingerprint>` (keyIdFor(), keyring.ts) —
          // generation 1 is the only one that can exist this early.
          expect(current.keyId.startsWith('1.')).toBe(true);
          expect(current.rmk.length).toBe(32);
        }
        // Either shape is fine — what matters is readSession() never threw
        // and never returned something that isn't cleanly one or the other.

        // Recoverable regardless of where the kill landed.
        expect(await runToCompletion(['unlock'], { cwd: dir, env: baseEnv(home) })).toBe(0);
      }
    },
    60_000,
  );

  it(
    '`key rotate` killed at a random point never leaves the keyring torn — the old generation list or the fully-rotated one, never a fragment',
    async () => {
      await runToCompletion(['init'], { cwd: dir, env: baseEnv(home) });
      const config = await readConfig(dir);
      await runToCompletion(['unlock'], { cwd: dir, env: baseEnv(home) });
      const keyringPath = resolveKeyringPath(config.repoId, home);
      // `rotate`'s own dirty-tree check (F13) refuses over the untracked
      // `.securegit/config.json` `init` just created — commit it first so
      // the tree is clean and rotate actually reaches the keyring rewrite.
      await execFile('git', ['add', '-A'], { cwd: dir, env: baseEnv(home) });
      await execFile('git', ['commit', '--quiet', '-m', 'init'], { cwd: dir, env: baseEnv(home) });
      // A real rotation for timing — the sweep below doesn't care which
      // generation it starts from, only that each kill lands somewhere in a
      // real rotate's actual duration.
      const naturalMs = await measureNaturalDuration(['key', 'rotate', '--confirm-recipients', '0'], {
        cwd: dir,
        env: baseEnv(home),
      });
      await runToCompletion(['unlock'], { cwd: dir, env: baseEnv(home) });

      for (const delayMs of fractionDelays(naturalMs)) {
        await spawnAndKill(['key', 'rotate', '--confirm-recipients', '0'], delayMs, {
          cwd: dir,
          env: baseEnv(home),
        });

        // The keyring must always be readable and structurally sound — a
        // kill mid-rewrite must never produce a file `readKeyringFile` can't
        // parse, thanks to the same temp+rename pattern proven for init and
        // unlock above.
        const file = await readKeyringFile(keyringPath);
        expect(file.generations.length).toBeGreaterThanOrEqual(1);
        expect(file.generations.some((g) => g.generation === file.current)).toBe(true);
        for (const gen of file.generations) {
          expect(gen.wrapped.length).toBeGreaterThan(0);
        }

        // Recoverable regardless of where the kill landed — a rotation that
        // completed invalidates the session (F13's own finding), one that
        // didn't leaves it alone either way, so unlock (re-)establishes it.
        expect(await runToCompletion(['unlock'], { cwd: dir, env: baseEnv(home) })).toBe(0);
      }
    },
    60_000,
  );
});
