import { describe, it, expect, beforeAll } from 'vitest';
import { execFile as execFileCb, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, rm, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const execFile = promisify(execFileCb);
const REPO_ROOT = join(import.meta.dirname, '..');
const BIN = join(REPO_ROOT, 'dist', 'bin', 'securegit.js');

// Proves the real compiled artifact — actual process.argv/env/stdin/stdout,
// actual exit codes — not just the injected-IO cli.ts unit tests. Builds
// once so `npm run test:integration` needs no separate build step.
beforeAll(async () => {
  await execFile('npm', ['run', 'build'], { cwd: REPO_ROOT });
}, 60_000);

async function run(
  args: string[],
  opts: { cwd: string; home: string; input?: Buffer; passphrase?: string },
): Promise<{ code: number; stdout: Buffer; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn('node', [BIN, ...args], {
      cwd: opts.cwd,
      env: {
        PATH: process.env.PATH,
        HOME: opts.home,
        ...(opts.passphrase !== undefined ? { SECUREGIT_PASSPHRASE: opts.passphrase } : {}),
      },
    });
    const outChunks: Buffer[] = [];
    const errChunks: Buffer[] = [];
    child.stdout.on('data', (c: Buffer) => outChunks.push(c));
    child.stderr.on('data', (c: Buffer) => errChunks.push(c));
    child.on('error', reject);
    child.on('close', (code: number) => {
      resolve({ code, stdout: Buffer.concat(outChunks), stderr: Buffer.concat(errChunks).toString('utf8') });
    });
    child.stdin.end(opts.input ?? Buffer.alloc(0));
  });
}

let dir: string;
let home: string;

describe('the real securegit binary', () => {
  it('wires argv/env/stdin/stdout/exit-codes end to end', async () => {
    dir = await mkdtemp(join(tmpdir(), 'securegit-bin-repo-'));
    home = await mkdtemp(join(tmpdir(), 'securegit-bin-home-'));
    try {
      await mkdir(join(dir, '.git'));

      const init = await run(['init'], { cwd: dir, home, passphrase: 'correct horse battery staple' });
      expect(init.code).toBe(0);

      const unlock = await run(['unlock'], { cwd: dir, home, passphrase: 'correct horse battery staple' });
      expect(unlock.code).toBe(0);

      const plaintext = Buffer.from('a real subprocess round trip\n');
      const encrypted = await run(['encrypt', '-'], { cwd: dir, home, input: plaintext });
      expect(encrypted.code).toBe(0);
      expect(encrypted.stdout.equals(plaintext)).toBe(false);
      expect(encrypted.stdout.subarray(0, 1).readUInt8(0)).toBe(0); // envelope magic starts with NUL

      const decrypted = await run(['decrypt', '-'], { cwd: dir, home, input: encrypted.stdout });
      expect(decrypted.code).toBe(0);
      expect(decrypted.stdout.equals(plaintext)).toBe(true);

      // A wrong exit code / usage error, through the real process too.
      const bogus = await run(['bogus'], { cwd: dir, home });
      expect(bogus.code).toBe(4);
      expect(bogus.stderr.length).toBeGreaterThan(0);
    } finally {
      await rm(dir, { recursive: true, force: true });
      await rm(home, { recursive: true, force: true });
    }
  });

  it('clean is byte-identical across two separate OS processes given the same input', async () => {
    // The unit-test version of this (src/filter.test.ts, "is deterministic")
    // proves the function is pure; this proves it stays pure once split
    // across process boundaries — no PID, no env, no timestamp, no
    // filesystem state leaking into the derivation. See
    // specs/securegit/03-determinism.md.
    const d = await mkdtemp(join(tmpdir(), 'securegit-bin-clean-'));
    const h = await mkdtemp(join(tmpdir(), 'securegit-bin-clean-home-'));
    try {
      await mkdir(join(d, '.git'));
      await run(['init'], { cwd: d, home: h, passphrase: 'correct horse battery staple' });
      await run(['unlock'], { cwd: d, home: h, passphrase: 'correct horse battery staple' });

      const plaintext = Buffer.from('the same bytes, two processes\n');
      const first = await run(['clean', '--', 'config/production.json'], { cwd: d, home: h, input: plaintext });
      const second = await run(['clean', '--', 'config/production.json'], { cwd: d, home: h, input: plaintext });
      expect(first.code).toBe(0);
      expect(second.code).toBe(0);
      expect(first.stdout.equals(second.stdout)).toBe(true);
    } finally {
      await rm(d, { recursive: true, force: true });
      await rm(h, { recursive: true, force: true });
    }
  });
});
