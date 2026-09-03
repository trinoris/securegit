// Process-spawning helpers shared by every driver/agent script. Deliberately
// plain `child_process` — no extra npm dependencies, matching the package's
// own zero-runtime-dependency ethos (16-adversarial-integrity.md T11), even
// though this sandbox never ships.

import { spawn } from 'node:child_process';

/**
 * Runs `cmd args...` to completion, stdin ignored (matters for `securegit`
 * itself — its non-TTY stdin read would otherwise hang forever, same
 * lesson as src/chaos.test.ts's `runToCompletion`). Never rejects on a
 * nonzero exit — callers decide whether a given exit code is expected.
 */
export function run(cmd, args, opts = {}) {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, {
      cwd: opts.cwd,
      env: opts.env ?? process.env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => (stdout += d.toString('utf8')));
    child.stderr.on('data', (d) => (stderr += d.toString('utf8')));
    child.on('error', (err) => resolve({ code: null, signal: null, stdout, stderr: String(err) }));
    child.on('exit', (code, signal) => resolve({ code, signal, stdout, stderr }));
  });
}

/**
 * Like `run`, but collects stdout as a `Buffer` rather than decoding it as
 * UTF-8 — required for anything that might be genuine binary content (a
 * committed ciphertext envelope, in particular: `child.stdout.on('data', d
 * => s += d.toString('utf8'))` is lossy for non-UTF-8 bytes, and an
 * envelope's ciphertext is exactly that, so decoding-then-re-encoding it
 * would corrupt it into something `looksLikeEnvelope()` could wrongly
 * reject — a false "plaintext leaked" finding from the checker itself, not
 * from anything that actually happened).
 */
export function runBinary(cmd, args, opts = {}) {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, {
      cwd: opts.cwd,
      env: opts.env ?? process.env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const stdoutChunks = [];
    let stderr = '';
    child.stdout.on('data', (d) => stdoutChunks.push(d));
    child.stderr.on('data', (d) => (stderr += d.toString('utf8')));
    child.on('error', (err) => resolve({ code: null, signal: null, stdout: Buffer.alloc(0), stderr: String(err) }));
    child.on('exit', (code, signal) => resolve({ code, signal, stdout: Buffer.concat(stdoutChunks), stderr }));
  });
}

/** Like `run`, but writes `input` to the child's stdin then closes it. */
export function runWithStdin(cmd, args, input, opts = {}) {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, {
      cwd: opts.cwd,
      env: opts.env ?? process.env,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => (stdout += d.toString('utf8')));
    child.stderr.on('data', (d) => (stderr += d.toString('utf8')));
    child.on('error', (err) => resolve({ code: null, signal: null, stdout, stderr: String(err) }));
    child.on('exit', (code, signal) => resolve({ code, signal, stdout, stderr }));
    child.stdin.write(input);
    child.stdin.end();
  });
}

/**
 * Like `runWithStdin`, but both directions are binary-safe: `input` may be
 * a `Buffer` (a ciphertext envelope, in particular), and stdout is
 * returned as a `Buffer` rather than decoded — the same lossy-UTF-8-
 * decoding trap `runBinary()`'s doc comment describes, just on the input
 * side too. Used for feeding a real committed envelope through `securegit
 * smudge` to prove it still decrypts (see chaos/actors/driver.mjs's
 * `finalIntegritySelfCheck()`), where garbling the ciphertext on the way
 * in would produce a false decrypt failure that never actually happened.
 */
export function runBinaryIO(cmd, args, input, opts = {}) {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, {
      cwd: opts.cwd,
      env: opts.env ?? process.env,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    const stdoutChunks = [];
    let stderr = '';
    child.stdout.on('data', (d) => stdoutChunks.push(d));
    child.stderr.on('data', (d) => (stderr += d.toString('utf8')));
    child.on('error', (err) => resolve({ code: null, signal: null, stdout: Buffer.alloc(0), stderr: String(err) }));
    child.on('exit', (code, signal) => resolve({ code, signal, stdout: Buffer.concat(stdoutChunks), stderr }));
    child.stdin.write(input);
    child.stdin.end();
  });
}

/** `securegit <args>` via the wrapper script baked into the image. */
export function securegit(args, opts = {}) {
  return run('securegit', args, opts);
}

/** `securegit <args>`, feeding `input` (a Buffer) to stdin, binary-safe both ways. */
export function securegitBinaryIO(args, input, opts = {}) {
  return runBinaryIO('securegit', args, input, opts);
}

/** `git <args>`. */
export function git(args, opts = {}) {
  return run('git', args, opts);
}

export function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** A random integer in [min, max], inclusive. */
export function jitter(min, max) {
  return Math.floor(min + Math.random() * (max - min + 1));
}

/** True until `deadline` (a Date.now()-style epoch ms) has passed. */
export function before(deadline) {
  return Date.now() < deadline;
}
