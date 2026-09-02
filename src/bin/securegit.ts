#!/usr/bin/env node
// The real executable: wires process.argv/env/stdin/stdout to runCli().
// Deliberately thin — every decision lives in cli.ts, which is unit-tested
// without touching a real process. See specs/securegit/10-cli-contract.md.

import { homedir } from 'node:os';
import { runCli, runFilterProcess } from '../cli.js';
import { installStdoutGuard } from '../process.js';

async function readStdin(): Promise<Buffer> {
  // Interactive commands (init/unlock) fall back to an empty passphrase here
  // when SECUREGIT_PASSPHRASE isn't set and stdin is a TTY — real prompting
  // (masked input via readline) is a follow-up, not yet wired.
  if (process.stdin.isTTY) return Buffer.alloc(0);
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
}

/**
 * `filter-process` is a long-running stream, not a single request/response —
 * it can't go through `readStdin()`/`runCli()`'s whole-buffer, one-shot
 * contract, so it's intercepted here before either runs. The stdout guard
 * (11-filter-process.md, implementation note 1) is installed for the whole
 * lifetime of this call: a stray `console.log` anywhere underneath —
 * including in a dependency — would otherwise corrupt whichever blob is
 * mid-flight on the real protocol stream.
 */
async function runFilterProcessMain(): Promise<void> {
  const guard = installStdoutGuard(process.stdout);
  try {
    const code = await runFilterProcess({
      cwd: process.cwd(),
      env: process.env,
      home: homedir(),
      onData: (handler) => process.stdin.on('data', handler),
      onEnd: (handler) => process.stdin.on('end', handler),
      write: guard.write,
      stderr: (message) => {
        process.stderr.write(`${message}\n`);
      },
    });
    process.exitCode = code;
  } finally {
    guard.restore();
  }
}

async function main(): Promise<void> {
  if (process.argv[2] === 'filter-process') {
    return runFilterProcessMain();
  }

  const stdin = await readStdin();
  const code = await runCli({
    argv: process.argv.slice(2),
    cwd: process.cwd(),
    env: process.env,
    stdin,
    home: homedir(),
    stdout: (chunk) => {
      process.stdout.write(chunk);
    },
    stderr: (message) => {
      process.stderr.write(`${message}\n`);
    },
  });
  process.exitCode = code;
}

main().catch((e: unknown) => {
  process.stderr.write(`securegit: fatal: ${(e as Error).message}\n`);
  process.exitCode = 4;
});
