#!/usr/bin/env node
// The real executable: wires process.argv/env/stdin/stdout to runCli().
// Deliberately thin — every decision lives in cli.ts, which is unit-tested
// without touching a real process. See specs/securegit/10-cli-contract.md.

import { homedir } from 'node:os';
import { runCli } from '../cli.js';

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

async function main(): Promise<void> {
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
