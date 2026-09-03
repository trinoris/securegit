// chaos-4 "virus" (specs/chaotests/01-sandbox.md). Shares its target
// actor's HOME (mounted at the same path via a shared volume in
// docker-compose.yml, plus `pid`/no code-exec beyond file I/O — see the
// spec's Scope guardrails). Periodically corrupts one of that actor's own
// securegit state files, the way commodity ransomware or a crashing
// backup tool touches files indiscriminately: no attempt to understand
// the format, no attempt to target anything else on the machine.

import { readFile, writeFile, unlink, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { sleep, jitter } from '../lib/proc.mjs';
import { record, say } from '../lib/log.mjs';
import { discoverRepoId, resolveKeyringPath, sessionDir, identityPath } from '../lib/paths.mjs';

const HOME = process.env.HOME;
const TARGET_ROLE = process.env.SANDBOX_TARGET ?? 'collaborator-a';
const DURATION_SECONDS = Number(process.env.CHAOS_DURATION_SECONDS ?? 300);

async function candidateFiles() {
  const files = [];
  const repoId = await discoverRepoId(HOME);
  if (repoId) files.push(resolveKeyringPath(repoId, HOME));
  try {
    const dir = sessionDir(HOME);
    for (const name of await readdir(dir)) files.push(join(dir, name));
  } catch {
    // No session directory yet — this actor hasn't unlocked yet.
  }
  files.push(identityPath(HOME)); // usually absent in this sandbox (passphrase-sharing model, no identity flow) — corrupt() below skips it cleanly
  return files;
}

const ACTIONS = ['truncate', 'bitflip', 'delete', 'overwrite'];

async function corrupt(path) {
  let original;
  try {
    original = await readFile(path);
  } catch {
    return { path, attempted: false, reason: 'not present' };
  }
  const action = ACTIONS[Math.floor(Math.random() * ACTIONS.length)];
  try {
    if (action === 'truncate') {
      const cut = Math.floor(Math.random() * original.length);
      await writeFile(path, original.subarray(0, cut));
    } else if (action === 'bitflip') {
      if (original.length === 0) return { path, attempted: false, reason: 'empty file' };
      const idx = Math.floor(Math.random() * original.length);
      const mutated = Buffer.from(original);
      mutated[idx] ^= 0xff;
      await writeFile(path, mutated);
    } else if (action === 'delete') {
      await unlink(path);
    } else {
      await writeFile(path, randomBytes(original.length || 64));
    }
    return { path, attempted: true, action, originalBytes: original.length };
  } catch (e) {
    return { path, attempted: false, reason: (e && e.message) || String(e) };
  }
}

async function main() {
  say(`virus targeting ${TARGET_ROLE}'s HOME=${HOME}`);
  const deadline = Date.now() + DURATION_SECONDS * 1000;
  let n = 0;
  while (Date.now() < deadline) {
    await sleep(jitter(4000, 12000));
    n += 1;
    const candidates = await candidateFiles();
    if (candidates.length === 0) continue;
    const target = candidates[Math.floor(Math.random() * candidates.length)];
    const result = await corrupt(target);
    await record('action', `virus round ${n}: ${result.attempted ? result.action : 'skipped'} on ${target}`, result);
  }
  await record('action', 'virus run complete', { rounds: n });
}

main().catch(async (e) => {
  await record('error', 'virus fatal', { message: (e && e.message) || String(e) });
  process.exit(1);
});
