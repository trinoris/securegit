// chaos-6 "infra" (specs/chaotests/01-sandbox.md). Paired with one actor via
// docker-compose.yml's `pid: "service:<actor>"` and `network_mode:
// "service:<actor>"` (shared PID and network namespace) plus a shared
// volume at the same HOME path — so this container can affect only that
// one actor's own process, disk, permissions and network link, nothing
// else. Impersonal fault injection (C1/C2/C3/C6 from 00-test-plan.md),
// sustained and randomized rather than one deterministic shot each.

import { readdir, readFile, writeFile, unlink, chmod, stat } from 'node:fs/promises';
import { lookup } from 'node:dns/promises';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { run, sleep, jitter } from '../lib/proc.mjs';
import { record, say } from '../lib/log.mjs';

const HOME = process.env.HOME;
const TARGET_ROLE = process.env.SANDBOX_TARGET ?? 'unknown';
const DURATION_SECONDS = Number(process.env.CHAOS_DURATION_SECONDS ?? 300);
const DISK_FILL_MB = Number(process.env.DISK_FILL_MB ?? 64);
const REMOTE_HOST = process.env.REMOTE_HOST ?? 'remote';

async function findPids(substr) {
  const pids = [];
  let entries;
  try {
    entries = await readdir('/proc');
  } catch {
    return pids;
  }
  for (const e of entries) {
    if (!/^\d+$/.test(e)) continue;
    try {
      const cmdline = (await readFile(`/proc/${e}/cmdline`, 'utf8')).replace(/\0/g, ' ');
      if (cmdline.includes(substr)) pids.push(Number(e));
    } catch {
      // Process exited between readdir and read — fine, skip it.
    }
  }
  return pids;
}

/** C1: kill a live `securegit` (or nested `clean`/`smudge`/`filter-process`) subprocess mid-operation, if one happens to be running right now. */
async function killMidOperation() {
  const pids = await findPids('dist/bin/securegit.js');
  if (pids.length === 0) return { attempted: false, reason: 'no securegit process running right now' };
  const killed = [];
  for (const pid of pids) {
    try {
      process.kill(pid, 'SIGKILL');
      killed.push(pid);
    } catch {
      // Already exited on its own between findPids() and here — not a bug.
    }
  }
  return { attempted: killed.length > 0, technique: 'C1', pids: killed };
}

/** C2: transient disk pressure — write a large file into the shared volume, hold it briefly, then remove it. */
async function fillDisk() {
  const path = join(HOME, `.chaos-fill-${process.pid}.bin`);
  try {
    await writeFile(path, randomBytes(DISK_FILL_MB * 1024 * 1024));
  } catch (e) {
    // A real ENOSPC here (this host's volume genuinely has a size limit)
    // is itself an interesting, worth-recording outcome, not a script bug.
    return { attempted: true, technique: 'C2', outcome: 'write failed', message: (e && e.message) || String(e) };
  }
  await sleep(jitter(1000, 4000));
  await unlink(path).catch(() => {});
  return { attempted: true, technique: 'C2', megabytes: DISK_FILL_MB };
}

/** C3: revoke permissions on the actor's securegit state directory, briefly. */
async function revokePermissions() {
  const target = join(HOME, '.securegit');
  let original;
  try {
    original = (await stat(target)).mode & 0o777;
  } catch {
    return { attempted: false, reason: `${target} does not exist yet` };
  }
  await chmod(target, 0o000);
  await sleep(jitter(1500, 5000));
  await chmod(target, original).catch(() => {});
  return { attempted: true, technique: 'C3', path: target, restoredMode: original.toString(8) };
}

/** C6: drop the network link to `remote` mid-transfer, briefly. Needs NET_ADMIN (granted only to this service in docker-compose.yml). */
async function dropNetworkLink() {
  let address;
  try {
    address = (await lookup(REMOTE_HOST)).address;
  } catch (e) {
    return { attempted: false, reason: `could not resolve ${REMOTE_HOST}: ${(e && e.message) || e}` };
  }
  const addRes = await run('iptables', ['-I', 'OUTPUT', '-d', address, '-j', 'DROP']);
  if (addRes.code !== 0) {
    return { attempted: false, reason: `iptables insert failed: ${addRes.stderr.trim()}` };
  }
  await sleep(jitter(1000, 4000));
  await run('iptables', ['-D', 'OUTPUT', '-d', address, '-j', 'DROP']);
  return { attempted: true, technique: 'C6', address, droppedForMs: 'see duration above' };
}

const ACTIONS = [killMidOperation, fillDisk, revokePermissions, dropNetworkLink];

async function main() {
  say(`infra targeting ${TARGET_ROLE}, HOME=${HOME}`);
  const deadline = Date.now() + DURATION_SECONDS * 1000;
  let n = 0;
  while (Date.now() < deadline) {
    await sleep(jitter(5000, 15000));
    n += 1;
    const action = ACTIONS[Math.floor(Math.random() * ACTIONS.length)];
    let result;
    try {
      result = await action();
    } catch (e) {
      result = { attempted: false, reason: (e && e.message) || String(e) };
    }
    await record('action', `infra round ${n}: ${action.name} — ${result.attempted ? 'applied' : 'skipped'}`, result);
  }
  await record('action', 'infra run complete', { rounds: n });
}

main().catch(async (e) => {
  await record('error', 'infra fatal', { message: (e && e.message) || String(e) });
  process.exit(1);
});
