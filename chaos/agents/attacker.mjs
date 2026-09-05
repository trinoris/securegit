// chaos-5 "attacker" (specs/chaotests/01-sandbox.md). Its own container, its
// own clone, ordinary push access to `remote` — nothing more. Automates
// the 16-adversarial-integrity.md catalogue: T1 (attribute downgrade), T3
// (blob relocation), T4 (blob rollback), T5 (hostile recipient). Every
// attack is built via chaos/lib/git-plumbing.mjs, entirely at the object
// level — this container has no securegit key, so anything routed through
// a working tree/`clean` filter would just double-wrap ciphertext it
// can't meaningfully produce; a real attacker with push access wouldn't
// do that either.

import { mkdir } from 'node:fs/promises';
import { git, sleep, jitter } from '../lib/proc.mjs';
import { record, say } from '../lib/log.mjs';
import { waitFor } from '../lib/wait-for.mjs';
import { buildAndPushCommit, readBlobAt, listPathsUnder, historyOf } from '../lib/git-plumbing.mjs';

const REMOTE_URL = process.env.REMOTE_URL ?? 'git://remote/repo.git';
const WORK_DIR = process.env.WORK_DIR ?? '/work';
const BRANCH = process.env.BRANCH ?? 'main';
const DURATION_SECONDS = Number(process.env.CHAOS_DURATION_SECONDS ?? 300);
// direct-master (W1) | working-branch (W2) | pr-gated (W3) —
// specs/chaotests/03-orchestrator.md. Under the latter two, `master` never
// accepts a direct update (remote/entrypoint.mjs's pre-receive hook) — a
// real hostile collaborator would have to route through a branch the
// orchestrator reviews too, same as any other pusher, so every attack
// below targets TARGET_REF, never BRANCH directly, except the one attack
// added specifically to confirm the direct route is actually refused.
const WORKFLOW = process.env.SANDBOX_WORKFLOW ?? 'direct-master';
const TARGET_REF = WORKFLOW === 'direct-master' ? BRANCH : WORKFLOW === 'working-branch' ? 'working' : `feature/${process.env.SANDBOX_ROLE ?? 'chaos-5-attacker'}`;

// Deliberately no shared-volume mount with any actor (see
// specs/chaotests/01-sandbox.md's Scope guardrails: chaos-5 only ever acts
// through ordinary `git push`) — even the collaborator-a's
// bootstrap-ready marker lives on a volume that also holds the shared
// keyring, which this container must never have filesystem access to.
// Waits on the remote itself instead: an empty bare repo has no `main`
// ref yet, so a successful, non-empty `ls-remote` is itself the signal
// that collaborator-a's bootstrap push landed.
async function remoteHasBranch() {
  const res = await git(['ls-remote', REMOTE_URL, `refs/heads/${BRANCH}`]);
  return res.code === 0 && res.stdout.trim().length > 0;
}

async function attackT1_attributeDowngrade() {
  const attrs = await readBlobAt(WORK_DIR, TARGET_REF, '.gitattributes');
  if (!attrs) return { attempted: false, reason: 'no .gitattributes on remote yet' };
  const lines = attrs.split('\n');
  const idx = lines.findIndex((l) => l.includes('filter=securegit'));
  if (idx === -1) return { attempted: false, reason: 'no protected pattern found to downgrade' };
  const removed = lines[idx];
  const next = [...lines.slice(0, idx), ...lines.slice(idx + 1)].join('\n');
  const sha = await buildAndPushCommit(WORK_DIR, TARGET_REF, 'chore: tidy up gitattributes', [
    { path: '.gitattributes', content: next },
  ]);
  return { attempted: true, technique: 'T1', removedLine: removed, commit: sha };
}

async function attackT3_relocateBlob() {
  const candidates = await listPathsUnder(WORK_DIR, TARGET_REF, 'secrets');
  if (candidates.length === 0) return { attempted: false, reason: 'no files under secrets/ yet' };
  const source = candidates[Math.floor(Math.random() * candidates.length)];
  const dest = `secrets/relocated-${Date.now()}.json`;
  const sha = await buildAndPushCommit(WORK_DIR, TARGET_REF, 'chore: reorganise secrets', [
    { path: dest, sourcePath: source },
  ]);
  return { attempted: true, technique: 'T3', source, dest, commit: sha };
}

async function attackT4_rollbackBlob() {
  const candidates = await listPathsUnder(WORK_DIR, TARGET_REF, 'secrets');
  if (candidates.length === 0) return { attempted: false, reason: 'no files under secrets/ yet' };
  const path = candidates[Math.floor(Math.random() * candidates.length)];
  const shas = await historyOf(WORK_DIR, TARGET_REF, path);
  if (shas.length < 2) return { attempted: false, reason: `not enough history on ${path} yet` };
  // shas[0] is the current (newest) commit — anything else is a genuine
  // rollback target.
  const olderCommit = shas[jitter(1, shas.length - 1)];
  const sha = await buildAndPushCommit(WORK_DIR, TARGET_REF, 'chore: restore previous value', [
    { path, sourcePath: path, sourceRef: olderCommit },
  ]);
  return { attempted: true, technique: 'T4', path, olderCommit, commit: sha };
}

async function attackT5_hostileRecipient() {
  const fingerprint = `attacker-${Date.now().toString(16)}`;
  const fakeRecipient = JSON.stringify(
    {
      version: 1,
      fingerprint,
      label: 'legit-looking-refactor',
      publicKey: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
      addedBy: 'chaos-5',
      keys: {},
    },
    null,
    2,
  );
  const sha = await buildAndPushCommit(WORK_DIR, TARGET_REF, 'chore: onboard new contributor', [
    { path: `.securegit/recipients/${fingerprint}.json`, content: `${fakeRecipient}\n` },
  ]);
  return { attempted: true, technique: 'T5', fingerprint, commit: sha };
}

/**
 * Confirms remote/entrypoint.mjs's pre-receive hook actually gates the
 * network path itself, not just that every other attack above *chooses*
 * to go through `TARGET_REF` — this one deliberately targets `BRANCH`
 * directly instead, the exact same shape a W1 attack would use, to prove
 * the difference under working-branch/pr-gated is enforced, not merely
 * assumed. `rejected: true` is the expected, good outcome here (see
 * specs/chaotests/03-orchestrator.md's "Predicted plaintext-leak shape"
 * table) — `rejected: false` would mean the gate itself failed.
 */
async function attackDirectMasterBypass() {
  const attrs = await readBlobAt(WORK_DIR, BRANCH, '.gitattributes');
  if (!attrs) return { attempted: false, reason: 'no .gitattributes on master yet' };
  const lines = attrs.split('\n');
  const idx = lines.findIndex((l) => l.includes('filter=securegit'));
  const next = idx === -1 ? attrs : [...lines.slice(0, idx), ...lines.slice(idx + 1)].join('\n');
  try {
    const sha = await buildAndPushCommit(WORK_DIR, BRANCH, 'chore: tidy up gitattributes (direct)', [
      { path: '.gitattributes', content: next },
    ]);
    return { attempted: true, technique: 'direct-master-bypass', rejected: false, commit: sha };
  } catch (e) {
    return { attempted: true, technique: 'direct-master-bypass', rejected: true, reason: (e && e.message) || String(e) };
  }
}

const ATTACKS = [attackT1_attributeDowngrade, attackT3_relocateBlob, attackT4_rollbackBlob, attackT5_hostileRecipient];
// Only meaningful once there's a `TARGET_REF` distinct from `BRANCH` to
// compare against — under direct-master a "direct" push is just the
// ordinary attack, already covered above.
if (TARGET_REF !== BRANCH) ATTACKS.push(attackDirectMasterBypass);

async function main() {
  await waitFor(remoteHasBranch, { description: `origin/${BRANCH} to exist (collaborator-a's bootstrap push)` });

  await mkdir(WORK_DIR, { recursive: true });
  await waitFor(async () => (await git(['clone', REMOTE_URL, WORK_DIR])).code === 0, {
    description: `git clone ${REMOTE_URL}`,
    intervalMs: 3000,
    timeoutMs: 180_000,
  });
  await git(['config', 'user.name', 'chaos-5'], { cwd: WORK_DIR });
  await git(['config', 'user.email', 'chaos-5@sandbox'], { cwd: WORK_DIR });

  if (TARGET_REF !== BRANCH) {
    // A real hostile collaborator under working-branch/pr-gated has
    // ordinary push access same as anyone — creating its own branch (or
    // working-branch's shared one, if a legitimate collaborator got
    // there first) is itself a `ref create` push, allowed unconditionally
    // by the pre-receive hook regardless of mode; see driver.mjs's
    // `ensureTargetRef()` for the identical logic on the legitimate side.
    const remoteHasTarget = await git(['ls-remote', '--exit-code', 'origin', `refs/heads/${TARGET_REF}`], { cwd: WORK_DIR });
    if (remoteHasTarget.code === 0) {
      await git(['fetch', 'origin', TARGET_REF], { cwd: WORK_DIR });
      await git(['checkout', '-B', TARGET_REF, `origin/${TARGET_REF}`], { cwd: WORK_DIR });
    } else {
      await git(['checkout', '-B', TARGET_REF], { cwd: WORK_DIR });
      await git(['push', 'origin', TARGET_REF], { cwd: WORK_DIR });
    }
  }
  say('attacker cloned and ready');

  const deadline = Date.now() + DURATION_SECONDS * 1000;
  let n = 0;
  while (Date.now() < deadline) {
    await sleep(jitter(6000, 15000));
    n += 1;
    const attack = ATTACKS[Math.floor(Math.random() * ATTACKS.length)];
    let result;
    try {
      result = await attack();
    } catch (e) {
      result = { attempted: false, reason: (e && e.message) || String(e) };
    }
    // `direct-master-bypass`'s "attempted but rejected" is a real, distinct
    // outcome from either "pushed" (it landed — the gate failed) or
    // "skipped" (never even tried this round) — worth its own label so
    // the report/viewer don't read a correctly-refused push as a landed
    // attack just because `attempted` is true.
    const outcome = result.rejected === true ? 'rejected' : result.attempted ? 'pushed' : 'skipped';
    await record('action', `attack round ${n}: ${attack.name} — ${outcome}`, result);
  }
  await record('action', 'attacker run complete', { rounds: n });
}

main().catch(async (e) => {
  await record('error', 'attacker fatal', { message: (e && e.message) || String(e) });
  process.exit(1);
});
