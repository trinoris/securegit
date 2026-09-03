// The verifier (specs/chaotests/01-sandbox.md "Orchestration"). Runs once,
// after the bounded sandbox run ends. Only has access to a fresh clone of
// `remote` and the shared JSONL report — deliberately no access to any
// actor's private HOME, so it can't accidentally "verify" anything using
// key material a real auditor with only repository access wouldn't have
// either.
//
// Three hard invariants — whatever chaos happened, all three must hold, no
// exceptions, no "expected failure" excuse accepted for any of them:
//   1. plaintext must never have reached the remote (01-threat-model.md)
//   2. the repository itself must be structurally intact (`git fsck`) —
//      "codebase integrity", not just content confidentiality
//   3. zero data loss — every commit this run itself confirmed as pushed
//      is still reachable, and every protected blob in history still
//      decrypts to its original, correctly-shaped content. This one the
//      verifier can't check directly (it has no key, by design — see
//      below); it trusts the operator's own finalIntegritySelfCheck()
//      report instead, because the operator is the one role in this
//      sandbox chaos never targets, so its keyring is the one guaranteed
//      to hold every generation, uncorrupted.
// Everything else observed during the run is summarized rather than
// force-fit into pass/fail: whether a given securegit failure was an
// expected fail-closed response to chaos or a genuine bug needs the kind
// of judgement this script doesn't try to fully automate
// (specs/chaotests/01-sandbox.md's own Open Questions say so).

import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { git, runBinary, sleep } from '../lib/proc.mjs';
import { say } from '../lib/log.mjs';
import { waitFor } from '../lib/wait-for.mjs';
import { looksLikeEnvelope } from '/app/dist/envelope.js';

const REMOTE_URL = process.env.REMOTE_URL ?? 'git://remote/repo.git';
const WORK_DIR = process.env.WORK_DIR ?? '/verify-clone';
const BRANCH = process.env.BRANCH ?? 'main';
const REPORT_PATH = process.env.REPORT_PATH ?? '/report/report.jsonl';
const RESULT_PATH = process.env.VERIFIER_RESULT_PATH ?? '/report/verifier-result.json';
// Give the actors/chaos agents a head start and a settle window before
// auditing — the verifier's own compose `depends_on` ordering only
// guarantees `remote` is up, not that anyone has pushed yet.
const STARTUP_GRACE_SECONDS = Number(process.env.VERIFIER_STARTUP_GRACE_SECONDS ?? 30);
const RUN_SECONDS = Number(process.env.CHAOS_DURATION_SECONDS ?? 300);
// finalIntegritySelfCheck() (chaos/actors/driver.mjs) decrypts every
// protected blob in history before the operator finishes — its own real
// cost on top of the run duration, scaling with how much history
// accumulated. 60s covers a default-length run; scale up for a much
// longer CHAOS_DURATION_SECONDS.
const SETTLE_SECONDS = Number(process.env.VERIFIER_SETTLE_SECONDS ?? 60);

async function cloneRemote() {
  await mkdir(WORK_DIR, { recursive: true });
  await waitFor(async () => (await git(['clone', REMOTE_URL, WORK_DIR])).code === 0, {
    description: `git clone ${REMOTE_URL}`,
    intervalMs: 5000,
    timeoutMs: 180_000,
  });
}

/** Every path under `dir` in `commit`. */
async function pathsUnder(commit, dir) {
  const res = await git(['ls-tree', '-r', '--name-only', commit, '--', dir], { cwd: WORK_DIR });
  if (res.code !== 0) return [];
  return res.stdout.trim().split('\n').filter(Boolean);
}

/**
 * The hard invariant: every commit that ever existed on `branch`, every
 * file under `secrets/` in that commit, must be envelope-shaped — never a
 * byte of plaintext, regardless of what chaos-4/chaos-5/chaos-6 did along
 * the way. Mirrors 01-threat-model.md's "pushed pack contains no plaintext
 * byte from any protected file", just walked across the sandbox's whole
 * history rather than one commit.
 */
async function checkNoPlaintextEverCommitted() {
  const revListRes = await git(['rev-list', '--all'], { cwd: WORK_DIR });
  const commits = revListRes.stdout.trim().split('\n').filter(Boolean);
  const violations = [];
  let checked = 0;
  for (const commit of commits) {
    for (const path of await pathsUnder(commit, 'secrets')) {
      const showRes = await runBinary('git', ['show', `${commit}:${path}`], { cwd: WORK_DIR });
      if (showRes.code !== 0) continue;
      checked += 1;
      if (!looksLikeEnvelope(showRes.stdout)) {
        violations.push({ commit, path, previewHex: showRes.stdout.subarray(0, 32).toString('hex') });
      }
    }
  }
  return { checked, violations };
}

/**
 * Codebase integrity: the repository's object graph itself must be
 * structurally sound — no corrupt, missing, or unreachable-when-it-
 * shouldn't-be objects — regardless of anything chaos-4/5/6 did. Needs no
 * key material, unlike the data-loss check below; this is Git's own
 * consistency, not securegit's.
 */
async function checkRepositoryIntegrity() {
  const res = await git(['fsck', '--full', '--no-dangling'], { cwd: WORK_DIR });
  return { ok: res.code === 0, code: res.code, stdout: res.stdout.trim(), stderr: res.stderr.trim() };
}

/**
 * Zero data loss (the hard invariant this verifier can't check itself —
 * see the file-level comment). Looks for the operator's own
 * `finalIntegritySelfCheck()` report event and treats its absence as a
 * failure in its own right: if the operator never got far enough to run
 * it, or the event never made it into the report, there's no basis to
 * claim zero data loss held, so this doesn't default to "assume fine".
 */
function checkZeroDataLoss(events) {
  const selfCheck = events.find((e) => e.role === 'operator' && e.message === 'final integrity self-check');
  if (!selfCheck) {
    return { ran: false, held: false, reason: 'operator never recorded a final integrity self-check' };
  }
  const held = (selfCheck.missingCommits?.length ?? 0) === 0 && (selfCheck.decryptFailures?.length ?? 0) === 0;
  return {
    ran: true,
    held,
    confirmedPushedCommits: selfCheck.confirmedPushedCommits,
    blobsChecked: selfCheck.blobsChecked,
    missingCommits: selfCheck.missingCommits ?? [],
    decryptFailures: selfCheck.decryptFailures ?? [],
  };
}

async function checkAttributeState() {
  const res = await git(['show', `${BRANCH}:.gitattributes`], { cwd: WORK_DIR });
  if (res.code !== 0) return { present: false };
  return { present: true, containsFilter: res.stdout.includes('filter=securegit') };
}

async function checkHostileRecipients() {
  const paths = await pathsUnder(BRANCH, '.securegit/recipients');
  return { count: paths.length, paths };
}

async function checkRelocatedFiles() {
  const paths = await pathsUnder(BRANCH, 'secrets');
  return paths.filter((p) => p.includes('relocated-'));
}

async function readReport() {
  let raw;
  try {
    raw = await readFile(REPORT_PATH, 'utf8');
  } catch {
    return [];
  }
  const events = [];
  for (const line of raw.split('\n')) {
    if (!line.trim()) continue;
    try {
      events.push(JSON.parse(line));
    } catch {
      // A line torn by a concurrent append (unlikely — appendFile() is
      // used throughout, not a partial write pattern) is skipped rather
      // than crashing the whole audit over one line.
    }
  }
  return events;
}

function summarizeReport(events) {
  const byRole = {};
  for (const e of events) {
    byRole[e.role] ??= { actions: 0, observations: 0, errors: 0, roundsCompleted: 0 };
    if (e.kind === 'action') byRole[e.role].actions += 1;
    if (e.kind === 'observation') byRole[e.role].observations += 1;
    if (e.kind === 'error') byRole[e.role].errors += 1;
    if (e.message === 'run complete' || e.message?.startsWith?.('run complete')) {
      byRole[e.role].roundsCompleted = e.rounds ?? 0;
    }
  }
  const errors = events.filter((e) => e.kind === 'error');
  const accessVerifyEvents = events.filter((e) => e.message?.includes?.('verify --access'));
  return { byRole, errorCount: errors.length, errors, accessVerifyEventCount: accessVerifyEvents.length };
}

async function main() {
  say(`waiting ${STARTUP_GRACE_SECONDS}s + run duration (${RUN_SECONDS}s) + settle (${SETTLE_SECONDS}s) before auditing`);
  await sleep(STARTUP_GRACE_SECONDS * 1000);
  await sleep(RUN_SECONDS * 1000);
  await sleep(SETTLE_SECONDS * 1000);

  say('auditing: cloning remote fresh');
  await cloneRemote();

  say('checking: no plaintext ever committed under secrets/, across all of history');
  const plaintext = await checkNoPlaintextEverCommitted();

  say('checking: repository object-graph integrity (git fsck)');
  const repoIntegrity = await checkRepositoryIntegrity();

  say('checking: final .gitattributes state (was chaos-5\'s T1 downgrade caught/reverted, or does it stand?)');
  const attributes = await checkAttributeState();

  say('checking: hostile recipient files present (chaos-5\'s T5)');
  const hostileRecipients = await checkHostileRecipients();

  say('checking: relocated files present (chaos-5\'s T3)');
  const relocated = await checkRelocatedFiles();

  say('reading the shared run report');
  const events = await readReport();
  const summary = summarizeReport(events);

  say('checking: zero data loss (operator\'s final integrity self-check)');
  const dataLoss = checkZeroDataLoss(events);

  const noPlaintextLeaked = plaintext.violations.length === 0;
  const repositoryIntact = repoIntegrity.ok;
  const zeroDataLoss = dataLoss.held;
  const hardInvariantsHeld = noPlaintextLeaked && repositoryIntact && zeroDataLoss;
  const anyoneRanAtAll = Object.values(summary.byRole).some((r) => r.roundsCompleted > 0 || r.actions > 0);

  const result = {
    ts: new Date().toISOString(),
    hardInvariantsHeld,
    invariants: { noPlaintextLeaked, repositoryIntact, zeroDataLoss },
    plaintextCheck: plaintext,
    repositoryIntegrityCheck: repoIntegrity,
    dataLossCheck: dataLoss,
    attributesFinalState: attributes,
    hostileRecipients,
    relocatedFiles: relocated,
    reportSummary: summary,
    anyoneRanAtAll,
  };

  await mkdir(join(RESULT_PATH, '..'), { recursive: true }).catch(() => {});
  await writeFile(RESULT_PATH, `${JSON.stringify(result, null, 2)}\n`);

  say('--- SUMMARY ---');
  say(`[invariant 1/3] no plaintext leaked: ${noPlaintextLeaked ? 'HELD' : 'VIOLATED'} (${plaintext.checked} blobs inspected, ${plaintext.violations.length} violations)`);
  say(`[invariant 2/3] repository intact (git fsck): ${repositoryIntact ? 'HELD' : 'VIOLATED'}`);
  say(
    `[invariant 3/3] zero data loss: ${dataLoss.ran ? (zeroDataLoss ? 'HELD' : 'VIOLATED') : 'COULD NOT CHECK'} ` +
      (dataLoss.ran
        ? `(${dataLoss.confirmedPushedCommits} confirmed-pushed commits, ${dataLoss.blobsChecked} blobs decrypted, ` +
          `${dataLoss.missingCommits.length} missing, ${dataLoss.decryptFailures.length} decrypt failures)`
        : `(${dataLoss.reason})`),
  );
  say(`.gitattributes still protects the pattern: ${attributes.present ? attributes.containsFilter : 'file absent'}`);
  say(`hostile recipient files on remote: ${hostileRecipients.count}`);
  say(`relocated files on remote: ${relocated.length}`);
  say(`script-level errors across all roles: ${summary.errorCount}`);
  for (const [role, s] of Object.entries(summary.byRole)) {
    say(`  ${role}: ${s.actions} actions, ${s.observations} observations, ${s.errors} errors, ${s.roundsCompleted} rounds`);
  }
  say(`full result written to ${RESULT_PATH}`);

  if (!noPlaintextLeaked) {
    say('FAIL: plaintext reached the remote at some point in history — see plaintextCheck.violations');
    process.exit(1);
  }
  if (!repositoryIntact) {
    say('FAIL: git fsck found a structural problem with the repository — see repositoryIntegrityCheck');
    process.exit(1);
  }
  if (!zeroDataLoss) {
    say('FAIL: data loss detected (or could not be ruled out) — see dataLossCheck');
    process.exit(1);
  }
  if (!anyoneRanAtAll) {
    say('FAIL: no actor completed any round or recorded any action — the run likely never got going (bootstrap failure?)');
    process.exit(1);
  }
  say('PASS: all three hard invariants held — no plaintext leaked, repository intact, zero data loss. Review reportSummary/errors for anything worth a closer look.');
}

main().catch((e) => {
  say(`verifier fatal: ${(e && e.message) || String(e)}`);
  process.exit(1);
});
