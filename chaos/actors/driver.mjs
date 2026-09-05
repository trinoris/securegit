// Legitimate-actor driver, parameterized by SANDBOX_ROLE:
//   collaborator-a  bootstraps the repo, then edits+commits+pushes its own
//                   file on a loop, same as collaborator-b
//   collaborator-b  waits for collaborator-a's bootstrap, then the same loop
//   operator        never edits secrets/ files — runs unlock/status/verify/
//                   rotate, plus reconciling attribute protection and
//                   re-encrypting stale generations every round (T1
//                   recovery and post-rotate cleanup — see
//                   reconcileProtection())
// See specs/chaotests/01-sandbox.md.
//
// v1 scope: each collaborator edits only its own file (secrets/<role>.json)
// — real push races (non-fast-forward, retry-after-pull) are still fully in
// play, but content-level merge conflicts are deliberately out of scope for
// this first version, so the driver never needs conflict-resolution logic
// of its own. A shared, contended file is a natural follow-up.

import { mkdir, copyFile, writeFile, readFile, stat, rm } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { git, securegit, securegitBinaryIO, runBinary, sleep, jitter } from '../lib/proc.mjs';
import { say, record } from '../lib/log.mjs';
import { waitFor } from '../lib/wait-for.mjs';
import { resolveKeyringPath, readConfig } from '../lib/paths.mjs';

const ROLE = process.env.SANDBOX_ROLE;
const REMOTE_URL = process.env.REMOTE_URL ?? 'git://remote/repo.git';
const WORK_DIR = process.env.WORK_DIR ?? '/work';
const SHARED_DIR = process.env.SHARED_DIR ?? '/shared';
const SHARED_KEYRING = join(SHARED_DIR, 'keyring.json');
const SHARED_READY = join(SHARED_DIR, 'bootstrap-ready');
const BRANCH = process.env.BRANCH ?? 'main';
const DURATION_SECONDS = Number(process.env.CHAOS_DURATION_SECONDS ?? 300);
const HOME = process.env.HOME;
// What `bootstrapAsCollaboratorA` protects at seed time, and what the
// operator's `reconcileProtection` keeps re-asserting every round — see
// there for why one list serves both purposes.
const PROTECTED_PATTERNS = ['secrets/**'];
const GITATTRIBUTES_PATH = join(WORK_DIR, '.gitattributes');

if (!ROLE) {
  say('SANDBOX_ROLE not set — nothing to do');
  process.exit(1);
}

function gitEnv() {
  return { ...process.env, GIT_AUTHOR_NAME: ROLE, GIT_AUTHOR_EMAIL: `${ROLE}@sandbox`, GIT_COMMITTER_NAME: ROLE, GIT_COMMITTER_EMAIL: `${ROLE}@sandbox` };
}

async function exists(path) {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
}

async function cloneOrInit() {
  if (await exists(join(WORK_DIR, '.git'))) return;
  // `remote`'s `git daemon` may not be accepting connections yet this early
  // in `docker compose up` — retry the whole clone. `git clone` refuses a
  // non-empty target, so a failed attempt's debris (if any) is cleared
  // before each retry rather than assumed safe to build on.
  await waitFor(
    async () => {
      await rm(WORK_DIR, { recursive: true, force: true });
      return (await git(['clone', REMOTE_URL, WORK_DIR])).code === 0;
    },
    { description: `git clone ${REMOTE_URL}`, intervalMs: 3000, timeoutMs: 180_000 },
  );
}

async function bootstrapAsCollaboratorA() {
  await cloneOrInit();
  await git(['checkout', '-B', BRANCH], { cwd: WORK_DIR, env: gitEnv() });
  await git(['config', 'user.name', ROLE], { cwd: WORK_DIR });
  await git(['config', 'user.email', `${ROLE}@sandbox`], { cwd: WORK_DIR });

  const alreadyInit = await exists(join(WORK_DIR, '.securegit', 'config.json'));
  if (!alreadyInit) {
    await record('action', 'securegit init', await securegit(['init'], { cwd: WORK_DIR }));
    await record('action', `securegit protect ${PROTECTED_PATTERNS.join(', ')}`, await securegit(['protect', ...PROTECTED_PATTERNS], { cwd: WORK_DIR }));
    // Must run before the seed files are ever `git add`ed — `.gitattributes`
    // alone only tells git *which* paths to filter; without this, no
    // `filter.securegit.clean` command is registered in `.git/config` at
    // all, so `git add` silently commits them unfiltered (confirmed by a
    // real chaos-sandbox run: every blob came back plaintext until this
    // call was added — see specs/chaotests/01-sandbox.md's Status note).
    await record('action', 'securegit install', await securegit(['install'], { cwd: WORK_DIR }));
    await mkdir(join(WORK_DIR, 'secrets'), { recursive: true });
    for (const role of ['collaborator-a', 'collaborator-b']) {
      await writeFile(join(WORK_DIR, 'secrets', `${role}.json`), `${JSON.stringify({ role, counter: 0 }, null, 2)}\n`);
    }
    await git(['add', '-A'], { cwd: WORK_DIR, env: gitEnv() });
    const commit = await git(['commit', '-m', 'bootstrap: init + protect + seed files'], { cwd: WORK_DIR, env: gitEnv() });
    await record('action', 'bootstrap commit', commit);
    const push = await git(['push', 'origin', BRANCH], { cwd: WORK_DIR, env: gitEnv() });
    await record('observation', 'bootstrap push', push);
  }

  await record('action', 'securegit unlock (bootstrap)', await securegit(['unlock'], { cwd: WORK_DIR }));
  const config = await readConfig(WORK_DIR);
  const keyringPath = resolveKeyringPath(config.repoId, HOME);
  await mkdir(SHARED_DIR, { recursive: true });
  await copyFile(keyringPath, SHARED_KEYRING);
  await writeFile(SHARED_READY, `${config.repoId}\n`);
  await record('action', 'published keyring to shared volume for other actors to bootstrap from', { repoId: config.repoId });
}

async function bootstrapAsFollower() {
  await waitFor(() => exists(SHARED_READY), { description: 'collaborator-a bootstrap (shared/bootstrap-ready)' });
  await cloneOrInit();
  await git(['checkout', BRANCH], { cwd: WORK_DIR, env: gitEnv() });
  await git(['config', 'user.name', ROLE], { cwd: WORK_DIR });
  await git(['config', 'user.email', `${ROLE}@sandbox`], { cwd: WORK_DIR });

  const config = await readConfig(WORK_DIR);
  const keyringPath = resolveKeyringPath(config.repoId, HOME);
  await mkdir(dirname(keyringPath), { recursive: true });
  await copyFile(SHARED_KEYRING, keyringPath);
  await record('action', 'copied shared keyring into local HOME', { repoId: config.repoId });
  // install-then-unlock-then-re-checkout, in that exact order — matches
  // specs/securegit/08-multi-recipient.md's "Joining" flow. `install` must
  // come *after* `cloneOrInit()`'s clone (a still-locked machine with the
  // filter already attached fails closed on git's own safety-check `clean`
  // call during a pull, per that spec), and unlock must come before the
  // re-checkout below or there's no session to smudge-decrypt with.
  await record('action', 'securegit install', await securegit(['install'], { cwd: WORK_DIR }));
  await record('action', 'securegit unlock (bootstrap)', await securegit(['unlock'], { cwd: WORK_DIR }));
  // Files were checked out by `cloneOrInit()`'s `git clone`, before the
  // filter existed — git's stat-cache means a plain re-checkout won't
  // re-run smudge on them. `rm --cached` + checkout from HEAD does (see
  // the same spec section for why `--force` alone does not).
  await git(['rm', '--cached', '-r', '-q', '.'], { cwd: WORK_DIR, env: gitEnv() });
  await git(['checkout', 'HEAD', '--', '.'], { cwd: WORK_DIR, env: gitEnv() });
}

/** Picks up a keyring the operator may have rotated since this actor last checked. */
async function resyncKeyring() {
  try {
    const config = await readConfig(WORK_DIR);
    const keyringPath = resolveKeyringPath(config.repoId, HOME);
    await copyFile(SHARED_KEYRING, keyringPath);
  } catch {
    // No shared keyring yet, or this actor has no clone yet — fine, try
    // again next iteration.
  }
}

async function pullOnce() {
  const fetchRes = await git(['fetch', 'origin', BRANCH], { cwd: WORK_DIR, env: gitEnv() });
  if (fetchRes.code !== 0) return { ok: false, step: 'fetch', ...fetchRes };
  const mergeRes = await git(['merge', '--no-edit', `origin/${BRANCH}`], { cwd: WORK_DIR, env: gitEnv() });
  if (mergeRes.code !== 0) {
    await git(['merge', '--abort'], { cwd: WORK_DIR, env: gitEnv() });
    return { ok: false, step: 'merge', ...mergeRes };
  }
  return { ok: true };
}

async function collaboratorRound(n) {
  await resyncKeyring();
  const unlock = await securegit(['unlock'], { cwd: WORK_DIR });
  await record('observation', `unlock (round ${n})`, { code: unlock.code });

  const pull = await pullOnce();
  await record('observation', `pull (round ${n})`, pull);

  const filePath = join(WORK_DIR, 'secrets', `${ROLE}.json`);
  let counter = n;
  try {
    const current = JSON.parse(await readFile(filePath, 'utf8'));
    counter = (current.counter ?? 0) + 1;
  } catch {
    // First round, or the file was corrupted/removed by chaos — either way,
    // writing a fresh, well-formed file is the correct move, not an error.
  }
  await writeFile(filePath, `${JSON.stringify({ role: ROLE, counter, at: new Date().toISOString() }, null, 2)}\n`);

  await git(['add', '-A'], { cwd: WORK_DIR, env: gitEnv() });
  const commit = await git(['commit', '-m', `${ROLE}: round ${n}`], { cwd: WORK_DIR, env: gitEnv() });
  if (commit.code !== 0) {
    await record('observation', `nothing to commit (round ${n})`, commit);
    return;
  }

  let push = await git(['push', 'origin', BRANCH], { cwd: WORK_DIR, env: gitEnv() });
  if (push.code !== 0) {
    // Non-fast-forward is the ordinary outcome of a real push race with
    // another collaborator — pull once and retry, exactly what a human
    // would do, not a failure worth escalating on its own.
    const retryPull = await pullOnce();
    if (retryPull.ok) {
      push = await git(['push', 'origin', BRANCH], { cwd: WORK_DIR, env: gitEnv() });
    }
  }
  if (push.code === 0) {
    // The commit sha at the moment of a *confirmed* push, not just "we
    // tried" — this is what the operator's finalIntegritySelfCheck()
    // cross-references at the end of the run: zero data loss means every
    // sha recorded here is still reachable and still decryptable, not
    // that every push attempt succeeded.
    const headSha = (await git(['rev-parse', 'HEAD'], { cwd: WORK_DIR, env: gitEnv() })).stdout.trim();
    await record('observation', `push (round ${n})`, { ...push, commit: headSha });
  } else {
    await record('observation', `push (round ${n})`, push);
  }
}

/**
 * The operator's answer to T1 (16-adversarial-integrity.md): `protect` is
 * idempotent (`install.ts`'s `updateGitattributes` only ever appends a
 * pattern's line when it's missing), so re-asserting the full protected-
 * pattern list every round is an ordinary GitOps-style reconciliation, not
 * an "if attacked" special case — a no-op when `.gitattributes` already
 * matches, a real repair the round after chaos-5's attribute-downgrade
 * attack lands. This is exactly the automated enforcement
 * 16-adversarial-integrity.md's T1 section documents as *not* shipped in
 * the product itself (no `install --hooks`, no server-side `pre-receive`)
 * — built here as the always-on ops process a real deployment would run
 * alongside it, using only the existing `protect`/`reencrypt` primitives,
 * not as a new CLI feature.
 *
 * Doesn't retroactively fix history: a blob some collaborator already
 * committed unprotected during the window between the downgrade landing
 * and this reconciling stays plaintext in that commit forever (rewriting
 * history is a deliberate, disruptive incident-response action this loop
 * must never take on its own) — this only bounds how long the *next*
 * write stays exposed for.
 *
 * **`reencrypt` runs every round, unconditionally — found the hard way,
 * twice, by real runs.** Restoring the attribute alone (run 33952769755)
 * wedges every future round: the instant `secrets/**`'s `filter=securegit`
 * line comes back, git runs `clean` again over the affected path's
 * *working-tree* content (still plaintext — that's exactly what the
 * downgrade let land) to compare against the index, which still holds
 * that *same* plaintext, so `clean`'s freshly-produced ciphertext no
 * longer matches it — git calls the path locally modified and refuses
 * every subsequent `pullOnce()` merge touching it, forever, since nothing
 * commits a fix on its own. Running `reencrypt` in the *same* branch as
 * the attribute fix (an earlier version of this function) resolved that
 * case but missed a second, independent trigger for the identical
 * symptom (run 33953375232): `operatorRound`'s own periodic `key rotate`
 * bumps the current generation, and 09-rotation-recovery.md's own
 * documented behavior — "files not touched again stay on their old
 * [generation] indefinitely, which is correct" — means every protected
 * path nobody has recommitted since is now on an *older* generation than
 * `clean` will produce for it, the exact same mismatch, with no
 * `.gitattributes` change involved at all to trigger the old
 * attribute-only-gated call. Calling `reencrypt` every round regardless
 * (idempotent — a no-op once nothing is stale) closes both triggers with
 * the one primitive, rather than chasing a third.
 */
async function reconcileProtection(n) {
  const before = await readFile(GITATTRIBUTES_PATH, 'utf8').catch(() => '');
  await securegit(['protect', ...PROTECTED_PATTERNS], { cwd: WORK_DIR });
  const after = await readFile(GITATTRIBUTES_PATH, 'utf8').catch(() => '');
  const reencrypt = await securegit(['reencrypt'], { cwd: WORK_DIR });
  // Logged every round, pass or fail, independently of whether anything
  // below ends up committed — a `reencrypt` that silently starts erroring
  // (e.g. on some future attack shape this doesn't anticipate) would
  // otherwise be invisible whenever nothing else gave this round a reason
  // to commit, the same blind spot `pullOnce()`'s own result had before
  // this file started recording it unconditionally too.
  if (reencrypt.code !== 0) {
    await record('observation', `reencrypt reported an error (round ${n})`, {
      code: reencrypt.code,
      stderr: reencrypt.stderr.trim(),
    });
  }

  await git(['add', '.gitattributes'], { cwd: WORK_DIR, env: gitEnv() });
  const commit = await git(
    ['commit', '-m', 'operator: reconcile attribute protection / re-encrypt stale generations'],
    { cwd: WORK_DIR, env: gitEnv() },
  );
  if (commit.code !== 0) return; // nothing needed fixing this round — the ordinary case, not worth logging

  let push = await git(['push', 'origin', BRANCH], { cwd: WORK_DIR, env: gitEnv() });
  if (push.code !== 0) {
    // Same ordinary push race `collaboratorRound` already handles — pull
    // (merging whatever else landed since) and retry once.
    const retryPull = await pullOnce();
    if (retryPull.ok) {
      push = await git(['push', 'origin', BRANCH], { cwd: WORK_DIR, env: gitEnv() });
    }
  }
  await record('action', `reconciled attribute protection / re-encrypted stale generations (round ${n})`, {
    before,
    after,
    reencrypt: { code: reencrypt.code, stderr: reencrypt.stderr.trim() },
    push,
  });
}

async function operatorRound(n) {
  await securegit(['unlock'], { cwd: WORK_DIR });
  const pull = await pullOnce();
  // Unlike `collaboratorRound` (which treats a failed pull as an ordinary
  // push race and retries around its own push), this is worth recording
  // every round, pass or fail: `reconcileProtection()` below can only ever
  // see what this pull actually brought in, so a merge that silently keeps
  // failing round after round would silently stop the T1 recovery loop
  // too, with nothing else in this round's own logic able to tell. `head`
  // makes a stuck/diverged local HEAD visible directly, not just inferred
  // from `pull.ok`.
  const headRes = await git(['rev-parse', 'HEAD'], { cwd: WORK_DIR });
  await record('observation', `pull (round ${n})`, { ...pull, head: headRes.stdout.trim() });
  if (!pull.ok) {
    const [originRes, statusRes] = await Promise.all([
      git(['rev-parse', `origin/${BRANCH}`], { cwd: WORK_DIR }),
      git(['status', '--porcelain'], { cwd: WORK_DIR }),
    ]);
    await record('observation', `pull failed (round ${n})`, {
      origin: originRes.stdout.trim(),
      dirty: statusRes.stdout.trim(),
    });
  }

  await reconcileProtection(n);

  const status = await securegit(['status', '--json'], { cwd: WORK_DIR });
  await record('observation', `status (round ${n})`, { code: status.code, stdout: status.stdout.trim() });

  const access = await securegit(['verify', '--access', '--json'], { cwd: WORK_DIR });
  await record('observation', `verify --access (round ${n})`, { code: access.code, stdout: access.stdout.trim() });

  const verify = await securegit(['verify', '--json'], { cwd: WORK_DIR });
  await record('observation', `verify (round ${n})`, { code: verify.code, stdout: verify.stdout.trim() });

  if (n % 4 === 0) {
    const rotate = await securegit(['key', 'rotate', '--confirm-recipients', '0'], { cwd: WORK_DIR });
    await record('action', `key rotate (round ${n})`, rotate);
    if (rotate.code === 0) {
      const config = await readConfig(WORK_DIR);
      const keyringPath = resolveKeyringPath(config.repoId, HOME);
      await copyFile(keyringPath, SHARED_KEYRING);
      await record('action', 'republished rotated keyring to shared volume', {});
    }
  }
}

/**
 * The zero-data-loss check (see the exchange that led here: "whatever
 * chaos happened, the codebase integrity must be guaranteed and data loss
 * must be ZERO"). Only meaningful run by the operator specifically —
 * chaos-4/chaos-6 never target it (see specs/chaotests/01-sandbox.md),
 * so its own keyring is the one in this whole sandbox guaranteed to hold
 * every generation ever created, uncorrupted, and is therefore the only
 * party that can actually *prove* recoverability rather than merely
 * assert it. The unprivileged `verifier` (no key, by design) trusts this
 * self-report rather than re-deriving it — that trust boundary is real
 * and worth restating: it holds only as long as the operator stays the
 * one role nothing in this sandbox corrupts.
 *
 * Two distinct failure classes:
 *   - a commit this run itself recorded as successfully pushed
 *     (report.jsonl's `push` observations, `commit` field) is no longer
 *     reachable in history at all — something *lost* a confirmed write,
 *     not just failed to make one
 *   - a protected blob that IS still reachable no longer decrypts (or
 *     decrypts to something that doesn't parse/match its own recorded
 *     shape) under the operator's own, complete keyring — `smudge
 *     --strict` is essential here: plain `smudge` passing ciphertext
 *     through unchanged when locked/missing-generation would silently
 *     read as a false "success"
 */
async function finalIntegritySelfCheck() {
  await pullOnce();

  const reportPath = process.env.REPORT_PATH ?? '/report/report.jsonl';
  let reportEvents = [];
  try {
    const raw = await readFile(reportPath, 'utf8');
    reportEvents = raw
      .split('\n')
      .filter(Boolean)
      .map((line) => {
        try {
          return JSON.parse(line);
        } catch {
          return null;
        }
      })
      .filter(Boolean);
  } catch {
    // No report yet — nothing confirmed-pushed to cross-reference, which
    // is a legitimate (if unlikely) state, not an error.
  }
  const confirmedPushedShas = [
    ...new Set(
      reportEvents
        .filter((e) => e.kind === 'observation' && e.code === 0 && typeof e.commit === 'string' && e.message?.startsWith?.('push (round'))
        .map((e) => e.commit),
    ),
  ];

  const reachableRes = await git(['log', '--all', '--format=%H'], { cwd: WORK_DIR, env: gitEnv() });
  const reachable = new Set(reachableRes.stdout.trim().split('\n').filter(Boolean));
  const missingCommits = confirmedPushedShas.filter((sha) => !reachable.has(sha));

  const decryptFailures = [];
  let blobsChecked = 0;
  const seenBlobs = new Set();
  for (const commit of reachable) {
    const lsRes = await git(['ls-tree', '-r', '--name-only', commit, '--', 'secrets'], { cwd: WORK_DIR, env: gitEnv() });
    for (const path of lsRes.stdout.trim().split('\n').filter(Boolean)) {
      const shaRes = await git(['rev-parse', `${commit}:${path}`], { cwd: WORK_DIR, env: gitEnv() });
      const blobSha = shaRes.stdout.trim();
      if (!blobSha || seenBlobs.has(blobSha)) continue;
      seenBlobs.add(blobSha);
      blobsChecked += 1;

      const ciphertext = await runBinary('git', ['cat-file', '-p', blobSha], { cwd: WORK_DIR, env: gitEnv() });
      const smudged = await securegitBinaryIO(['smudge', '--strict', '--', path], ciphertext.stdout, {
        cwd: WORK_DIR,
        env: gitEnv(),
      });
      if (smudged.code !== 0) {
        decryptFailures.push({ commit, path, blobSha, reason: 'smudge --strict exited nonzero', stderr: smudged.stderr.trim() });
        continue;
      }
      try {
        const parsed = JSON.parse(smudged.stdout.toString('utf8'));
        if (typeof parsed.role !== 'string' || typeof parsed.counter !== 'number') {
          decryptFailures.push({ commit, path, blobSha, reason: 'decrypted content has an unexpected shape', got: parsed });
        }
      } catch {
        decryptFailures.push({ commit, path, blobSha, reason: 'decrypted content is not valid JSON' });
      }
    }
  }

  await record('observation', 'final integrity self-check', {
    confirmedPushedCommits: confirmedPushedShas.length,
    missingCommits,
    blobsChecked,
    decryptFailures,
  });
}

async function main() {
  say(`starting as ${ROLE}, duration ${DURATION_SECONDS}s`);

  if (ROLE === 'collaborator-a') {
    await bootstrapAsCollaboratorA();
  } else {
    await bootstrapAsFollower();
  }

  const deadline = Date.now() + DURATION_SECONDS * 1000;
  let round = 0;
  while (Date.now() < deadline) {
    round += 1;
    try {
      if (ROLE === 'operator') {
        await operatorRound(round);
      } else {
        await collaboratorRound(round);
      }
    } catch (e) {
      await record('error', `round ${round} threw`, { message: (e && e.message) || String(e) });
    }
    await sleep(jitter(3000, 8000));
  }

  if (ROLE === 'operator') {
    say('main loop done — running final integrity self-check');
    try {
      await finalIntegritySelfCheck();
    } catch (e) {
      await record('error', 'finalIntegritySelfCheck threw', { message: (e && e.message) || String(e) });
    }
  }

  await record('action', 'run complete', { rounds: round });
}

main().catch(async (e) => {
  await record('error', 'fatal', { message: (e && e.message) || String(e) });
  process.exit(1);
});
