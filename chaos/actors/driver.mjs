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
import { resolveKeyringPath, readConfig, identityPath } from '../lib/paths.mjs';

const ROLE = process.env.SANDBOX_ROLE;
const REMOTE_URL = process.env.REMOTE_URL ?? 'git://remote/repo.git';
const WORK_DIR = process.env.WORK_DIR ?? '/work';
const SHARED_DIR = process.env.SHARED_DIR ?? '/shared';
const SHARED_KEYRING = join(SHARED_DIR, 'keyring.json');
const SHARED_READY = join(SHARED_DIR, 'bootstrap-ready');
const BRANCH = process.env.BRANCH ?? 'main';
const DURATION_SECONDS = Number(process.env.CHAOS_DURATION_SECONDS ?? 300);
const HOME = process.env.HOME;
// direct-master (W1) | working-branch (W2) | pr-gated (W3) —
// specs/chaotests/03-orchestrator.md.
const WORKFLOW = process.env.SANDBOX_WORKFLOW ?? 'direct-master';
// Registering collaborator-a/b as signing recipients (chaos-5 deliberately
// excluded) only matters where something actually checks a signature —
// direct-master's pre-receive hook is an unconditional no-op
// (remote/entrypoint.mjs), so there's nothing there for signing to harden,
// and enabling it anyway would just make every ordinary commit fail
// `verify`'s own commit-signed-by-recipient check for no protective
// benefit. See 03-orchestrator.md's "Since then" note for why this exists.
const SIGNING_ENABLED = WORKFLOW !== 'direct-master';
const SHARED_IDENTITY = (role) => join(SHARED_DIR, `identity-${role}.json`);
// Only set (and only meaningful) for the operator under working-branch/
// pr-gated — see `landReviewedMerge()`.
const REMOTE_REPO_PATH = process.env.REMOTE_REPO_PATH;
// What `bootstrapAsCollaboratorA` protects at seed time, and what the
// operator's `reconcileProtection` keeps re-asserting every round — see
// there for why one list serves both purposes.
const PROTECTED_PATTERNS = ['secrets/**'];
const GITATTRIBUTES_PATH = join(WORK_DIR, '.gitattributes');

/**
 * Where a non-orchestrator role's own edits land. Under `direct-master`
 * this *is* `BRANCH` (today's only behaviour, unchanged); under the other
 * two, `master` never accepts a direct update at all
 * (chaos/remote/entrypoint.mjs's pre-receive hook) — every push instead
 * targets a branch the orchestrator later reviews. `working-branch` (W2)
 * shares one ref between both collaborators (and chaos-5); `pr-gated`
 * (W3) gives every role, attacker included, its own, so the orchestrator
 * reviews per-branch rather than per-promotion. Not called for `operator`
 * itself — it works directly against `BRANCH`, reviewing, never
 * contributing.
 */
function targetRef() {
  if (WORKFLOW === 'direct-master') return BRANCH;
  if (WORKFLOW === 'working-branch') return 'working';
  return `feature/${ROLE}`;
}
const TARGET_REF = targetRef();

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

/**
 * Adopts `TARGET_REF` if it already exists on `origin` (working-branch:
 * whichever collaborator gets here second finds the other's already
 * pushed), or creates it fresh otherwise (pr-gated: always unique per
 * role, so always this branch). Either way this is a ref *creation* push
 * the very first time anyone does it for a shared ref, or every time for
 * a per-role one — both allowed unconditionally by the pre-receive hook,
 * which only ever gates *updates* to `master`, never the creation of any
 * other ref. Not called for `operator`/`direct-master` — see `targetRef()`.
 */
async function ensureTargetRef() {
  if (TARGET_REF === BRANCH) return;
  const remoteHas = await git(['ls-remote', '--exit-code', 'origin', `refs/heads/${TARGET_REF}`], { cwd: WORK_DIR });
  if (remoteHas.code === 0) {
    await git(['fetch', 'origin', TARGET_REF], { cwd: WORK_DIR, env: gitEnv() });
    await git(['checkout', '-B', TARGET_REF, `origin/${TARGET_REF}`], { cwd: WORK_DIR, env: gitEnv() });
  } else {
    await git(['checkout', '-B', TARGET_REF], { cwd: WORK_DIR, env: gitEnv() });
    await git(['push', 'origin', TARGET_REF], { cwd: WORK_DIR, env: gitEnv() });
  }
}

/**
 * Generates this role's own signing identity (specs/securegit/08-multi-recipient.md,
 * "Commit signing") and, unlike a real user, configures git to sign
 * *every* subsequent commit automatically (`commit.gpgsign = true`) —
 * `identity init` deliberately never touches git's own signing config
 * itself (a real user might already have `user.signingkey` pointing
 * somewhere else entirely), but this sandbox's collaborators have no
 * existing signing setup to preserve, so wiring it up here is the
 * sandbox's job, not the CLI's.
 */
async function enableCommitSigning() {
  await record('action', 'securegit identity init --generate-signing-key', await securegit(['identity', 'init', '--generate-signing-key'], { cwd: WORK_DIR }));
  const signingKeyFile = join(HOME, '.securegit', 'signing_key');
  await git(['config', 'gpg.format', 'ssh'], { cwd: WORK_DIR });
  await git(['config', 'user.signingkey', signingKeyFile], { cwd: WORK_DIR });
  await git(['config', 'commit.gpgsign', 'true'], { cwd: WORK_DIR });
  const identity = JSON.parse(await readFile(identityPath(HOME), 'utf8'));
  return { fingerprint: identity.fingerprint, publicKey: identity.publicKey, signingKey: identity.signingKey };
}

/** Publishes the public half of this role's signing identity for whoever registers recipients to pick up. */
async function publishSigningIdentity(identity) {
  await mkdir(SHARED_DIR, { recursive: true });
  await writeFile(SHARED_IDENTITY(ROLE), JSON.stringify(identity));
  await record('action', 'published signing identity to shared volume', { fingerprint: identity.fingerprint });
}

/**
 * Operator only: waits for both collaborators' published signing
 * identities, then registers each as a recipient with `--signing-key` and
 * lands the result directly onto `BRANCH` — via the same privileged
 * `landReviewedMerge()` path the orchestrator's own reviewed merges use,
 * not an ordinary push. This isn't a style choice: `BRANCH` accepts no
 * ordinary-push *update* at all once the pre-receive hook is live (a
 * first version of this function tried `git push origin BRANCH` from
 * collaborator-a and was correctly refused by the very protection this
 * feature depends on — confirmed by a real run's own
 * "refusing direct push to refs/heads/main" rejection). Only the operator
 * has the filesystem access to land it, which is also the more honest
 * real-world shape: onboarding a repository's initial trusted signers is
 * exactly the kind of one-time, administrative action a real deployment's
 * trusted party performs, not something an ordinary collaborator pushes
 * through on their own. chaos-5 is never invited into this exchange at
 * all (no paired legitimate role to wait on), which is what makes it
 * unable to sign anything under any registered key afterward.
 */
async function registerSigningRecipients() {
  await waitFor(() => exists(SHARED_IDENTITY('collaborator-a')) && exists(SHARED_IDENTITY('collaborator-b')), {
    description: 'both collaborators publishing signing identities',
  });
  await git(['fetch', 'origin', BRANCH], { cwd: WORK_DIR, env: gitEnv() });
  const expectedOld = (await git(['rev-parse', `origin/${BRANCH}`], { cwd: WORK_DIR })).stdout.trim();
  await git(['checkout', '-B', BRANCH, `origin/${BRANCH}`], { cwd: WORK_DIR, env: gitEnv() });
  for (const role of ['collaborator-a', 'collaborator-b']) {
    const identity = JSON.parse(await readFile(SHARED_IDENTITY(role), 'utf8'));
    await record(
      'action',
      `securegit key add-recipient (${role}, signing)`,
      await securegit(['key', 'add-recipient', identity.publicKey, '--label', role, '--signing-key', identity.signingKey], { cwd: WORK_DIR }),
    );
  }
  await git(['add', '.securegit/recipients'], { cwd: WORK_DIR, env: gitEnv() });
  const commit = await git(['commit', '-m', 'bootstrap: register collaborator-a and collaborator-b as signing recipients'], { cwd: WORK_DIR, env: gitEnv() });
  await record('action', 'commit signing recipients', commit);
  const newSha = (await git(['rev-parse', 'HEAD'], { cwd: WORK_DIR })).stdout.trim();
  const landed = await landReviewedMerge(newSha, expectedOld);
  await record('observation', 'landed signing recipients onto BRANCH', landed);
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

  // Unlock and publish the keyring *before* switching to `working`
  // (`ensureTargetRef()`, below) — this is what unblocks
  // `bootstrapAsFollower()`'s own wait on `SHARED_READY`, and
  // collaborator-b's signing identity (needed by
  // `registerSigningRecipients()` next) can't exist until collaborator-b
  // has started at all.
  await record('action', 'securegit unlock (bootstrap)', await securegit(['unlock'], { cwd: WORK_DIR }));
  const config = await readConfig(WORK_DIR);
  const keyringPath = resolveKeyringPath(config.repoId, HOME);
  await mkdir(SHARED_DIR, { recursive: true });
  await copyFile(keyringPath, SHARED_KEYRING);
  await writeFile(SHARED_READY, `${config.repoId}\n`);
  await record('action', 'published keyring to shared volume for other actors to bootstrap from', { repoId: config.repoId });

  if (SIGNING_ENABLED) {
    const identity = await enableCommitSigning();
    await publishSigningIdentity(identity);
  }

  await ensureTargetRef();
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

  // The operator reviews other roles' branches but never contributes its
  // own content commits, so it has nothing for a signing check to gate —
  // only collaborator-b needs an identity here (collaborator-a generated
  // and published its own earlier, in bootstrapAsCollaboratorA()). The
  // operator instead performs the *registration* itself once both
  // identities exist, since it's the one role with the filesystem access
  // to land that commit onto a hook-protected BRANCH at all.
  if (ROLE === 'collaborator-b' && SIGNING_ENABLED) {
    const identity = await enableCommitSigning();
    await publishSigningIdentity(identity);
  }
  if (ROLE === 'operator' && SIGNING_ENABLED) {
    await registerSigningRecipients();
  }

  // The operator/orchestrator works directly against `BRANCH` always —
  // reviewing other roles' branches, never contributing its own.
  if (ROLE !== 'operator') await ensureTargetRef();
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

async function pullOnce(ref = BRANCH) {
  const fetchRes = await git(['fetch', 'origin', ref], { cwd: WORK_DIR, env: gitEnv() });
  if (fetchRes.code !== 0) return { ok: false, step: 'fetch', ...fetchRes };
  const mergeRes = await git(['merge', '--no-edit', `origin/${ref}`], { cwd: WORK_DIR, env: gitEnv() });
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

  const pull = await pullOnce(TARGET_REF);
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

  let push = await git(['push', 'origin', TARGET_REF], { cwd: WORK_DIR, env: gitEnv() });
  if (push.code !== 0) {
    // Non-fast-forward is the ordinary outcome of a real push race with
    // another collaborator — pull once and retry, exactly what a human
    // would do, not a failure worth escalating on its own.
    const retryPull = await pullOnce(TARGET_REF);
    if (retryPull.ok) {
      push = await git(['push', 'origin', TARGET_REF], { cwd: WORK_DIR, env: gitEnv() });
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

// ---------------------------------------------------------------------------
// Orchestrator (working-branch / pr-gated) — specs/chaotests/03-orchestrator.md
// ---------------------------------------------------------------------------

/** `working-branch`: the one shared ref. `pr-gated`: every `feature/*` branch currently on `origin`. */
async function candidateRefs() {
  if (WORKFLOW === 'working-branch') return ['working'];
  const res = await git(['ls-remote', '--heads', 'origin', 'feature/*'], { cwd: WORK_DIR });
  if (res.code !== 0) return [];
  return res.stdout
    .trim()
    .split('\n')
    .filter(Boolean)
    .map((line) => line.split('\t')[1])
    .filter(Boolean)
    .map((ref) => ref.replace(/^refs\/heads\//, ''));
}

/**
 * Lands a locally-computed commit as `master`'s new tip via a direct
 * `update-ref` against the bare repo's own filesystem (mounted read-write
 * via `REMOTE_REPO_PATH`, docker-compose.yml) — the *ref* update never
 * invokes `receive-pack` and so never runs the pre-receive hook every
 * ordinary push (including the orchestrator's own, were it to try) is
 * subject to. This is the privileged path 03-orchestrator.md's "Enforcing
 * 'only the orchestrator writes master'" describes: the network protocol
 * gates everyone uniformly (no identity to exempt anyone by); direct
 * filesystem access to the bare repo is what's actually reserved for the
 * one trusted process. The compare-and-swap form
 * (`update-ref <ref> <new> <old>`) refuses if `master` moved since
 * `expectedOld` was read, which shouldn't happen — the orchestrator is
 * meant to be `master`'s only writer under these two workflows — but
 * costs nothing to check for rather than assume.
 *
 * The scratch-ref push first is a separate concern from the ref update
 * itself: `newSha` is only ever *already* in the bare repo's own object
 * database for free when landing happens to be a fast-forward (an
 * already-pushed ref's own tip, the common case while `master` hasn't
 * diverged from whatever's being merged) — a real, divergent merge commit
 * (or, here, a plain new commit built directly on `master`) exists only
 * in WORK_DIR's local objects until *something* transfers it, and
 * `update-ref` alone refuses to point a ref at an object it doesn't have
 * ("nonexistent object", confirmed directly the first time this function
 * was ever asked to land a genuine non-fast-forward commit). Pushing to a
 * disposable, unprotected ref name does that transfer — it invokes
 * `receive-pack`, but never for `refs/heads/${BRANCH}` itself, so the
 * actual property this function exists to guarantee (that ref is never
 * moved except by this privileged path) is untouched.
 */
async function landReviewedMerge(newSha, expectedOld) {
  await git(['push', 'origin', `${newSha}:refs/land-object/${newSha}`], { cwd: WORK_DIR, env: gitEnv() });
  return git(['--git-dir', REMOTE_REPO_PATH, 'update-ref', `refs/heads/${BRANCH}`, newSha, expectedOld]);
}

/**
 * The merge-request review itself (03-orchestrator.md, "The orchestrator's
 * review, precisely"): build the merge against `master`'s *current* tip
 * (never trust the incoming branch's own `.gitattributes` — the same
 * precision 16-adversarial-integrity.md's T1 section insists on), then
 * accept or reject, never silently repair. Reuses `securegit verify`
 * as-is rather than re-implementing its attribute/envelope checks —
 * `verify` never needs a session ([13](../securegit/13-verify.md)), so
 * this works whether or not the orchestrator itself is unlocked.
 *
 * Deliberately narrow, matching the spec's own honesty about what an
 * automated check can prove:
 *   - a merge conflict rejects outright (no auto-resolution attempted)
 *   - any change under `.securegit/recipients/**` rejects unconditionally
 *     (T5 — "no cryptographic fix... a code-review problem", never
 *     auto-accepted regardless of how plausible it looks)
 *   - `attributes-present` / `no-conflicting-attributes` failing, or any
 *     `leak` finding, rejects (T1, both the attack and the accident case)
 *   - once signing has been adopted (2+ recipients, at least one signing
 *     key registered), any commit unique to the proposed ref that is
 *     unsigned or signed by an unregistered key rejects too
 *     (`allCommitsSignedByRecipient()` — point 5, subsuming T3/T4's
 *     relocation/rollback shapes by identity rather than content: an
 *     attacker never added as a recipient can't sign at all, regardless of
 *     what the commit actually changes)
 *   - anything else is accepted — 16-adversarial-integrity.md's own
 *     ceiling still holds precisely: there is no cryptographic fix for the
 *     *content* of a relocated/rolled-back blob, only for *who* committed it
 */
async function reviewAndMaybeMerge(ref, sha, n) {
  await git(['fetch', 'origin', BRANCH], { cwd: WORK_DIR, env: gitEnv() });
  const expectedOld = (await git(['rev-parse', `origin/${BRANCH}`], { cwd: WORK_DIR })).stdout.trim();
  await git(['checkout', '-B', 'review', `origin/${BRANCH}`], { cwd: WORK_DIR, env: gitEnv() });

  const merge = await git(['merge', '--no-edit', sha], { cwd: WORK_DIR, env: gitEnv() });
  if (merge.code !== 0) {
    await git(['merge', '--abort'], { cwd: WORK_DIR, env: gitEnv() }).catch(() => {});
    await record('action', `rejected ${ref} (round ${n}): merge conflict`, { ref, sha, stderr: merge.stderr.trim() });
    return;
  }

  const recipientDiff = await git(
    ['diff', '--name-only', `origin/${BRANCH}`, 'HEAD', '--', '.securegit/recipients'],
    { cwd: WORK_DIR },
  );
  if (recipientDiff.stdout.trim().length > 0) {
    await record('action', `rejected ${ref} (round ${n}): recipient change requires human review, never auto-merged`, {
      ref,
      sha,
      changed: recipientDiff.stdout.trim().split('\n'),
    });
    return;
  }

  const verify = await securegit(['verify', '--json'], { cwd: WORK_DIR });
  let report = null;
  try {
    report = JSON.parse(verify.stdout);
  } catch {
    // Falls through to the rejected branch below — an unparseable report
    // is exactly as untrustworthy as a failed one, never treated as a pass.
  }
  const checkOk = (id) => report?.checks?.find((c) => c.id === id)?.ok === true;
  const hasLeak = (report?.findings ?? []).some((f) => f.kind === 'leak');
  const passed = report !== null && checkOk('attributes-present') && checkOk('no-conflicting-attributes') && !hasLeak;
  if (!passed) {
    await record('action', `rejected ${ref} (round ${n}): failed integrity review`, {
      ref,
      sha,
      verify: report ?? verify.stdout.trim(),
    });
    return;
  }

  const signing = await allCommitsSignedByRecipient(expectedOld, sha);
  if (!signing.ok) {
    await record('action', `rejected ${ref} (round ${n}): ${signing.reason}`, { ref, sha });
    return;
  }

  const mergeSha = (await git(['rev-parse', 'HEAD'], { cwd: WORK_DIR })).stdout.trim();
  const landed = await landReviewedMerge(mergeSha, expectedOld);
  if (landed.code !== 0) {
    // `master` moved since `expectedOld` was read — shouldn't happen (the
    // orchestrator is meant to be the only writer), but safe to just
    // retry next round against a freshly re-fetched tip rather than
    // escalate on what's likely a leftover from a previous run's volume.
    await record('observation', `merge of ${ref} computed but update-ref lost a race (round ${n})`, {
      ref,
      sha,
      stderr: landed.stderr.trim(),
    });
    return;
  }
  await record('action', `merged ${ref} onto master (round ${n})`, { ref, sha, mergeSha });
}

/**
 * Point 5 (03-orchestrator.md, "The orchestrator's review, precisely"):
 * every commit unique to the proposed ref — `git log origin/master..<sha>`,
 * computed here as `expectedOld..sha` directly against the incoming
 * branch tip, never the merge commit — must be signed, and by a
 * fingerprint already on `master`'s own recipient list. Rejects the whole
 * merge otherwise: an attacker who was never added as a recipient can't
 * produce a valid signature under any registered key, which is what makes
 * this one check reject T1/T3/T4/T5 alike without needing to recognize
 * the attack shape at all.
 *
 * Reads registered fingerprints via `securegit key list-recipients --json`
 * against the already-checked-out merged worktree rather than
 * reimplementing OpenSSH fingerprint hashing here — safe to read from the
 * merge result specifically because the recipient-diff check earlier in
 * `reviewAndMaybeMerge` already rejected any change under
 * `.securegit/recipients/**`, so the merged tree's recipients are
 * guaranteed identical to `origin/${BRANCH}`'s.
 *
 * Mirrors verify.ts's own `commit-signed-by-recipient` no-op tiers
 * (13-verify.md, "Authenticity") on purpose: fewer than 2 recipients, or
 * none with a signing key registered, means nobody has adopted signing
 * yet, and enforcing against an empty allow-list would reject every merge
 * forever — indistinguishable from a repository that simply hasn't turned
 * this on. This is deliberately *not* delegated to the existing `verify
 * --json` call already in `reviewAndMaybeMerge`: that check only ever
 * resolves `HEAD`'s own signer (by design — 13-verify.md's own doc comment
 * says a per-commit-range version is a merge reviewer's job, not verify's),
 * so the full-range walk is new work that belongs here.
 */
async function allCommitsSignedByRecipient(base, tip) {
  const listRes = await securegit(['key', 'list-recipients', '--json'], { cwd: WORK_DIR });
  let recipients = [];
  try {
    recipients = JSON.parse(listRes.stdout);
  } catch {
    return { ok: false, reason: 'could not read recipient list' };
  }
  const registered = new Set(recipients.map((r) => r.signingFingerprint).filter((fp) => typeof fp === 'string'));
  if (recipients.length < 2 || registered.size === 0) {
    return { ok: true }; // not yet adopted — same no-op tiers as verify.ts's own check
  }

  const logRes = await git(['log', '--format=%H', `${base}..${tip}`], { cwd: WORK_DIR });
  const commits = logRes.stdout.trim().split('\n').filter(Boolean);
  for (const commit of commits) {
    const fpRes = await git(
      ['-c', 'gpg.ssh.allowedSignersFile=/dev/null', 'log', '-1', '--format=%GF', commit],
      { cwd: WORK_DIR },
    );
    const fingerprint = fpRes.stdout.trim();
    if (!fingerprint) return { ok: false, reason: `commit ${commit.slice(0, 8)} is not signed` };
    if (!registered.has(fingerprint)) {
      return { ok: false, reason: `commit ${commit.slice(0, 8)} is signed by an unrecognized key (${fingerprint})` };
    }
  }
  return { ok: true };
}

// ref -> last sha reviewed (accepted or rejected) — skips re-reviewing
// (and re-logging) a branch nothing has changed on since last round.
const lastReviewedSha = new Map();

async function orchestratorReviewRound(n) {
  for (const ref of await candidateRefs()) {
    // `ls-remote` alone (the first version of this loop) only ever learns
    // a ref's sha, never transfers the commit *object* — every real run
    // then failed `git merge <sha>` with "not something we can merge"
    // (git's error for an unknown object, easy to misread as an ordinary
    // merge conflict since both hit the same `merge.code !== 0` branch in
    // `reviewAndMaybeMerge()`), rejecting every genuine edit while only
    // ever "succeeding" on a branch's still-untouched creation point,
    // already known locally from bootstrap. `fetch` actually brings the
    // commit down first.
    const fetchRes = await git(['fetch', 'origin', ref], { cwd: WORK_DIR });
    if (fetchRes.code !== 0) continue; // ref briefly missing/racing with creation — try again next round
    const sha = (await git(['rev-parse', `origin/${ref}`], { cwd: WORK_DIR })).stdout.trim();
    if (!sha || lastReviewedSha.get(ref) === sha) continue;
    lastReviewedSha.set(ref, sha);
    await reviewAndMaybeMerge(ref, sha, n);
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
  // A full fetch of *every* branch, not just BRANCH — confirmed necessary
  // by two real runs (33955584166, 33955942857): under working-branch/
  // pr-gated, a collaborator's very last push (to its own feature/working
  // ref) can land after the orchestrator's last review round of the run,
  // which is otherwise the only thing keeping those branches' remote-
  // tracking refs current here. Without this, `git log --all` below
  // simply never sees that commit — not because anything was lost, but
  // because this operator clone never fetched the branch it was on again
  // — and it shows up as a false "missing commit", a race in this test
  // harness's own end-of-run timing, not a real data-loss finding. A
  // no-op refspec for direct-master (nothing else exists to fetch beyond
  // BRANCH), so safe unconditionally. `git fetch origin` with no
  // ref argument uses the clone's default refspec
  // (`+refs/heads/*:refs/remotes/origin/*`) — every branch, not one.
  await git(['fetch', 'origin'], { cwd: WORK_DIR, env: gitEnv() });
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
        if (WORKFLOW === 'direct-master') {
          await operatorRound(round);
        } else {
          await orchestratorReviewRound(round);
        }
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
