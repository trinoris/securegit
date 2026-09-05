// The `remote` service: an anonymous `git daemon` serving one bare repo.
// No auth — this is a Docker Compose-internal network, not exposed outside
// the sandbox, and the repo holds only ciphertext regardless
// (01-threat-model.md's whole point). `-b main` pins the bare repo's HEAD
// symref up front so every actor's later `git checkout main` is an
// ordinary, unambiguous operation — see chaos/actors/driver.mjs's
// bootstrap comments for why that matters.
//
// Under SANDBOX_WORKFLOW=working-branch/pr-gated (specs/chaotests/03-orchestrator.md),
// this also installs a `pre-receive` hook that rejects any *update* (not
// creation) of `refs/heads/<BRANCH>` over the ordinary git protocol —
// unconditionally, for every pusher, since `git://` has no identity to
// exempt the orchestrator by. The orchestrator lands its own reviewed
// merges by a different, privileged path instead: a direct `update-ref`
// against this same bare repo over a shared filesystem volume
// (REMOTE_REPO_PATH in docker-compose.yml), which never invokes
// `receive-pack` and so never runs this hook at all. That split — network
// push always gated, direct filesystem access reserved for the one
// trusted process — is the actual mechanism this simulates; see
// 03-orchestrator.md's "Enforcing 'only the orchestrator writes master'"
// for the real-world server-side equivalents (self-hosted `pre-receive`,
// or github.com's required status checks) and its honest limits.

import { existsSync, writeFileSync, chmodSync } from 'node:fs';
import { spawn, execFileSync } from 'node:child_process';

const REPO_PATH = process.env.REPO_PATH ?? '/repos/repo.git';
const BRANCH = process.env.BRANCH ?? 'main';
const SANDBOX_WORKFLOW = process.env.SANDBOX_WORKFLOW ?? 'direct-master';

if (!existsSync(REPO_PATH)) {
  execFileSync('git', ['init', '--bare', '-b', 'main', REPO_PATH], { stdio: 'inherit' });
  execFileSync('git', ['config', '--file', `${REPO_PATH}/config`, 'daemon.uploadpack', 'true'], { stdio: 'inherit' });
  execFileSync('git', ['config', '--file', `${REPO_PATH}/config`, 'daemon.receivepack', 'true'], { stdio: 'inherit' });
}

const PROTECTED_REF = `refs/heads/${BRANCH}`;
const ZERO_SHA = '0'.repeat(40);
const hookPath = `${REPO_PATH}/hooks/pre-receive`;
if (SANDBOX_WORKFLOW === 'direct-master') {
  // W1: no gate at all — every push (including chaos-5's) lands directly,
  // exactly as before this spec existed. An empty/absent hook is a no-op,
  // but write one anyway (always exits 0) so a volume reused across a
  // mode switch can't accidentally keep a stale rejecting hook around.
  writeFileSync(hookPath, '#!/bin/sh\nexit 0\n');
} else {
  writeFileSync(
    hookPath,
    [
      '#!/bin/sh',
      '# Installed by chaos/remote/entrypoint.mjs — specs/chaotests/03-orchestrator.md.',
      '# Reads "<old-sha> <new-sha> <ref>" lines from stdin, one per ref in this push.',
      'status=0',
      'while read old new ref; do',
      `  if [ "$ref" = "${PROTECTED_REF}" ] && [ "$old" != "${ZERO_SHA}" ]; then`,
      `    echo "remote: refusing direct push to ${PROTECTED_REF} — this workflow (${SANDBOX_WORKFLOW}) only accepts reviewed merges" >&2`,
      '    status=1',
      '  fi',
      'done',
      'exit $status',
      '',
    ].join('\n'),
  );
}
chmodSync(hookPath, 0o755);
process.stdout.write(`[remote] SANDBOX_WORKFLOW=${SANDBOX_WORKFLOW}, pre-receive hook ${SANDBOX_WORKFLOW === 'direct-master' ? 'is a no-op' : `protects ${PROTECTED_REF}`}\n`);

process.stdout.write(`[remote] serving ${REPO_PATH} on :9418\n`);

const child = spawn(
  'git',
  ['daemon', '--verbose', '--export-all', '--reuseaddr', '--enable=receive-pack', '--base-path=/repos', '/repos'],
  { stdio: 'inherit' },
);
child.on('exit', (code) => process.exit(code ?? 1));
