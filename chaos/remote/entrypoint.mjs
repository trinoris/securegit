// The `remote` service: an anonymous `git daemon` serving one bare repo.
// No auth — this is a Docker Compose-internal network, not exposed outside
// the sandbox, and the repo holds only ciphertext regardless
// (01-threat-model.md's whole point). `-b main` pins the bare repo's HEAD
// symref up front so every actor's later `git checkout main` is an
// ordinary, unambiguous operation — see chaos/actors/driver.mjs's
// bootstrap comments for why that matters.

import { existsSync } from 'node:fs';
import { spawn, execFileSync } from 'node:child_process';

const REPO_PATH = process.env.REPO_PATH ?? '/repos/repo.git';

if (!existsSync(REPO_PATH)) {
  execFileSync('git', ['init', '--bare', '-b', 'main', REPO_PATH], { stdio: 'inherit' });
  execFileSync('git', ['config', '--file', `${REPO_PATH}/config`, 'daemon.uploadpack', 'true'], { stdio: 'inherit' });
  execFileSync('git', ['config', '--file', `${REPO_PATH}/config`, 'daemon.receivepack', 'true'], { stdio: 'inherit' });
}

process.stdout.write(`[remote] serving ${REPO_PATH} on :9418\n`);

const child = spawn(
  'git',
  ['daemon', '--verbose', '--export-all', '--reuseaddr', '--enable=receive-pack', '--base-path=/repos', '/repos'],
  { stdio: 'inherit' },
);
child.on('exit', (code) => process.exit(code ?? 1));
