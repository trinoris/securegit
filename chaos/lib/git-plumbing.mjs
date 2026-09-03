// Plumbing-level commit construction for chaos-5 ("attacker",
// specs/chaotests/01-sandbox.md). A real attacker with push access relocating
// or rolling back a blob never goes through `git add`/the working tree —
// they operate on tree/blob objects directly, which matters here
// specifically: going through the working tree would run through
// securegit's own `clean` filter, and chaos-5 has no key, so the working
// tree only ever holds ciphertext-shaped bytes it can't meaningfully
// re-encrypt (16-adversarial-integrity.md's T3/T4 are about *reusing an
// existing envelope verbatim*, not producing a new one).
//
// Every attack here builds one commit on top of the *current remote* head
// and pushes that exact object, without ever touching chaos-5's own
// checkout, working tree, or index — a temporary GIT_INDEX_FILE is used for
// tree construction and discarded afterward.

import { git, runWithStdin } from './proc.mjs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { rm } from 'node:fs/promises';

/**
 * pathChanges: array of one of
 *   { path, content: string }                    — write new blob content
 *                                                    at path
 *   { path, sourcePath, sourceRef? }              — reuse an existing blob
 *                                                    (and its mode) from
 *                                                    `sourceRef` (any
 *                                                    commit-ish; defaults to
 *                                                    `origin/<branch>`,
 *                                                    i.e. the tree this
 *                                                    commit is otherwise
 *                                                    built from), unchanged,
 *                                                    at `path` — this is
 *                                                    what makes T3
 *                                                    (relocate a blob
 *                                                    verbatim) and T4
 *                                                    (roll a path back to
 *                                                    an older blob) the same
 *                                                    primitive
 *   { path, remove: true }                         — remove path from the
 *                                                     tree
 *
 * Returns the new commit sha on success, or throws with the git command's
 * stderr on any plumbing failure (fetch/push rejected, path not found).
 */
export async function buildAndPushCommit(cwd, branch, message, pathChanges) {
  const fetchRes = await git(['fetch', 'origin', branch], { cwd });
  if (fetchRes.code !== 0) throw new Error(`fetch failed: ${fetchRes.stderr.trim()}`);

  const base = `origin/${branch}`;
  const parentRes = await git(['rev-parse', base], { cwd });
  if (parentRes.code !== 0) throw new Error(`rev-parse ${base} failed: ${parentRes.stderr.trim()}`);
  const parent = parentRes.stdout.trim();

  const indexFile = join(tmpdir(), `chaos-index-${process.pid}-${Math.random().toString(16).slice(2)}`);
  const env = { ...process.env, GIT_INDEX_FILE: indexFile };
  try {
    const readTreeRes = await git(['read-tree', base], { cwd, env });
    if (readTreeRes.code !== 0) throw new Error(`read-tree failed: ${readTreeRes.stderr.trim()}`);

    for (const change of pathChanges) {
      if (change.remove) {
        const rmRes = await git(['update-index', '--force-remove', change.path], { cwd, env });
        if (rmRes.code !== 0) throw new Error(`update-index --force-remove ${change.path} failed: ${rmRes.stderr.trim()}`);
        continue;
      }
      let mode = '100644';
      let sha;
      if (change.sourcePath !== undefined) {
        const sourceRef = change.sourceRef ?? base;
        const lsRes = await git(['ls-tree', sourceRef, '--', change.sourcePath], { cwd });
        const m = /^(\d+) blob ([0-9a-f]+)\t/.exec(lsRes.stdout.trim());
        if (!m) throw new Error(`sourcePath not found in ${sourceRef}: ${change.sourcePath}`);
        mode = m[1];
        sha = m[2];
      } else {
        const hashRes = await runWithStdin('git', ['hash-object', '-w', '--stdin'], change.content, { cwd, env });
        if (hashRes.code !== 0) throw new Error(`hash-object failed: ${hashRes.stderr.trim()}`);
        sha = hashRes.stdout.trim();
      }
      const uiRes = await git(['update-index', '--add', '--cacheinfo', `${mode},${sha},${change.path}`], {
        cwd,
        env,
      });
      if (uiRes.code !== 0) throw new Error(`update-index --add ${change.path} failed: ${uiRes.stderr.trim()}`);
    }

    const treeRes = await git(['write-tree'], { cwd, env });
    if (treeRes.code !== 0) throw new Error(`write-tree failed: ${treeRes.stderr.trim()}`);
    const tree = treeRes.stdout.trim();

    const commitRes = await runWithStdin('git', ['commit-tree', tree, '-p', parent], message, { cwd, env });
    if (commitRes.code !== 0) throw new Error(`commit-tree failed: ${commitRes.stderr.trim()}`);
    const newSha = commitRes.stdout.trim();

    const pushRes = await git(['push', 'origin', `${newSha}:refs/heads/${branch}`], { cwd });
    if (pushRes.code !== 0) throw new Error(`push failed: ${pushRes.stderr.trim()}`);

    return newSha;
  } finally {
    await rm(indexFile, { force: true });
  }
}

/** The full text content of `path` as of `origin/<branch>`, or null if absent. */
export async function readBlobAt(cwd, branch, path) {
  await git(['fetch', 'origin', branch], { cwd });
  const res = await git(['show', `origin/${branch}:${path}`], { cwd });
  return res.code === 0 ? res.stdout : null;
}

/** Every file path under `dir` on `origin/<branch>`, or [] if none/absent. */
export async function listPathsUnder(cwd, branch, dir) {
  await git(['fetch', 'origin', branch], { cwd });
  const res = await git(['ls-tree', '-r', '--name-only', `origin/${branch}`, '--', dir], { cwd });
  if (res.code !== 0) return [];
  return res.stdout.trim().split('\n').filter(Boolean);
}

/** Every commit sha touching `path` on `origin/<branch>`, newest first. */
export async function historyOf(cwd, branch, path) {
  await git(['fetch', 'origin', branch], { cwd });
  const res = await git(['log', '--format=%H', `origin/${branch}`, '--', path], { cwd });
  if (res.code !== 0) return [];
  return res.stdout.trim().split('\n').filter(Boolean);
}
