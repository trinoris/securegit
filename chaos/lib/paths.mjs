// Re-exports the *real* path-resolution logic from the built package
// (/app/dist, baked into the shared image by chaos/Dockerfile) instead of
// reimplementing it here — a second, drifted copy of
// resolveSessionPath()/resolveKeyringPath() would be exactly the kind of
// thing that quietly stops matching reality. Absolute-path ESM specifiers
// resolve as file URLs in Node, so this works without any package.json
// wiring between /chaos and /app.

export { resolveSessionPath } from '/app/dist/session.js';
export { resolveKeyringPath, configPath, readConfig } from '/app/dist/config.js';
export { identityPath } from '/app/dist/identity.js';

import { readdir } from 'node:fs/promises';
import { join } from 'node:path';

/**
 * A chaos agent sharing an actor's HOME doesn't necessarily have its own
 * clone (chaos-4/chaos-6 don't), so it can't just `readConfig()` a working
 * tree it doesn't have — but the keyring layout
 * (`~/.securegit/repos/<repoId>/keyring.json`) makes the repoId
 * discoverable directly from HOME once the actor has unlocked at least
 * once. Returns the first (only, in this sandbox) repoId directory found,
 * or null before that actor has gotten that far yet.
 */
export async function discoverRepoId(home) {
  const reposDir = join(home, '.securegit', 'repos');
  let entries;
  try {
    entries = await readdir(reposDir, { withFileTypes: true });
  } catch {
    return null;
  }
  const dir = entries.find((e) => e.isDirectory());
  return dir ? dir.name : null;
}

export function sessionDir(home) {
  return join(home, '.securegit', 'session');
}
