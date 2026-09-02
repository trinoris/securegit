import { describe, it, expect } from 'vitest';
import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';

// Static checks for specs/securegit/16-adversarial-integrity.md T11 (supply
// chain: zero runtime dependencies) and the timing-safe-comparison
// requirement under "Non-goals, restated". These are properties of the
// published package and the source tree, not of any one module's behaviour,
// so they belong in their own file rather than beside crypto.ts or config.ts.

const REPO_ROOT = join(import.meta.dirname, '..');

interface PackageJson {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  files?: string[];
}

async function readPackageJson(): Promise<PackageJson> {
  return JSON.parse(await readFile(join(REPO_ROOT, 'package.json'), 'utf8')) as PackageJson;
}

async function listProductionSourceFiles(dir: string): Promise<string[]> {
  const entries = await readdir(dir, { withFileTypes: true });
  const files: string[] = [];
  for (const entry of entries) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...(await listProductionSourceFiles(full)));
    } else if (entry.name.endsWith('.ts') && !entry.name.endsWith('.test.ts')) {
      files.push(full);
    }
  }
  return files;
}

describe('package.json (T11: supply chain)', () => {
  it('declares zero runtime dependencies', async () => {
    const pkg = await readPackageJson();
    expect(pkg.dependencies).toBeUndefined();
  });

  it('publishes only dist/, src/, README.md and LICENSE', async () => {
    const pkg = await readPackageJson();
    expect(pkg.files).toEqual(['dist', 'src', 'README.md', 'LICENSE']);
  });

  it('development dependencies are exactly the expected build/test tooling', async () => {
    const pkg = await readPackageJson();
    expect(Object.keys(pkg.devDependencies ?? {}).sort()).toEqual(
      ['@types/node', '@vitest/coverage-v8', 'typescript', 'vitest'].sort(),
    );
  });
});

// A specifier is either relative (`./x.js`, `../x.js`) or a `node:` builtin.
// Anything else — a bare package name — is a runtime dependency this test
// exists to catch before it ever reaches package.json.
const IMPORT_RE = /(?:import|export)\s+(?:type\s+)?[^'"]*from\s+['"]([^'"]+)['"]/g;

describe('src/ import hygiene (T11)', () => {
  it('every import in production source is relative or a node: builtin', async () => {
    const files = await listProductionSourceFiles(join(REPO_ROOT, 'src'));
    expect(files.length).toBeGreaterThan(10); // sanity: the scan actually found the package

    const offenders: string[] = [];
    for (const file of files) {
      const content = await readFile(file, 'utf8');
      for (const match of content.matchAll(IMPORT_RE)) {
        const specifier = match[1]!;
        if (specifier.startsWith('.') || specifier.startsWith('node:')) continue;
        offenders.push(`${file}: ${specifier}`);
      }
    }
    expect(offenders).toEqual([]);
  });
});

describe('non-AEAD comparisons use timingSafeEqual', () => {
  it('crypto.ts wraps node:crypto\'s timingSafeEqual as equalCt', async () => {
    const content = await readFile(join(REPO_ROOT, 'src', 'crypto.ts'), 'utf8');
    expect(content).toContain('timingSafeEqual');
    expect(content).toContain('export function equalCt');
  });

  it('no production file outside crypto.ts/envelope.ts/identity.ts/cli.ts/recovery.ts calls Buffer#equals()', async () => {
    // envelope.ts's one use is `looksLikeEnvelope`, comparing against the
    // public MAGIC constant — not secret material, so timing doesn't matter
    // there. identity.ts's one use is decodePublicKey's checksum check —
    // also public material (the checksum is derived from the public key
    // itself, sent in the clear), so a timing attack there could reveal
    // nothing an observer with the encoded string couldn't already compute
    // directly. cli.ts's one use is `reencrypt` deciding whether a
    // re-encrypted blob differs from what's already staged — both sides are
    // ciphertext that either already is, or is about to become, public
    // repository content, never secret material. recovery.ts's one use is
    // parseRecoveryCode's checksum check: even though the recovery code
    // itself is secret, both sides of that comparison are derived from the
    // *same caller-supplied input* — it's a transcription-typo catcher, not
    // a security boundary, and reveals nothing about a secret the caller
    // doesn't already control. The actual secrecy check is `importRecovery`'s
    // AEAD auth tag, timing-safe by construction via Node's own crypto.
    // Anywhere else, a raw `.equals()` on a Buffer is exactly the mistake
    // `equalCt` exists to prevent (see `keyring.ts`'s fingerprint check,
    // which uses it).
    const allowedBasenames = new Set(['crypto.ts', 'envelope.ts', 'identity.ts', 'cli.ts', 'recovery.ts']);
    const files = await listProductionSourceFiles(join(REPO_ROOT, 'src'));
    const offenders: string[] = [];
    for (const file of files) {
      if (allowedBasenames.has(file.split('/').pop()!)) continue;
      const content = await readFile(file, 'utf8');
      if (/\.equals\(/.test(content)) offenders.push(file);
    }
    expect(offenders).toEqual([]);
  });

  it('no production file compares a fingerprint with a raw === or !==', async () => {
    const files = await listProductionSourceFiles(join(REPO_ROOT, 'src'));
    const offenders: string[] = [];
    for (const file of files) {
      if (file.endsWith('crypto.ts')) continue; // equalCt's own definition
      const content = await readFile(file, 'utf8');
      if (/fingerprint\w*\s*[!=]==|[!=]==\s*\w*[fF]ingerprint/.test(content)) {
        offenders.push(file);
      }
    }
    expect(offenders).toEqual([]);
  });
});
