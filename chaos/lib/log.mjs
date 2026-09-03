// Shared logging + JSONL report writer for every actor/chaos-agent/verifier
// script. Console output is for a human watching `docker compose logs`;
// the JSONL report (one line per event, appended to REPORT_PATH — a file
// on a volume shared with the verifier) is what the verifier actually
// reads at the end of the run. See specs/chaotests/01-sandbox.md
// "Orchestration" — the report is closer to a fuzzing campaign's output
// than a single pass/fail.

import { appendFile, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';

const ROLE = process.env.SANDBOX_ROLE ?? 'unknown';
const REPORT_PATH = process.env.REPORT_PATH ?? '/report/report.jsonl';

let reportDirReady = false;
async function ensureReportDir() {
  if (reportDirReady) return;
  await mkdir(dirname(REPORT_PATH), { recursive: true }).catch(() => {});
  reportDirReady = true;
}

function timestamp() {
  return new Date().toISOString();
}

/** Human-readable line to stdout, for `docker compose logs -f`. */
export function say(message) {
  process.stdout.write(`[${timestamp()}] [${ROLE}] ${message}\n`);
}

/**
 * Structured event appended to the shared JSONL report, in addition to the
 * human-readable line. `kind` is one of:
 *   - 'action'      this process did something on purpose (an edit, a
 *                    push, a corruption, an attack attempt)
 *   - 'observation'  this process noticed a state (a command's exit code,
 *                    a file's readability, a recovery attempt's result)
 *   - 'error'        something failed in a way the driver script itself
 *                    didn't expect — distinct from an *observed* securegit
 *                    failure, which is an 'observation' with ok: false
 */
export async function record(kind, message, data = {}) {
  say(message);
  await ensureReportDir();
  const line = `${JSON.stringify({ ts: timestamp(), role: ROLE, kind, message, ...data })}\n`;
  await appendFile(REPORT_PATH, line).catch((e) => {
    process.stderr.write(`[${timestamp()}] [${ROLE}] failed to append report: ${(e && e.message) || e}\n`);
  });
}

export const ROLE_NAME = ROLE;
export const REPORT_PATH_RESOLVED = REPORT_PATH;
