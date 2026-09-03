import { sleep } from './proc.mjs';
import { say } from './log.mjs';

/**
 * Polls `conditionFn` (returning a truthy value, or a Promise of one) until
 * it succeeds or `timeoutMs` elapses. Every service in this sandbox starts
 * roughly together (`docker compose up`), so bootstrapping actors and
 * agents alike need to wait on each other rather than assume a start order
 * compose itself doesn't guarantee.
 */
export async function waitFor(conditionFn, { intervalMs = 2000, timeoutMs = 180_000, description = 'condition' } = {}) {
  const deadline = Date.now() + timeoutMs;
  let attempt = 0;
  for (;;) {
    attempt += 1;
    let result;
    try {
      result = await conditionFn();
    } catch {
      result = false;
    }
    if (result) return result;
    if (Date.now() >= deadline) {
      throw new Error(`timed out after ${timeoutMs}ms waiting for: ${description}`);
    }
    if (attempt === 1 || attempt % 10 === 0) {
      say(`waiting for ${description}… (attempt ${attempt})`);
    }
    await sleep(intervalMs);
  }
}
