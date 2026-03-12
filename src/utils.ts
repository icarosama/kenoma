import * as core from "@actions/core";

/**
 * Retries an async function with exponential backoff on transient errors.
 */
export async function withRetry<T>(
  fn: () => Promise<T>,
  maxAttempts = 3,
  baseDelayMs = 1000
): Promise<T> {
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await fn();
    } catch (error) {
      if (attempt === maxAttempts || !isTransientError(error)) throw error;
      const delay = baseDelayMs * 2 ** (attempt - 1);
      core.info(`  Attempt ${attempt}/${maxAttempts} failed, retrying in ${delay}ms...`);
      await sleep(delay);
    }
  }
  throw new Error("unreachable");
}

function isTransientError(error: unknown): boolean {
  if (!(error instanceof Error)) return false;
  const status = (error as { status?: number }).status;
  if (typeof status === "number") {
    return [408, 429, 500, 502, 503, 504].includes(status);
  }
  const msg = error.message.toLowerCase();
  return (
    msg.includes("rate limit") ||
    msg.includes("timeout") ||
    msg.includes("econnreset") ||
    msg.includes("etimedout") ||
    msg.includes("econnrefused") ||
    msg.includes("network")
  );
}

/**
 * Races a promise against a timeout. Rejects if the timeout fires first.
 */
export function withTimeout<T>(
  promise: Promise<T>,
  timeoutMs: number,
  label = "Operation"
): Promise<T> {
  return Promise.race([
    promise,
    new Promise<never>((_, reject) =>
      setTimeout(
        () => reject(new Error(`${label} timed out after ${timeoutMs}ms`)),
        timeoutMs
      )
    ),
  ]);
}

/**
 * Returns a function that runs tasks with at most `concurrency` active at a time.
 */
export function createConcurrencyLimiter(concurrency: number) {
  let active = 0;
  const queue: Array<() => void> = [];

  return function limit<T>(fn: () => Promise<T>): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      const run = () => {
        active++;
        fn()
          .then(resolve, reject)
          .finally(() => {
            active--;
            if (queue.length > 0) queue.shift()!();
          });
      };
      if (active < concurrency) run();
      else queue.push(run);
    });
  };
}

export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Returns a structured logger that prefixes messages with ISO timestamp and context label.
 */
export function makeLogger(context: string) {
  const ts = () => new Date().toISOString();
  return {
    info: (msg: string) => core.info(`[${ts()}] [${context}] ${msg}`),
    warning: (msg: string) => core.warning(`[${ts()}] [${context}] ${msg}`),
    error: (msg: string) => core.error(`[${ts()}] [${context}] ${msg}`),
  };
}
