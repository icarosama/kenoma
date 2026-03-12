/**
 * Retries an async function with exponential backoff on transient errors.
 */
export declare function withRetry<T>(fn: () => Promise<T>, maxAttempts?: number, baseDelayMs?: number): Promise<T>;
/**
 * Races a promise against a timeout. Rejects if the timeout fires first.
 */
export declare function withTimeout<T>(promise: Promise<T>, timeoutMs: number, label?: string): Promise<T>;
/**
 * Returns a function that runs tasks with at most `concurrency` active at a time.
 */
export declare function createConcurrencyLimiter(concurrency: number): <T>(fn: () => Promise<T>) => Promise<T>;
export declare function sleep(ms: number): Promise<void>;
/**
 * Returns a structured logger that prefixes messages with ISO timestamp and context label.
 */
export declare function makeLogger(context: string): {
    info: (msg: string) => void;
    warning: (msg: string) => void;
    error: (msg: string) => void;
};
