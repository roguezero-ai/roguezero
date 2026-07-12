/**
 * A small, self-contained token-bucket rate limiter — the throttle in front of the runtime's
 * unauthenticated surface (`GET /challenge` mints a nonce for anyone who asks, so it is the one
 * endpoint an attacker can hit before presenting any credential).
 *
 * Token bucket, not fixed window: a bucket holds up to `capacity` tokens and refills at
 * `refillPerSecond`. Each `check(key)` spends one token; when the bucket is empty the caller is
 * throttled and told how long to wait. This permits a short honest burst while capping the
 * sustained rate — the shape you want for a challenge endpoint a well-behaved client hits a few
 * times, never in a flood.
 *
 * Security note — the limiter must bound *its own* memory. A naive `Map<key, bucket>` keyed on
 * client IP is itself an unbounded-memory DoS: an attacker spraying spoofed source addresses would
 * grow the map without limit, so the throttle meant to protect the process becomes the thing that
 * exhausts it. Two defenses, mirroring the nonce store: a full bucket carries no state worth
 * keeping (a caller who has fully refilled is indistinguishable from a brand-new one), so full
 * buckets are swept and dropped; and a hard `maxKeys` cap evicts the least-recently-seen keys as a
 * backstop. Eviction can only ever *forgive* a client early — it never wrongly throttles one — so
 * it is safe under memory pressure.
 *
 * In-process only: this bounds a single instance. Shared/distributed throttling (Redis, a gateway)
 * is the horizontal-scale path, and lives behind this same interface — as with the nonce store.
 */

/** Result of a throttle check. `retryAfterSeconds` is 0 when allowed, else a hint for `Retry-After`. */
export interface RateLimitResult {
  allowed: boolean;
  retryAfterSeconds: number;
}

export interface RateLimiter {
  /** Spend one token for `key`. Allowed only if a token was available. */
  check(key: string): RateLimitResult;
}

export interface RateLimiterOptions {
  /** Max tokens a bucket holds — the largest instantaneous burst permitted. */
  capacity: number;
  /** Tokens added per second — the sustained request rate once the burst is spent. */
  refillPerSecond: number;
  /**
   * Hard cap on tracked keys, so the bucket map can't grow without bound under a spray of distinct
   * source addresses. Past it, the least-recently-seen keys are evicted (only ever forgiving a
   * client early). Defaults to 100k.
   */
  maxKeys?: number;
  /** Clock source in **milliseconds**; injectable for deterministic tests. Defaults to `Date.now`. */
  now?: () => number;
}

interface Bucket {
  /** Fractional token count, brought current lazily on each check. */
  tokens: number;
  /** Last time (ms) this bucket was touched — for refill math and LRU eviction. */
  lastSeen: number;
}

/**
 * Create an in-process token-bucket rate limiter. Deterministic given an injected `now`, so the
 * negative tests can prove throttle-then-recover without real time passing.
 */
export function createRateLimiter(options: RateLimiterOptions): RateLimiter {
  const { capacity, refillPerSecond } = options;
  if (capacity <= 0 || refillPerSecond <= 0) {
    throw new Error("rate limiter capacity and refillPerSecond must be positive");
  }
  const maxKeys = options.maxKeys ?? 100_000;
  const now = options.now ?? (() => Date.now());
  const buckets = new Map<string, Bucket>();

  // Time (ms) for an empty bucket to refill completely — past this a bucket is provably full and
  // holds no state, so it is safe to drop during a sweep.
  const fullRefillMs = (capacity / refillPerSecond) * 1000;

  const sweepFull = (t: number): void => {
    for (const [key, bucket] of buckets) {
      if (t - bucket.lastSeen >= fullRefillMs) buckets.delete(key);
    }
  };

  const evictOldest = (): void => {
    // Backstop only, when live (non-full) keys alone exceed the cap: drop least-recently-seen.
    let oldestKey: string | undefined;
    let oldestSeen = Infinity;
    for (const [key, bucket] of buckets) {
      if (bucket.lastSeen < oldestSeen) {
        oldestSeen = bucket.lastSeen;
        oldestKey = key;
      }
    }
    if (oldestKey !== undefined) buckets.delete(oldestKey);
  };

  return {
    check(key) {
      const t = now();
      let bucket = buckets.get(key);
      if (!bucket) {
        // New key. Sweep provably-full buckets first so honest traffic doesn't accrete memory.
        sweepFull(t);
        while (buckets.size >= maxKeys) evictOldest();
        bucket = { tokens: capacity, lastSeen: t };
        buckets.set(key, bucket);
      } else {
        const elapsedSec = (t - bucket.lastSeen) / 1000;
        bucket.tokens = Math.min(capacity, bucket.tokens + elapsedSec * refillPerSecond);
        bucket.lastSeen = t;
      }

      if (bucket.tokens >= 1) {
        bucket.tokens -= 1;
        return { allowed: true, retryAfterSeconds: 0 };
      }
      // Not enough for one token: report the wait until the next whole token refills.
      const retryAfterSeconds = Math.ceil((1 - bucket.tokens) / refillPerSecond);
      return { allowed: false, retryAfterSeconds };
    },
  };
}
