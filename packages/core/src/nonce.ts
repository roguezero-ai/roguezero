/**
 * Challenge (nonce) issuance and single-use consumption — the replay defense.
 *
 * The interface is async and storage-agnostic on purpose: the in-memory store here is for
 * local dev and single-instance deployments, but replay protection must be *shared* across
 * horizontally-scaled verifier instances, so the same interface can be backed by Redis or
 * another shared store later without changing the pipeline. Nonces are single-use and
 * bound to an audience; a consumed nonce is remembered (until expiry) so a replay is
 * reported as `replayed`, distinct from an unknown/forged nonce.
 */

import { randomBytes } from "node:crypto";
import { DEFAULT_LIFETIMES } from "./constants.js";

export interface IssuedChallenge {
  nonce: string;
  audience: string;
  /** Unix-second expiry. */
  expiresAt: number;
}

/**
 * Outcome of consuming a challenge. Only `ok` permits the request to proceed; every other
 * value maps to a precise, fail-closed verification reason in the pipeline.
 */
export type ChallengeConsumeResult =
  "ok" | "unknown" | "replayed" | "expired" | "audience-mismatch";

export interface NonceStore {
  /** Issue a fresh, unguessable, audience-bound challenge. */
  issue(audience: string, ttlSeconds?: number): Promise<IssuedChallenge>;
  /** Atomically validate and consume a challenge (single use). */
  consume(nonce: string, audience: string): Promise<ChallengeConsumeResult>;
}

interface NonceEntry {
  audience: string;
  expiresAt: number;
  used: boolean;
}

export interface InMemoryNonceStoreOptions {
  /** Clock source (unix seconds); injectable for tests. */
  now?: () => number;
  /**
   * Hard cap on stored challenges. Past this, the soonest-to-expire entries are evicted so
   * memory stays bounded even under a flood of unconsumed `issue()` calls (an unauthenticated
   * caller can request challenges). Defaults to 100k.
   */
  maxEntries?: number;
}

/**
 * In-memory NonceStore for local dev / single-instance use. Not shared across processes
 * (see module note for the scaling path). Memory is bounded two ways: a throttled sweep of
 * expired entries on issue, and a hard `maxEntries` cap — so abandoned or flooded challenges
 * cannot grow the map without limit.
 */
export function createInMemoryNonceStore(options: InMemoryNonceStoreOptions = {}): NonceStore {
  const now = options.now ?? (() => Math.floor(Date.now() / 1000));
  const maxEntries = options.maxEntries ?? 100_000;
  const entries = new Map<string, NonceEntry>();
  let lastSweep = 0;

  const evictIfExpired = (nonce: string, entry: NonceEntry): boolean => {
    if (entry.expiresAt < now()) {
      entries.delete(nonce);
      return true;
    }
    return false;
  };

  const sweepExpired = (): void => {
    const t = now();
    for (const [nonce, entry] of entries) {
      if (entry.expiresAt < t) {
        entries.delete(nonce);
      }
    }
    lastSweep = t;
  };

  const enforceMaxEntries = (): void => {
    if (entries.size <= maxEntries) return;
    // Evict soonest-to-expire first until back under the cap.
    const byExpiry = [...entries.entries()].sort((a, b) => a[1].expiresAt - b[1].expiresAt);
    for (const [nonce] of byExpiry) {
      if (entries.size <= maxEntries) break;
      entries.delete(nonce);
    }
  };

  return {
    async issue(audience, ttlSeconds = DEFAULT_LIFETIMES.challengeSeconds) {
      const t = now();
      if (t - lastSweep >= 1) {
        sweepExpired(); // amortized cleanup, at most ~once/second
      }
      const nonce = randomBytes(32).toString("base64url");
      const expiresAt = t + ttlSeconds;
      entries.set(nonce, { audience, expiresAt, used: false });
      enforceMaxEntries();
      return { nonce, audience, expiresAt };
    },

    async consume(nonce, audience) {
      const entry = entries.get(nonce);
      if (!entry) return "unknown";
      if (evictIfExpired(nonce, entry)) return "expired";
      if (entry.audience !== audience) return "audience-mismatch";
      if (entry.used) return "replayed";
      entry.used = true;
      return "ok";
    },
  };
}
