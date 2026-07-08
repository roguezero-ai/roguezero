/**
 * Revocation: a simple JSON list of revoked credential ids, checked at verify time, plus
 * a `revoke` API. Deliberately simpler than the Bitstring Status List spec (deferred) —
 * the interface (a loader → a Set of ids) is what stays stable if we adopt that later.
 *
 * Security posture:
 * - Fail closed: if the list source can't be loaded (file error, HTTP failure), the checker
 *   throws, and the pipeline denies. A revocation source we can't read is not "allow".
 * - Fresh by default: checkers read the current list on every check, so a revocation takes
 *   effect immediately (defends the "revoked-but-cached" threat). A TTL cache is opt-in for
 *   high-throughput deployments that accept a bounded propagation delay.
 */

import { readFile, writeFile } from "node:fs/promises";
import { z } from "zod";
import type { RevocationChecker } from "./verify.js";

export interface RevocationList {
  revoked: string[];
  updatedAt?: string;
}

export const revocationListSchema = z.object({
  revoked: z.array(z.string()),
  updatedAt: z.string().optional(),
});

/** Loads the current set of revoked credential ids. */
export type RevocationListLoader = () => Promise<Set<string>>;

/** Build a RevocationChecker from a loader. Credentials without an id are not revocable. */
export function createRevocationChecker(loader: RevocationListLoader): RevocationChecker {
  return async (credential) => {
    if (!credential.id) return false;
    const revoked = await loader();
    return revoked.has(credential.id);
  };
}

/**
 * Wrap a loader with a TTL cache. Opt-in: caching trades revocation-propagation latency for
 * throughput, so callers choose it explicitly (default checkers below read fresh).
 */
export function withTtlCache(
  loader: RevocationListLoader,
  ttlSeconds: number,
  now: () => number = () => Date.now(),
): RevocationListLoader {
  let cache: { at: number; value: Set<string> } | undefined;
  return async () => {
    if (cache && now() - cache.at < ttlSeconds * 1000) {
      return cache.value;
    }
    const value = await loader();
    cache = { at: now(), value };
    return value;
  };
}

async function readRevocationFile(path: string): Promise<RevocationList> {
  try {
    const raw = await readFile(path, "utf8");
    return revocationListSchema.parse(JSON.parse(raw));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return { revoked: [] };
    }
    throw error;
  }
}

/** Load a revocation list from a local JSON file. */
export async function loadRevocationListFromFile(path: string): Promise<Set<string>> {
  const list = await readRevocationFile(path);
  return new Set(list.revoked);
}

/** Default timeout for fetching a remote revocation list (ms). */
export const DEFAULT_FETCH_TIMEOUT_MS = 3000;

/**
 * Load a revocation list from an HTTP(S) URL. Bounded by a timeout so a slow or hanging
 * endpoint cannot stall verification indefinitely; throws (fail closed) on timeout or a
 * non-OK response.
 */
export async function loadRevocationListFromUrl(
  url: string,
  timeoutMs = DEFAULT_FETCH_TIMEOUT_MS,
): Promise<Set<string>> {
  const response = await fetch(url, { signal: AbortSignal.timeout(timeoutMs) });
  if (!response.ok) {
    throw new Error(`revocation list fetch failed: ${response.status} ${response.statusText}`);
  }
  const list = revocationListSchema.parse(await response.json());
  return new Set(list.revoked);
}

/** A RevocationChecker backed by a local file, read fresh on each check by default. */
export function createFileRevocationChecker(path: string, cacheTtlSeconds = 0): RevocationChecker {
  const load = () => loadRevocationListFromFile(path);
  return createRevocationChecker(cacheTtlSeconds > 0 ? withTtlCache(load, cacheTtlSeconds) : load);
}

/** A RevocationChecker backed by an HTTP(S) list. A small cache TTL is sensible here. */
export function createUrlRevocationChecker(
  url: string,
  cacheTtlSeconds = 0,
  timeoutMs = DEFAULT_FETCH_TIMEOUT_MS,
): RevocationChecker {
  const load = () => loadRevocationListFromUrl(url, timeoutMs);
  return createRevocationChecker(cacheTtlSeconds > 0 ? withTtlCache(load, cacheTtlSeconds) : load);
}

/** Revoke a credential by id, appending to (or creating) the local JSON list. Idempotent. */
export async function revokeCredential(path: string, credentialId: string): Promise<void> {
  const list = await readRevocationFile(path);
  if (!list.revoked.includes(credentialId)) {
    list.revoked.push(credentialId);
  }
  list.updatedAt = new Date().toISOString();
  await writeFile(path, `${JSON.stringify(list, null, 2)}\n`, "utf8");
}
