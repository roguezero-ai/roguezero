/**
 * Revocation: the kill switch. A list of revoked credential ids, checked at verify time.
 *
 * There are two forms, and the difference is where trust comes from:
 *
 * - **Local file** — an unsigned JSON list. The filesystem *is* the trust root: if an attacker
 *   can rewrite the file, they can already rewrite the policy next to it. Zero-friction for a
 *   laptop, a single box, or the golden-path demo.
 * - **Signed list** — a JWT signed by a DID on the verifier's `trustedIssuers`. Required for
 *   anything fetched over the network, because otherwise whoever hosts the list (a CDN, a
 *   bucket, an intermediary with a valid TLS certificate) could silently drop an entry and
 *   resurrect a revoked agent. Signing moves the trust from the *host* to the *publisher*,
 *   which is what lets the list be mirrored anywhere — the availability problem becomes a CDN's
 *   problem instead of a verifier's.
 *
 * The signed format borrows three ideas from thirty years of CRLs, and each is load-bearing:
 *
 * 1. **A freshness window (`exp`).** A list is only trusted until it expires, so a publisher
 *    must re-sign on a schedule *even when nothing has changed*. Without this, an attacker who
 *    can block your fetch keeps a revoked credential alive forever; with it, staleness fails
 *    closed on the list's own terms rather than on the verifier's uptime.
 * 2. **A sequence number (`seq`).** A signed list stays cryptographically valid until it
 *    expires, so replaying an *older* one is a rollback attack that hides a fresh revocation.
 *    Verifiers refuse a `seq` lower than one they've already seen.
 * 3. **Per-entry expiry.** An entry may be dropped once the credential it names has expired on
 *    its own — a revoked credential that can no longer be presented needs no entry. Without
 *    recording each credential's expiry we could never prune, and the list would grow without
 *    bound while being re-fetched on every call.
 *
 * Security posture: fail closed everywhere. A list we cannot read, cannot verify, or cannot
 * trust is never "nothing is revoked" — it is a denial with a reason naming which of those
 * happened, because the operator's response differs for each.
 */

import { readFile, writeFile } from "node:fs/promises";
import { createJWT, verifyJWT } from "did-jwt";
import type { Resolvable } from "did-resolver";
import { z } from "zod";
import { DEFAULT_CLOCK_SKEW_SECONDS, DEFAULT_LIFETIMES } from "./constants.js";
import { signerToIssuer, type CredentialSigner } from "./credentials.js";
import { VerificationError } from "./errors.js";
import type { Did, VerificationFailureReason } from "./types.js";
import type { RevocationChecker } from "./verify.js";

/** Marks a JWT as a RogueZero revocation list, and versions the payload shape. */
export const REVOCATION_LIST_FORMAT = 1;

/** Default timeout for fetching a remote revocation list (ms). */
export const DEFAULT_FETCH_TIMEOUT_MS = 3000;

function fail(reason: VerificationFailureReason, message: string): VerificationError {
  return new VerificationError(message, reason);
}

// --- Entries ----------------------------------------------------------------------

/**
 * One revoked credential. `expiresAt` is the *credential's own* expiry (unix seconds), carried
 * so a publisher can prune the entry once the credential could no longer be presented anyway.
 * Without it the list grows forever while being re-fetched on every call.
 */
export interface RevocationEntry {
  id: string;
  expiresAt?: number;
}

export const revocationEntrySchema = z.object({
  id: z.string().min(1),
  expiresAt: z.number().int().positive().optional(),
});

/** Drop entries whose credential has already expired — they can no longer be presented. */
export function pruneExpiredEntries(
  entries: RevocationEntry[],
  nowSeconds: number = Math.floor(Date.now() / 1000),
): RevocationEntry[] {
  return entries.filter((e) => e.expiresAt === undefined || e.expiresAt > nowSeconds);
}

// --- Unsigned local list ----------------------------------------------------------

/** A bare id is still accepted: it simply can never be pruned. */
const revokedItemSchema = z.union([z.string().min(1), revocationEntrySchema]);

export interface RevocationList {
  revoked: Array<string | RevocationEntry>;
  updatedAt?: string;
}

export const revocationListSchema = z.object({
  revoked: z.array(revokedItemSchema),
  updatedAt: z.string().optional(),
});

function toEntry(item: string | RevocationEntry): RevocationEntry {
  return typeof item === "string" ? { id: item } : item;
}

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

/** Load an unsigned revocation list from a local JSON file. */
export async function loadRevocationListFromFile(path: string): Promise<Set<string>> {
  const list = await readRevocationFile(path);
  return new Set(list.revoked.map((item) => toEntry(item).id));
}

/** Load the full entries (with expiries), which is what a publisher needs in order to prune. */
export async function loadRevocationEntriesFromFile(path: string): Promise<RevocationEntry[]> {
  const list = await readRevocationFile(path);
  return list.revoked.map(toEntry);
}

/**
 * A RevocationChecker backed by an unsigned local file, read fresh on each check by default.
 * The filesystem is the trust root — see the module note. Use a signed list for anything
 * fetched over a network.
 */
export function createFileRevocationChecker(path: string, cacheTtlSeconds = 0): RevocationChecker {
  const load = async (): Promise<Set<string>> => {
    try {
      return await loadRevocationListFromFile(path);
    } catch (error) {
      throw fail(
        "revocation-list-unavailable",
        `could not read revocation list at ${path}: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  };
  return createRevocationChecker(cacheTtlSeconds > 0 ? withTtlCache(load, cacheTtlSeconds) : load);
}

export interface RevokeOptions {
  /** The credential's own expiry (unix seconds). Recorded so the entry can later be pruned. */
  expiresAt?: number;
}

/** Revoke a credential by id, appending to (or creating) an unsigned local JSON list. Idempotent. */
export async function revokeCredential(
  path: string,
  credentialId: string,
  options: RevokeOptions = {},
): Promise<void> {
  const list = await readRevocationFile(path);
  const entries = list.revoked.map(toEntry);
  const existing = entries.find((e) => e.id === credentialId);
  if (existing) {
    // Idempotent, but learn an expiry we didn't know before.
    if (existing.expiresAt === undefined && options.expiresAt !== undefined) {
      existing.expiresAt = options.expiresAt;
    }
  } else {
    entries.push({ id: credentialId, expiresAt: options.expiresAt });
  }
  const next: RevocationList = {
    revoked: entries.map((e) => (e.expiresAt === undefined ? e.id : e)),
    updatedAt: new Date().toISOString(),
  };
  await writeFile(path, `${JSON.stringify(next, null, 2)}\n`, "utf8");
}

/**
 * The next sequence number for a published list.
 *
 * Floored at the current unix time, which is what makes it safe: every `seq` we have ever
 * published was at least its own publish time, and time only moves forward — so even losing the
 * stored counter entirely cannot produce a number below one a verifier has already seen. The
 * stored value only breaks ties between two publishes inside the same second.
 *
 * A previous value implausibly far in the future means someone planted it (a denial of service
 * against future publishes), and we refuse rather than chase it.
 */
export function nextSequence(
  previous: number | undefined,
  nowSeconds: number = Math.floor(Date.now() / 1000),
): number {
  const ONE_YEAR = 365 * 24 * 60 * 60;
  if (previous !== undefined && previous > nowSeconds + ONE_YEAR) {
    throw new Error(
      `refusing to publish: the previous revocation list sequence (${previous}) is more than a ` +
        `year ahead of the current time. Someone planted it, or this machine's clock is wrong.`,
    );
  }
  return Math.max((previous ?? 0) + 1, nowSeconds);
}

// --- Signed list ------------------------------------------------------------------

/** A verified signed revocation list. */
export interface SignedRevocationList {
  issuer: Did;
  /** Strictly increasing per issuer; a lower value than one already seen is a rollback. */
  seq: number;
  /** Unix seconds. */
  issuedAt: number;
  /** Unix seconds; past this the list is stale and verification fails closed. */
  expiresAt: number;
  entries: RevocationEntry[];
}

const signedListPayloadSchema = z.object({
  rzrl: z.literal(REVOCATION_LIST_FORMAT),
  seq: z.number().int().nonnegative(),
  iat: z.number().int().positive(),
  exp: z.number().int().positive(),
  revoked: z.array(revocationEntrySchema),
});

export interface SignRevocationListOptions {
  /**
   * Strictly increasing per issuer. Persist it alongside the list; reusing or lowering it
   * makes a rollback indistinguishable from a legitimate republish.
   */
  seq: number;
  /** Freshness window. The publisher must re-sign this often, even with no changes. */
  ttlSeconds?: number;
  /** Clock source (unix seconds); injectable for tests. */
  now?: () => number;
}

/** Sign a revocation list. The signer must be a DID the verifiers already trust. */
export async function signRevocationList(
  signer: CredentialSigner,
  entries: RevocationEntry[],
  options: SignRevocationListOptions,
): Promise<string> {
  const now = options.now ?? (() => Math.floor(Date.now() / 1000));
  const issuedAt = now();
  const issuer = signerToIssuer(signer);
  return createJWT(
    {
      rzrl: REVOCATION_LIST_FORMAT,
      seq: options.seq,
      iat: issuedAt,
      exp: issuedAt + (options.ttlSeconds ?? DEFAULT_LIFETIMES.revocationListSeconds),
      revoked: entries.map((e) => revocationEntrySchema.parse(e)),
    },
    { issuer: issuer.did, signer: issuer.signer, alg: issuer.alg },
  );
}

export interface VerifyRevocationListOptions {
  trustedIssuers: Iterable<Did>;
  /**
   * The verifier's *own* staleness tolerance, independent of the publisher's `exp`. A relying
   * party is entitled to demand a fresher list than the publisher promises.
   */
  maxAgeSeconds?: number;
  /** Reject any list whose `seq` is below this (rollback defense). */
  minSeq?: number;
  now?: () => number;
}

function mapVerifyError(error: unknown): VerificationError {
  const message = error instanceof Error ? error.message : String(error);
  // did-jwt reports expiry and signature failures by message; map them to our taxonomy so an
  // operator can tell "re-sign the list" from "someone tampered with it".
  if (/expired|exp/i.test(message)) {
    return fail("revocation-list-stale", `revocation list has expired: ${message}`);
  }
  if (/resolve|resolver|DID document|no DID/i.test(message)) {
    return fail("revocation-list-invalid", `revocation list issuer is unresolvable: ${message}`);
  }
  return fail("revocation-list-invalid", `revocation list did not verify: ${message}`);
}

/**
 * Verify a signed revocation list: signature, format, trusted publisher, freshness, and that
 * it is not a replay of an older list. Returns the verified list on success; throws a
 * `VerificationError` naming the exact failure otherwise.
 */
export async function verifyRevocationList(
  jwt: string,
  resolver: Resolvable,
  options: VerifyRevocationListOptions,
): Promise<SignedRevocationList> {
  const now = options.now ?? (() => Math.floor(Date.now() / 1000));

  let verified;
  try {
    // did-jwt's skewTime is in SECONDS (verified empirically against did-jwt@8; passing
    // milliseconds here would silently widen the freshness window by 1000x).
    verified = await verifyJWT(jwt, { resolver, skewTime: DEFAULT_CLOCK_SKEW_SECONDS });
  } catch (error) {
    throw mapVerifyError(error);
  }

  const parsed = signedListPayloadSchema.safeParse(verified.payload);
  if (!parsed.success) {
    throw fail(
      "revocation-list-invalid",
      `revocation list payload is not a RogueZero revocation list (format ${REVOCATION_LIST_FORMAT}): ${parsed.error.message}`,
    );
  }
  const payload = parsed.data;
  const issuer = verified.issuer as Did;

  const trusted = new Set(options.trustedIssuers);
  if (!trusted.has(issuer)) {
    throw fail(
      "revocation-list-untrusted",
      `revocation list is signed by ${issuer}, which is not a trusted issuer — a list signed by anyone else could hide a revocation`,
    );
  }

  // The publisher's own window. did-jwt checks `exp` with skew, but re-check explicitly so an
  // injected clock (and our own skew policy) governs, not the library's default.
  if (payload.exp + DEFAULT_CLOCK_SKEW_SECONDS < now()) {
    throw fail(
      "revocation-list-stale",
      `revocation list expired at ${new Date(payload.exp * 1000).toISOString()}; publishers must re-sign on a schedule`,
    );
  }

  // The verifier's own tolerance, which may be stricter than the publisher's promise.
  if (options.maxAgeSeconds !== undefined) {
    const age = now() - payload.iat;
    if (age > options.maxAgeSeconds + DEFAULT_CLOCK_SKEW_SECONDS) {
      throw fail(
        "revocation-list-stale",
        `revocation list is ${age}s old, older than this verifier accepts (${options.maxAgeSeconds}s)`,
      );
    }
  }

  if (options.minSeq !== undefined && payload.seq < options.minSeq) {
    throw fail(
      "revocation-list-rollback",
      `revocation list seq ${payload.seq} is older than seq ${options.minSeq} already seen from ${issuer} — an old-but-valid list is how a revoked credential gets resurrected`,
    );
  }

  return {
    issuer,
    seq: payload.seq,
    issuedAt: payload.iat,
    expiresAt: payload.exp,
    entries: payload.revoked,
  };
}

export interface SignedRevocationSourceOptions extends Omit<VerifyRevocationListOptions, "minSeq"> {
  resolver: Resolvable;
}

/**
 * A loader over a source of *signed* lists. Remembers the highest `seq` seen from this source
 * for the life of the process, so a replayed older list is rejected as a rollback.
 *
 * The counter is tracked per *source*, not per issuer: one source is one publisher, and keying
 * by issuer would let an attacker reset the floor by replaying an old list from a different
 * trusted signer. The cost is that rotating the publishing key must not lower `seq`.
 *
 * The memory is in-process only. A verifier that restarts forgets, and would accept one old
 * (still unexpired) list. Persisting it — or shrinking the freshness window, which bounds the
 * exposure to that window — is the deployment's call; a hosted publisher makes the window small.
 */
export function createSignedRevocationLoader(
  read: () => Promise<string>,
  options: SignedRevocationSourceOptions,
): RevocationListLoader {
  let highestSeq: number | undefined;

  return async () => {
    const jwt = await read();
    const list = await verifyRevocationList(jwt, options.resolver, {
      trustedIssuers: options.trustedIssuers,
      maxAgeSeconds: options.maxAgeSeconds,
      minSeq: highestSeq,
      now: options.now,
    });
    highestSeq = list.seq;
    return new Set(list.entries.map((e) => e.id));
  };
}

async function fetchText(url: string, timeoutMs: number): Promise<string> {
  let response: Response;
  try {
    response = await fetch(url, { signal: AbortSignal.timeout(timeoutMs) });
  } catch (error) {
    throw fail(
      "revocation-list-unavailable",
      `could not fetch revocation list from ${url}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  if (!response.ok) {
    throw fail(
      "revocation-list-unavailable",
      `revocation list fetch failed: ${response.status} ${response.statusText}`,
    );
  }
  return (await response.text()).trim();
}

export interface UrlRevocationCheckerOptions extends SignedRevocationSourceOptions {
  cacheTtlSeconds?: number;
  timeoutMs?: number;
}

/**
 * A RevocationChecker backed by a signed list at an HTTP(S) URL.
 *
 * The signature — not the transport — is the trust root, so this list may be mirrored, cached,
 * or served from a CDN without the host being able to forge it. A small cache TTL is sensible;
 * it bounds propagation delay in exchange for not fetching on every call.
 */
export function createUrlRevocationChecker(
  url: string,
  options: UrlRevocationCheckerOptions,
): RevocationChecker {
  const timeoutMs = options.timeoutMs ?? DEFAULT_FETCH_TIMEOUT_MS;
  const load = createSignedRevocationLoader(() => fetchText(url, timeoutMs), options);
  return createRevocationChecker(
    options.cacheTtlSeconds && options.cacheTtlSeconds > 0
      ? withTtlCache(load, options.cacheTtlSeconds)
      : load,
  );
}

/** A RevocationChecker backed by a *signed* list in a local file — the signed path, testable offline. */
export function createSignedFileRevocationChecker(
  path: string,
  options: SignedRevocationSourceOptions & { cacheTtlSeconds?: number },
): RevocationChecker {
  const read = async (): Promise<string> => {
    try {
      return (await readFile(path, "utf8")).trim();
    } catch (error) {
      throw fail(
        "revocation-list-unavailable",
        `could not read signed revocation list at ${path}: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  };
  const load = createSignedRevocationLoader(read, options);
  return createRevocationChecker(
    options.cacheTtlSeconds && options.cacheTtlSeconds > 0
      ? withTtlCache(load, options.cacheTtlSeconds)
      : load,
  );
}
