/**
 * `roguezero revocations publish` — turn the unsigned list an operator edits into the signed
 * list a fleet consumes.
 *
 * Two files, two jobs. `revocations.json` is the source of truth for *which* credentials are
 * revoked: `revoke` appends to it, a human can read it, git can diff it. `revocations.jwt` is
 * what verifiers fetch: signed, sequenced, and stamped with a freshness window.
 *
 * The freshness window is why this is a *service* and not a one-off command. Verifiers reject a
 * stale list, so the publisher must re-sign on a schedule **even when nothing has changed** —
 * a cron entry, or something hosted. Shorter window, tighter revocation guarantee, less
 * tolerance for the publisher going quiet.
 *
 * The sequence counter is kept in a sidecar (`<out>.seq`) but is floored at the wall clock, so
 * losing it cannot roll the list backwards. See `nextSequence`.
 */

import { readFile, writeFile } from "node:fs/promises";
import {
  DEFAULT_LIFETIMES,
  loadRevocationEntriesFromFile,
  nextSequence,
  pruneExpiredEntries,
  signRevocationList,
  type RevocationEntry,
} from "@roguezero/core";
import { loadSigner } from "./keystore.js";

export const SEQ_SUFFIX = ".seq";

async function readStoredSeq(path: string): Promise<number | undefined> {
  try {
    const raw = (await readFile(path, "utf8")).trim();
    const seq = Number(raw);
    return Number.isSafeInteger(seq) && seq >= 0 ? seq : undefined;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw err;
  }
}

export interface PublishResult {
  outPath: string;
  seq: number;
  issuer: string;
  expiresAt: number;
  published: RevocationEntry[];
  pruned: RevocationEntry[];
}

export async function publishRevocationsCommand(opts: {
  /** The unsigned list to read (`revocations.json`). */
  listPath: string;
  /** Keystore of a controller on the verifiers' `trustedIssuers`. */
  signWithPath: string;
  /** Where to write the signed list (`revocations.jwt`). */
  outPath: string;
  /** Freshness window in seconds. Re-publish at least this often. */
  ttlSeconds?: number;
  now?: () => number;
}): Promise<PublishResult> {
  const now = opts.now ?? (() => Math.floor(Date.now() / 1000));
  const signer = await loadSigner(opts.signWithPath);

  const entries = await loadRevocationEntriesFromFile(opts.listPath);
  const published = pruneExpiredEntries(entries, now());
  const pruned = entries.filter((e) => !published.includes(e));

  const seqPath = `${opts.outPath}${SEQ_SUFFIX}`;
  const seq = nextSequence(await readStoredSeq(seqPath), now());
  const ttlSeconds = opts.ttlSeconds ?? DEFAULT_LIFETIMES.revocationListSeconds;

  const jwt = await signRevocationList(signer, published, { seq, ttlSeconds, now });
  await writeFile(opts.outPath, `${jwt}\n`, "utf8");
  // Only after the list is durable: a bumped counter with no list would strand the next publish
  // one sequence ahead of a list nobody has, which is harmless, whereas the reverse is not.
  await writeFile(seqPath, `${seq}\n`, "utf8");

  return {
    outPath: opts.outPath,
    seq,
    issuer: signer.did,
    expiresAt: now() + ttlSeconds,
    published,
    pruned,
  };
}
