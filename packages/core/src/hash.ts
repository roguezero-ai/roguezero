/**
 * Hashing for audit evidence. We record hashes of credentials/nonces — never the raw
 * bearer tokens or key material — so a decision can be reconstructed later without the
 * audit log itself becoming a credential store.
 */

import { createHash } from "node:crypto";

/** SHA-256 of a string, prefixed `sha256:` so the algorithm is self-describing. */
export function sha256Hex(input: string): string {
  return `sha256:${createHash("sha256").update(input, "utf8").digest("hex")}`;
}
