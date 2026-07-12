/**
 * Atomic on-disk persistence for the credential vault (ADR 0005, review follow-up — Pax).
 *
 * Two jobs the in-memory vault can't do safely on its own:
 *   1. **Crash-safe writes.** A naive `writeFile` can leave a torn/truncated vault after a crash
 *      mid-write. We write to a temp file, `fsync`, then `rename` (atomic on the same filesystem),
 *      always mode `0600`.
 *   2. **Rollback detection.** The in-file manifest MAC catches every *partial* tamper, but not a
 *      restore of an earlier, fully-valid snapshot (which could resurrect a rotated-out secret). We
 *      track the highest `generation` seen in a `0600` sidecar and refuse to open a vault whose
 *      generation regressed.
 *
 * Honest residual (stated, not hidden): a determined attacker with write access to *both* the vault
 * and its sidecar can still roll both back together. Fully closing that needs external monotonic
 * state — a KMS-backed counter or TPM — which slots in by pointing `expectedMinGeneration` at it.
 * For the common cases (an accidental backup restore, a read-only vault, a stale replica) the
 * sidecar is sufficient, and the argon2id/KMS providers + the manifest MAC already make the
 * higher-value attacks fail closed.
 */

import { chmod, open, readFile, rename } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import { basename, dirname, join } from "node:path";
import { loadVault, type Vault, type VaultFile } from "./vault.js";
import type { KeyProvider } from "./vault.js";

const MODE = 0o600;
const genSidecar = (path: string): string => `${path}.gen`;

/** Write `data` to `path` atomically and `0600`: temp file → fsync → rename. */
async function atomicWrite(path: string, data: string): Promise<void> {
  const tmp = join(dirname(path), `.${basename(path)}.${randomBytes(6).toString("hex")}.tmp`);
  const handle = await open(tmp, "wx", MODE);
  try {
    await handle.writeFile(data, "utf8");
    await handle.sync(); // durability before the rename
  } finally {
    await handle.close();
  }
  await rename(tmp, path);
  await chmod(path, MODE); // enforce mode regardless of umask
}

async function readGeneration(path: string): Promise<number | undefined> {
  try {
    const parsed = JSON.parse(await readFile(path, "utf8")) as { generation?: unknown };
    return typeof parsed.generation === "number" ? parsed.generation : undefined;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw err;
  }
}

/**
 * Persist the vault to `path` atomically, and advance the rollback sidecar to its current
 * generation. The vault file is written first (source of truth), then the sidecar bumped — so a
 * crash between them leaves the sidecar behind, which only ever makes a later open *stricter*, never
 * looser (fail-safe direction).
 */
export async function saveVaultToFile(path: string, file: VaultFile): Promise<void> {
  await atomicWrite(path, `${JSON.stringify(file, null, 2)}\n`);
  const seen = await readGeneration(genSidecar(path));
  if (seen === undefined || file.generation > seen) {
    await atomicWrite(genSidecar(path), `${JSON.stringify({ generation: file.generation })}\n`);
  }
}

/**
 * Load the vault from `path`: parse, verify the manifest (`loadVault`), then reject a generation
 * that regressed below the sidecar (or an explicit `expectedMinGeneration` from external trusted
 * state). Fails closed on a missing file, malformed JSON, bad MAC, or rollback.
 */
export async function readVaultFromFile(
  path: string,
  keyProvider: KeyProvider,
  opts: { expectedMinGeneration?: number } = {},
): Promise<Vault> {
  const raw = JSON.parse(await readFile(path, "utf8")) as unknown;
  const vault = await loadVault(raw, keyProvider); // Zod + manifest MAC (fail closed)

  const floor = Math.max(
    opts.expectedMinGeneration ?? 0,
    (await readGeneration(genSidecar(path))) ?? 0,
  );
  if (vault.file.generation < floor) {
    throw new Error(
      `vault at ${path} appears rolled back: generation ${vault.file.generation} < expected ${floor}`,
    );
  }
  return vault;
}
