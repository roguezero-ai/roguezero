/**
 * `roguezero.config.json` — a protected tool's trust settings, kept out of its code so the
 * deployment owns them: which audience this endpoint answers to, whose credentials it trusts,
 * and where policy, audit, and revocation live.
 *
 * Revocation and audit are *sources*, not paths, because the same enforcement code has to work
 * on a laptop (a JSON file next to the config) and across a fleet (a signed list on a CDN, a
 * retention endpoint). Swapping between them is a config change and nothing else — that is the
 * whole point of this file, and the reason the shapes below are discriminated unions rather
 * than optional fields.
 *
 * Two rules the schema enforces:
 *
 * - **Paths resolve against the config file**, not the working directory. A tool spawned by an
 *   MCP client inherits that client's cwd, which is nobody's idea of where the policy lives.
 * - **No secrets in this file.** It gets committed. A remote audit sink names an *environment
 *   variable* to read its authorization header from; the value never appears here.
 */

import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { z } from "zod";
import type { Did } from "./types.js";

export const CONFIG_VERSION = 1;

// --- Schema (what a human writes) -------------------------------------------------

const cacheTtlSeconds = z.number().int().nonnegative().optional();
const maxAgeSeconds = z.number().int().positive().optional();
const timeoutMs = z.number().int().positive().optional();

export const revocationSourceSchema = z.discriminatedUnion("source", [
  /** Unsigned JSON on this filesystem. The filesystem is the trust root. */
  z.object({ source: z.literal("file"), path: z.string().min(1), cacheTtlSeconds }),
  /** A signed list on this filesystem — the signed path, exercisable offline. */
  z.object({
    source: z.literal("signed-file"),
    path: z.string().min(1),
    cacheTtlSeconds,
    maxAgeSeconds,
  }),
  /** A signed list over HTTP(S). Signature, not transport, is the trust root, so it may be mirrored. */
  z.object({
    source: z.literal("url"),
    url: z.string().url(),
    cacheTtlSeconds,
    maxAgeSeconds,
    timeoutMs,
  }),
]);

export const auditSinkSchema = z.discriminatedUnion("sink", [
  z.object({ sink: z.literal("file"), path: z.string().min(1) }),
  z.object({
    sink: z.literal("http"),
    url: z.string().url(),
    timeoutMs,
    /** Name of an env var holding the `Authorization` header value. Never the value itself. */
    authorizationEnv: z.string().min(1).optional(),
  }),
]);

export const guardConfigSchema = z.object({
  version: z.literal(CONFIG_VERSION),
  /** This endpoint's audience; presentations must be bound to it. */
  audience: z.string().min(1),
  /** Credentials — and signed revocation lists — from anyone else are rejected. */
  trustedIssuers: z.array(z.string().min(1)).min(1),
  policy: z.object({ path: z.string().min(1) }),
  audit: auditSinkSchema,
  revocation: revocationSourceSchema,
});

export type GuardConfigFile = z.infer<typeof guardConfigSchema>;

// --- Resolved (what the guard consumes) -------------------------------------------

export type ResolvedRevocationSource =
  | { source: "file"; path: string; cacheTtlSeconds: number }
  | { source: "signed-file"; path: string; cacheTtlSeconds: number; maxAgeSeconds?: number }
  | {
      source: "url";
      url: string;
      cacheTtlSeconds: number;
      maxAgeSeconds?: number;
      timeoutMs?: number;
    };

export type ResolvedAuditSink =
  | { sink: "file"; path: string }
  /**
   * `authorizationEnv` stays a *name*, unresolved. Core never reads the environment: whoever
   * builds the sink resolves it, and fails there. That keeps `loadGuardConfig` pure — and it
   * means a command that only needs the revocation path (`revoke`) doesn't die because an
   * unrelated audit token happens to be unset.
   */
  | { sink: "http"; url: string; timeoutMs?: number; authorizationEnv?: string };

/** A validated config with paths made absolute and env-referenced secrets resolved. */
export interface GuardConfig {
  audience: string;
  trustedIssuers: Did[];
  policyPath: string;
  audit: ResolvedAuditSink;
  revocation: ResolvedRevocationSource;
}

/**
 * The local file a `revoke` command may write to, or `undefined` when this deployment reads
 * revocation from somewhere it cannot author (a URL). Callers should say so plainly rather
 * than writing a file nobody reads.
 */
export function writableRevocationPath(config: GuardConfig): string | undefined {
  return config.revocation.source === "url" ? undefined : config.revocation.path;
}

export async function loadGuardConfig(configPath: string): Promise<GuardConfig> {
  let raw: string;
  try {
    raw = await readFile(configPath, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      throw new Error(`No RogueZero config at ${configPath}. Create one with \`roguezero init\`.`);
    }
    throw err;
  }

  const parsed = guardConfigSchema.parse(JSON.parse(raw));
  const base = dirname(resolve(configPath));
  const abs = (p: string) => resolve(base, p);

  const revocation: ResolvedRevocationSource =
    parsed.revocation.source === "url"
      ? {
          source: "url",
          url: parsed.revocation.url,
          cacheTtlSeconds: parsed.revocation.cacheTtlSeconds ?? 0,
          maxAgeSeconds: parsed.revocation.maxAgeSeconds,
          timeoutMs: parsed.revocation.timeoutMs,
        }
      : parsed.revocation.source === "signed-file"
        ? {
            source: "signed-file",
            path: abs(parsed.revocation.path),
            cacheTtlSeconds: parsed.revocation.cacheTtlSeconds ?? 0,
            maxAgeSeconds: parsed.revocation.maxAgeSeconds,
          }
        : {
            source: "file",
            path: abs(parsed.revocation.path),
            cacheTtlSeconds: parsed.revocation.cacheTtlSeconds ?? 0,
          };

  const audit: ResolvedAuditSink =
    parsed.audit.sink === "http"
      ? {
          sink: "http",
          url: parsed.audit.url,
          timeoutMs: parsed.audit.timeoutMs,
          authorizationEnv: parsed.audit.authorizationEnv,
        }
      : { sink: "file", path: abs(parsed.audit.path) };

  return {
    audience: parsed.audience,
    trustedIssuers: parsed.trustedIssuers as Did[],
    policyPath: abs(parsed.policy.path),
    audit,
    revocation,
  };
}
