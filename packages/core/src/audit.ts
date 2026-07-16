/**
 * Audit: an append-only record of every decision, with enough evidence to reconstruct it
 * later — actor, subject, tool, decision, reason, credential/nonce hashes, timestamp, and a
 * correlation id linking challenge → call → decision.
 *
 * Evidence carries hashes/ids only, never raw credentials or key material (the hashing is
 * done upstream in the pipeline). Events are validated against a schema before they are
 * written, so a malformed event is caught at the boundary rather than corrupting the log.
 * The JSONL sink appends; it never rewrites history.
 */

import { appendFile } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { z } from "zod";
import type { AuditEvent, Decision, Did } from "./types.js";

export const auditEventSchema = z.object({
  ts: z.string(),
  correlationId: z.string(),
  actor: z.string(),
  subject: z.string(),
  tool: z.string(),
  decision: z.enum(["allow", "deny"]),
  reason: z.string(),
  evidence: z.object({
    profileVc: z.string().optional(),
    capabilityVc: z.string().optional(),
    nonce: z.string().optional(),
    presentation: z.string().optional(),
  }),
  attempt: z
    .object({
      args: z.record(z.string(), z.unknown()).optional(),
      target: z.object({ method: z.string(), url: z.string() }).optional(),
      truncated: z.boolean().optional(),
    })
    .optional(),
});

/**
 * Largest serialized `attempt.args` we keep. A denied/attacking agent controls the arguments, so
 * an unbounded copy would let it bloat the log; past the cap we drop the args and flag `truncated`.
 */
export const MAX_ATTEMPT_ARGS_BYTES = 4096;

/**
 * Build the `attempt` record from agent-supplied inputs — never the credential (decrypted later) nor
 * an Authorization header (the caller passes only method+url). Over-cap args are dropped, not stored.
 */
export function summarizeAttempt(input: {
  args?: Record<string, unknown>;
  target?: { method: string; url: string };
}): AuditEvent["attempt"] | undefined {
  const attempt: NonNullable<AuditEvent["attempt"]> = {};
  if (input.target) attempt.target = { method: input.target.method, url: input.target.url };
  if (input.args && Object.keys(input.args).length > 0) {
    let serialized = "";
    try {
      serialized = JSON.stringify(input.args);
    } catch {
      serialized = "";
    }
    if (serialized && Buffer.byteLength(serialized, "utf8") <= MAX_ATTEMPT_ARGS_BYTES) {
      attempt.args = input.args;
    } else {
      attempt.truncated = true;
    }
  }
  return attempt.args || attempt.target || attempt.truncated ? attempt : undefined;
}

/** A fresh correlation id linking the challenge, the call, and the decision. */
export function newCorrelationId(): string {
  return randomUUID();
}

export interface AuditEventInput {
  actor: Did;
  subject: Did;
  tool: string;
  decision: Decision;
  reason: string;
  evidence?: AuditEvent["evidence"];
  /** What the agent tried (args/target) — pass through `summarizeAttempt` for the size cap. */
  attempt?: AuditEvent["attempt"];
  correlationId?: string;
  /** Override timestamp (ISO 8601); defaults to now. */
  ts?: string;
}

/** Build a validated AuditEvent, filling timestamp and correlation id if omitted. */
export function buildAuditEvent(input: AuditEventInput): AuditEvent {
  return auditEventSchema.parse({
    ts: input.ts ?? new Date().toISOString(),
    correlationId: input.correlationId ?? newCorrelationId(),
    actor: input.actor,
    subject: input.subject,
    tool: input.tool,
    decision: input.decision,
    reason: input.reason,
    evidence: input.evidence ?? {},
    attempt: input.attempt,
  });
}

export interface AuditSink {
  write(event: AuditEvent): Promise<void>;
}

/** Append-only JSONL sink: one validated event per line. */
export function createJsonlAuditSink(path: string): AuditSink {
  return {
    async write(event) {
      const valid = auditEventSchema.parse(event);
      await appendFile(path, `${JSON.stringify(valid)}\n`, "utf8");
    },
  };
}

/** Default timeout for shipping an audit event to a remote sink (ms). */
export const DEFAULT_AUDIT_TIMEOUT_MS = 3000;

export interface HttpAuditSinkOptions {
  url: string;
  timeoutMs?: number;
  /** Sent as the `Authorization` header. Read from the environment, never from a config file. */
  authorization?: string;
}

/**
 * Ship each decision to an HTTP endpoint (audit retention, a SIEM, a collector).
 *
 * One request per decision, and a failed request throws — which the pipeline turns into an
 * `audit-write-failed` deny. That is deliberate: batching would mean buffering, and a buffered
 * event is an *allow that was never audited*. Correctness over throughput here; a deployment
 * that needs throughput puts a local collector on the box and ships from there.
 */
export function createHttpAuditSink(options: HttpAuditSinkOptions): AuditSink {
  const timeoutMs = options.timeoutMs ?? DEFAULT_AUDIT_TIMEOUT_MS;
  return {
    async write(event) {
      const valid = auditEventSchema.parse(event);
      const response = await fetch(options.url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          ...(options.authorization ? { authorization: options.authorization } : {}),
        },
        body: JSON.stringify(valid),
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (!response.ok) {
        throw new Error(`audit sink rejected event: ${response.status} ${response.statusText}`);
      }
    },
  };
}

/** In-memory sink for tests and single-process inspection. */
export function createInMemoryAuditSink(): AuditSink & { events: AuditEvent[] } {
  const events: AuditEvent[] = [];
  return {
    events,
    async write(event) {
      events.push(auditEventSchema.parse(event));
    },
  };
}
