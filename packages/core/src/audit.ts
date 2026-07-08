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
});

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
