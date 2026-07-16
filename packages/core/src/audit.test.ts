import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  buildAuditEvent,
  createInMemoryAuditSink,
  createJsonlAuditSink,
  MAX_ATTEMPT_ARGS_BYTES,
  newCorrelationId,
  summarizeAttempt,
} from "./audit.js";
import type { AuditEvent } from "./types.js";

const tmpDirs: string[] = [];
async function tempFile(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "rz-audit-"));
  tmpDirs.push(dir);
  return join(dir, "audit.jsonl");
}
afterEach(async () => {
  await Promise.all(tmpDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

const baseInput = {
  actor: "did:key:z6MkAgent",
  subject: "did:web:acme.example",
  tool: "read_report",
  decision: "allow" as const,
  reason: "policy:rule-0:allow",
  evidence: { capabilityVc: "sha256:abc", nonce: "sha256:def" },
};

describe("buildAuditEvent", () => {
  it("fills timestamp and correlation id when omitted", () => {
    const event = buildAuditEvent(baseInput);
    expect(event.ts).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(event.correlationId).toBeTruthy();
    expect(event.decision).toBe("allow");
  });

  it("preserves a supplied correlation id (linking challenge->call->decision)", () => {
    const correlationId = newCorrelationId();
    const event = buildAuditEvent({ ...baseInput, correlationId });
    expect(event.correlationId).toBe(correlationId);
  });

  it("rejects an invalid decision at the boundary", () => {
    expect(() =>
      buildAuditEvent({ ...baseInput, decision: "maybe" as unknown as "allow" }),
    ).toThrow();
  });
});

describe("summarizeAttempt (what the agent tried, bounded)", () => {
  it("keeps small args and the resolved target", () => {
    const attempt = summarizeAttempt({
      args: { title: "hi", body: "world" },
      target: { method: "POST", url: "https://api.github.com/repos/o/r/issues" },
    });
    expect(attempt?.args).toEqual({ title: "hi", body: "world" });
    expect(attempt?.target).toEqual({
      method: "POST",
      url: "https://api.github.com/repos/o/r/issues",
    });
    expect(attempt?.truncated).toBeUndefined();
  });

  it("drops over-cap args and flags truncated, so a huge arg can't bloat the log", () => {
    const attempt = summarizeAttempt({ args: { blob: "x".repeat(MAX_ATTEMPT_ARGS_BYTES + 1) } });
    expect(attempt?.args).toBeUndefined();
    expect(attempt?.truncated).toBe(true);
  });

  it("returns undefined when there is nothing to record (no args, no target)", () => {
    expect(summarizeAttempt({ args: {} })).toBeUndefined();
    expect(summarizeAttempt({})).toBeUndefined();
  });

  it("survives the schema round-trip inside a built event", () => {
    const event = buildAuditEvent({
      ...baseInput,
      attempt: summarizeAttempt({
        args: { q: "find" },
        target: { method: "GET", url: "https://x/y" },
      }),
    });
    expect(event.attempt?.args).toEqual({ q: "find" });
    expect(event.attempt?.target?.method).toBe("GET");
  });
});

describe("JSONL audit sink (append-only)", () => {
  it("appends one validated JSON event per line, in order", async () => {
    const path = await tempFile();
    const sink = createJsonlAuditSink(path);

    await sink.write(buildAuditEvent(baseInput));
    await sink.write(
      buildAuditEvent({
        ...baseInput,
        tool: "delete_report",
        decision: "deny",
        reason: "policy:default-deny",
      }),
    );

    const lines = (await readFile(path, "utf8")).trim().split("\n");
    expect(lines).toHaveLength(2);
    const parsed = lines.map((l) => JSON.parse(l) as AuditEvent);
    expect(parsed[0]?.tool).toBe("read_report");
    expect(parsed[1]?.decision).toBe("deny");
  });
});

describe("in-memory audit sink", () => {
  it("collects validated events", async () => {
    const sink = createInMemoryAuditSink();
    await sink.write(buildAuditEvent(baseInput));
    expect(sink.events).toHaveLength(1);
    expect(sink.events[0]?.actor).toBe("did:key:z6MkAgent");
  });
});
