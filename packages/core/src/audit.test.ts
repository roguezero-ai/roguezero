import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  buildAuditEvent,
  createInMemoryAuditSink,
  createJsonlAuditSink,
  newCorrelationId,
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
