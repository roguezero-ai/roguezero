import { afterEach, describe, expect, it, vi } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createDidKey, signRevocationList } from "@roguezero/core";
import { guardOptionsFromConfig } from "./config.js";

const dirs: string[] = [];

async function workspace(overrides: Record<string, unknown>): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "rz-mw-config-"));
  dirs.push(dir);
  await writeFile(join(dir, "policy.json"), JSON.stringify({ rules: [] }), "utf8");
  const configPath = join(dir, "roguezero.config.json");
  await writeFile(
    configPath,
    JSON.stringify({
      version: 1,
      audience: "mcp://reports.local",
      trustedIssuers: ["did:key:zPlaceholder"],
      policy: { path: "policy.json" },
      audit: { sink: "file", path: "audit.jsonl" },
      revocation: { source: "file", path: "revocations.json" },
      ...overrides,
    }),
    "utf8",
  );
  return configPath;
}

afterEach(async () => {
  vi.unstubAllGlobals();
  delete process.env.RZ_TEST_AUDIT_TOKEN;
  await Promise.all(dirs.splice(0).map((d) => rm(d, { recursive: true, force: true })));
});

describe("guardOptionsFromConfig — the control-plane seam", () => {
  it("checks revocation against a signed list served over HTTP", async () => {
    const publisher = createDidKey();
    const signed = await signRevocationList(
      { did: publisher.did, privateKey: publisher.privateKey },
      [{ id: "urn:uuid:dead" }],
      { seq: 1 },
    );
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(signed)),
    );

    const configPath = await workspace({
      trustedIssuers: [publisher.did],
      revocation: { source: "url", url: "https://revocations.example/list.jwt" },
    });

    const options = await guardOptionsFromConfig(configPath);
    expect(options.isRevoked).toBeDefined();
    // The same guard code, pointed at a fleet-wide list by configuration alone.
    expect(await options.isRevoked?.({ id: "urn:uuid:dead", issuer: publisher.did })).toBe(true);
    expect(await options.isRevoked?.({ id: "urn:uuid:live", issuer: publisher.did })).toBe(false);
  });

  it("refuses a signed list from a publisher the config does not trust", async () => {
    const attacker = createDidKey();
    const signed = await signRevocationList(
      { did: attacker.did, privateKey: attacker.privateKey },
      [],
      { seq: 1 },
    );
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(signed)),
    );

    const configPath = await workspace({
      trustedIssuers: [createDidKey().did], // someone else
      revocation: { source: "url", url: "https://revocations.example/list.jwt" },
    });

    const options = await guardOptionsFromConfig(configPath);
    await expect(options.isRevoked?.({ id: "urn:uuid:x", issuer: attacker.did })).rejects.toThrow(
      /not a trusted issuer/,
    );
  });

  it("reads the audit token from the environment, and refuses to start without it", async () => {
    const configPath = await workspace({
      audit: {
        sink: "http",
        url: "https://audit.example/events",
        authorizationEnv: "RZ_TEST_AUDIT_TOKEN",
      },
    });
    // A sink that cannot authenticate makes every decision unauditable, and an unauditable
    // decision is denied — so fail loudly at construction, not silently on every call.
    await expect(guardOptionsFromConfig(configPath)).rejects.toThrow(/RZ_TEST_AUDIT_TOKEN/);

    process.env.RZ_TEST_AUDIT_TOKEN = "Bearer s3cret";
    const options = await guardOptionsFromConfig(configPath);
    expect(options.auditSink).toBeDefined();

    // The token never appears in the file that gets committed.
    const { readFile } = await import("node:fs/promises");
    expect(await readFile(configPath, "utf8")).not.toContain("s3cret");
  });

  it("ships audit events to a remote sink, and denies the call if the sink rejects them", async () => {
    const posted: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_url: string, init: RequestInit) => {
        posted.push(String(init.body));
        return new Response(null, { status: 202 });
      }),
    );

    const configPath = await workspace({
      audit: { sink: "http", url: "https://audit.example/events" },
    });
    const options = await guardOptionsFromConfig(configPath);
    await options.auditSink.write({
      ts: "2026-07-10T00:00:00Z",
      correlationId: "c1",
      actor: "did:key:zA",
      subject: "did:key:zC",
      tool: "read_report",
      decision: "allow",
      reason: "policy:rule-0:allow",
      evidence: {},
    });
    expect(posted).toHaveLength(1);
    expect(JSON.parse(posted[0] as string)).toMatchObject({ tool: "read_report" });

    // A sink that rejects the event must throw — the pipeline turns that into a denial, because
    // an allow nobody could audit is not an allow.
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(null, { status: 500, statusText: "Boom" })),
    );
    const failing = await guardOptionsFromConfig(configPath);
    await expect(
      failing.auditSink.write({
        ts: "2026-07-10T00:00:00Z",
        correlationId: "c2",
        actor: "did:key:zA",
        subject: "did:key:zC",
        tool: "read_report",
        decision: "allow",
        reason: "policy:rule-0:allow",
        evidence: {},
      }),
    ).rejects.toThrow(/500/);
  });
});
