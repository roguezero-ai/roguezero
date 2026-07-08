import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createCommand,
  credentialIdFromJwt,
  inspectAuditCommand,
  inspectJwtCommand,
  issueCapabilityCommand,
  issueProfileCommand,
  parseToolSpec,
  revokeCommand,
  verifyCommand,
} from "./commands.js";

let dir = "";
async function tmp(name: string): Promise<string> {
  if (!dir) dir = await mkdtemp(join(tmpdir(), "rz-cli-"));
  return join(dir, name);
}
afterEach(async () => {
  if (dir) await rm(dir, { recursive: true, force: true });
  dir = "";
});

describe("parseToolSpec", () => {
  it("parses name=scopes with colon-bearing scopes", () => {
    expect(parseToolSpec("read_report=reports:read,reports:list")).toEqual({
      name: "read_report",
      scopes: ["reports:read", "reports:list"],
    });
  });

  it("rejects a spec without an '='", () => {
    expect(() => parseToolSpec("read_report")).toThrow();
  });
});

describe("CLI golden path (create → issue → verify → revoke)", () => {
  it("creates identities, issues + verifies both credential types, then revokes", async () => {
    // create controller + agent identities
    const controllerPath = await tmp("controller.key.json");
    const agentPath = await tmp("agent.key.json");
    const controller = await createCommand({ outPath: controllerPath });
    const agent = await createCommand({ outPath: agentPath });
    expect(controller.did.startsWith("did:key:")).toBe(true);
    expect(agent.did.startsWith("did:key:")).toBe(true);

    // issue AgentProfile (controller issues, about the agent)
    const profilePath = await tmp("profile.jwt");
    await issueProfileCommand({
      issuerPath: controllerPath,
      subjectDid: agent.did,
      controller: controller.did,
      name: "Reporter",
      outPath: profilePath,
    });

    // issue AgentCapability
    const capPath = await tmp("capability.jwt");
    await issueCapabilityCommand({
      issuerPath: controllerPath,
      subjectDid: agent.did,
      audience: "mcp://reports.acme.example",
      tools: [parseToolSpec("read_report=reports:read")],
      outPath: capPath,
    });

    // verify both
    const profileResult = await verifyCommand({ jwtPath: profilePath });
    expect(profileResult.type).toBe("AgentProfile");
    expect(profileResult.issuer).toBe(controller.did);
    expect(profileResult.subject.id).toBe(agent.did);

    const capResult = await verifyCommand({ jwtPath: capPath });
    expect(capResult.type).toBe("AgentCapability");
    expect(capResult.subject.id).toBe(agent.did);

    // revoke the capability by file; the id lands in the list
    const listPath = await tmp("revocations.json");
    const capJwt = (await readFile(capPath, "utf8")).trim();
    const { revokedId } = await revokeCommand({ listPath, jwtPath: capPath });
    expect(revokedId).toBe(credentialIdFromJwt(capJwt));
    const list = JSON.parse(await readFile(listPath, "utf8")) as { revoked: string[] };
    expect(list.revoked).toContain(revokedId);
  });
});

describe("inspect", () => {
  it("decodes a JWT's header and payload", async () => {
    const issuerPath = await tmp("issuer.key.json");
    const issuer = await createCommand({ outPath: issuerPath });
    const capPath = await tmp("cap.jwt");
    await issueCapabilityCommand({
      issuerPath,
      subjectDid: issuer.did,
      audience: "mcp://x",
      tools: [parseToolSpec("t=a:read")],
      outPath: capPath,
    });
    const out = await inspectJwtCommand({ jwtPath: capPath });
    expect(out).toContain("AgentCapability");
    expect(out).toContain('"alg": "EdDSA"');
  });

  it("pretty-prints an append-only audit log", async () => {
    const auditPath = await tmp("audit.jsonl");
    const events = [
      {
        ts: "2026-07-07T10:00:00Z",
        correlationId: "c1",
        actor: "did:key:zAgent",
        subject: "did:key:zCtl",
        tool: "read_report",
        decision: "allow",
        reason: "policy:rule-0:allow",
        evidence: {},
      },
      {
        ts: "2026-07-07T10:00:01Z",
        correlationId: "c2",
        actor: "did:key:zAgent",
        subject: "did:key:zCtl",
        tool: "delete_report",
        decision: "deny",
        reason: "policy:default-deny",
        evidence: {},
      },
    ];
    await writeFile(auditPath, events.map((e) => JSON.stringify(e)).join("\n") + "\n", "utf8");
    const out = await inspectAuditCommand({ auditPath });
    expect(out).toContain("ALLOW read_report");
    expect(out).toContain("DENY  delete_report");
    expect(out).toContain("reason=policy:default-deny");
  });
});
