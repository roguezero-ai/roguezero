import { describe, expect, it } from "vitest";
import { Hono } from "hono";
import {
  createDidKey,
  createDidWebDocument,
  createInMemoryAuditSink,
  createInMemoryNonceStore,
  createPresentation,
  createResolver,
  didWebFromHost,
  generateEd25519KeyPair,
  issueAgentCapabilityCredential,
  issueAgentProfileCredential,
  type CredentialSigner,
  type Policy,
  type RevocationChecker,
} from "@roguezero/core";
import { createHttpGuard, PRESENTATION_HEADER, type RogueZeroHonoEnv } from "./http.js";

const AUDIENCE = "https://reports.acme.example";

function credentialId(jwt: string): string {
  const segment = jwt.split(".")[1] ?? "";
  const payload = JSON.parse(Buffer.from(segment, "base64url").toString("utf8")) as { jti: string };
  return payload.jti;
}

async function harness() {
  const { publicKey: orgPub, privateKey: orgPriv } = generateEd25519KeyPair();
  const orgDid = didWebFromHost("acme.example");
  const resolver = createResolver({
    localDidWebDocuments: { [orgDid]: createDidWebDocument(orgDid, orgPub) },
  });
  const org: CredentialSigner = { did: orgDid, privateKey: orgPriv };
  const agent = createDidKey();

  const profileVc = await issueAgentProfileCredential(org, {
    id: agent.did,
    controller: orgDid,
    name: "Reporter",
  });
  const capabilityVc = await issueAgentCapabilityCredential(org, {
    id: agent.did,
    tools: [
      { name: "read_report", scopes: ["reports:read"] },
      { name: "delete_report", scopes: ["reports:delete"] },
    ],
    audience: AUDIENCE,
  });
  const capabilityId = credentialId(capabilityVc);

  const policy: Policy = {
    rules: [{ agent: agent.did, tool: "read_report", scopes: ["reports:read"], effect: "allow" }],
  };
  const auditSink = createInMemoryAuditSink();
  const nonceStore = createInMemoryNonceStore();
  const revoked = new Set<string>();
  const isRevoked: RevocationChecker = async (c) => !!c.id && revoked.has(c.id);

  const guard = createHttpGuard({
    audience: AUDIENCE,
    resolver,
    trustedIssuers: [orgDid],
    nonceStore,
    policy,
    auditSink,
    isRevoked,
  });

  const app = new Hono<RogueZeroHonoEnv>();
  app.post("/challenge", (c) => guard.issueChallenge(c));
  app.post("/reports/read", guard.protect("read_report"), (c) =>
    c.json({
      report: "Q3 revenue: up and to the right",
      agent: c.get("rogueZero").authorized.agent,
    }),
  );
  app.post("/reports/delete", guard.protect("delete_report"), (c) => c.json({ deleted: true }));

  const present = async (): Promise<string> => {
    const res = await app.request("/challenge", { method: "POST" });
    const challenge = (await res.json()) as { nonce: string };
    return createPresentation(
      { did: agent.did, privateKey: agent.privateKey },
      { profileVc, capabilityVc },
      { challenge: challenge.nonce, audience: AUDIENCE },
    );
  };
  const call = (path: string, presentation: string) =>
    app.request(path, { method: "POST", headers: { [PRESENTATION_HEADER]: presentation } });

  return { app, agent, auditSink, revoked, capabilityId, present, call };
}

describe("HTTP middleware — end-to-end round trip", () => {
  it("allows read, denies delete (policy), denies after revoke", async () => {
    const h = await harness();

    const allowed = await h.call("/reports/read", await h.present());
    expect(allowed.status).toBe(200);
    expect((await allowed.json()).agent).toBe(h.agent.did);

    const policyDenied = await h.call("/reports/delete", await h.present());
    expect(policyDenied.status).toBe(403);
    expect((await policyDenied.json()).reason).toBe("policy:default-deny");

    h.revoked.add(h.capabilityId);
    const revokedResp = await h.call("/reports/read", await h.present());
    expect(revokedResp.status).toBe(403);
    expect((await revokedResp.json()).reason).toBe("verify:revoked");

    const decisions = h.auditSink.events.map((e) => `${e.tool}:${e.decision}`);
    expect(decisions).toEqual(["read_report:allow", "delete_report:deny", "read_report:deny"]);
  });

  it("denies a missing presentation and a replayed one", async () => {
    const h = await harness();

    const noPresentation = await h.call("/reports/read", "");
    expect(noPresentation.status).toBe(403);

    const presentation = await h.present();
    const first = await h.call("/reports/read", presentation);
    expect(first.status).toBe(200);
    const replay = await h.call("/reports/read", presentation);
    expect(replay.status).toBe(403);
    expect((await replay.json()).reason).toBe("verify:nonce-replayed");
  });
});
