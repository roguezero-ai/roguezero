/**
 * CLI command implementations, as plain async functions over `@roguezero/core` (the `bin`
 * entrypoint is a thin argv parser over these). Kept separate from argv handling so the
 * behavior is directly testable.
 *
 * The demo path uses did:key throughout, so verification resolves with the default resolver
 * and needs no hosting. did:web remains a first-class, tested core feature for the org story.
 */

import { readFile, writeFile } from "node:fs/promises";
import {
  CREDENTIAL_TYPES,
  createResolver,
  issueAgentCapabilityCredential,
  issueAgentProfileCredential,
  revokeCredential,
  verifyAgentCapabilityCredential,
  verifyAgentProfileCredential,
  verifyCredentialEnvelope,
  type AgentCapabilitySubject,
  type AgentProfileSubject,
  type Did,
  type ToolGrant,
} from "@roguezero/core";
import { createKeystore, loadSigner, saveKeystore, type Keystore } from "./keystore.js";

async function readJwt(path: string): Promise<string> {
  return (await readFile(path, "utf8")).trim();
}

/** Read a JWT VC's id (jti) from its payload without a JWT dependency. */
export function credentialIdFromJwt(jwt: string): string {
  const segment = jwt.split(".")[1] ?? "";
  const payload = JSON.parse(Buffer.from(segment, "base64url").toString("utf8")) as {
    jti?: string;
  };
  if (!payload.jti) throw new Error("credential has no id (jti)");
  return payload.jti;
}

// --- create ----------------------------------------------------------------------

export async function createCommand(opts: { outPath?: string }): Promise<Keystore> {
  const keystore = createKeystore();
  if (opts.outPath) await saveKeystore(opts.outPath, keystore);
  return keystore;
}

// --- issue -----------------------------------------------------------------------

export async function issueProfileCommand(opts: {
  issuerPath: string;
  subjectDid: Did;
  controller: Did;
  name: string;
  description?: string;
  expiresInSeconds?: number;
  outPath?: string;
}): Promise<{ jwt: string }> {
  const signer = await loadSigner(opts.issuerPath);
  const subject: AgentProfileSubject = {
    id: opts.subjectDid,
    controller: opts.controller,
    name: opts.name,
    description: opts.description,
  };
  const jwt = await issueAgentProfileCredential(signer, subject, {
    expiresInSeconds: opts.expiresInSeconds,
  });
  if (opts.outPath) await writeFile(opts.outPath, `${jwt}\n`, "utf8");
  return { jwt };
}

export async function issueCapabilityCommand(opts: {
  issuerPath: string;
  subjectDid: Did;
  audience: string;
  tools: ToolGrant[];
  expiresInSeconds?: number;
  outPath?: string;
}): Promise<{ jwt: string }> {
  const signer = await loadSigner(opts.issuerPath);
  const subject: AgentCapabilitySubject = {
    id: opts.subjectDid,
    tools: opts.tools,
    audience: opts.audience,
  };
  const jwt = await issueAgentCapabilityCredential(signer, subject, {
    expiresInSeconds: opts.expiresInSeconds,
  });
  if (opts.outPath) await writeFile(opts.outPath, `${jwt}\n`, "utf8");
  return { jwt };
}

/** Parse a `name=scope1,scope2` tool spec (scopes may themselves contain colons). */
export function parseToolSpec(spec: string): ToolGrant {
  const eq = spec.indexOf("=");
  if (eq <= 0) {
    throw new Error(`invalid --tool "${spec}"; expected name=scope1,scope2`);
  }
  const name = spec.slice(0, eq);
  const scopes = spec
    .slice(eq + 1)
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  return { name, scopes };
}

// --- verify ----------------------------------------------------------------------

export interface VerifyResult {
  type: string;
  issuer: Did;
  subject: AgentProfileSubject | AgentCapabilitySubject;
  expiresAt?: number;
}

export async function verifyCommand(opts: { jwtPath: string }): Promise<VerifyResult> {
  const jwt = await readJwt(opts.jwtPath);
  const resolver = createResolver();
  const env = await verifyCredentialEnvelope(jwt, resolver);

  if (env.types.includes(CREDENTIAL_TYPES.agentProfile)) {
    const v = await verifyAgentProfileCredential(jwt, resolver);
    return {
      type: CREDENTIAL_TYPES.agentProfile,
      issuer: v.issuer,
      subject: v.subject,
      expiresAt: v.expiresAt,
    };
  }
  if (env.types.includes(CREDENTIAL_TYPES.agentCapability)) {
    const v = await verifyAgentCapabilityCredential(jwt, resolver);
    return {
      type: CREDENTIAL_TYPES.agentCapability,
      issuer: v.issuer,
      subject: v.subject,
      expiresAt: v.expiresAt,
    };
  }
  throw new Error(`unsupported credential type: [${env.types.join(", ")}]`);
}

// --- revoke ----------------------------------------------------------------------

export async function revokeCommand(opts: {
  listPath: string;
  id?: string;
  jwtPath?: string;
}): Promise<{ revokedId: string }> {
  const id =
    opts.id ?? (opts.jwtPath ? credentialIdFromJwt(await readJwt(opts.jwtPath)) : undefined);
  if (!id) throw new Error("revoke requires --id or --jwt");
  await revokeCredential(opts.listPath, id);
  return { revokedId: id };
}

// --- inspect ---------------------------------------------------------------------

/** Decode (without verifying) a JWT's header and payload for inspection. */
export async function inspectJwtCommand(opts: { jwtPath: string }): Promise<string> {
  const jwt = await readJwt(opts.jwtPath);
  const [header, payload] = jwt.split(".");
  const decode = (seg: string | undefined) =>
    JSON.parse(Buffer.from(seg ?? "", "base64url").toString("utf8"));
  return JSON.stringify({ header: decode(header), payload: decode(payload) }, null, 2);
}

interface AuditLine {
  ts: string;
  decision: string;
  tool: string;
  actor: string;
  reason: string;
  correlationId: string;
}

/** Pretty-print an append-only JSONL audit log, one decision per line. */
export async function inspectAuditCommand(opts: { auditPath: string }): Promise<string> {
  const content = await readFile(opts.auditPath, "utf8");
  const lines = content.split("\n").filter((l) => l.trim());
  return lines
    .map((line) => {
      const e = JSON.parse(line) as AuditLine;
      return `${e.ts}  ${e.decision.toUpperCase().padEnd(5)} ${e.tool.padEnd(16)} actor=${e.actor} reason=${e.reason} cid=${e.correlationId}`;
    })
    .join("\n");
}
