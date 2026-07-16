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
  loadRevocationListFromFile,
  revokeCredential,
  verifyAgentCapabilityCredential,
  verifyAgentProfileCredential,
  verifyCredentialEnvelope,
  type AgentCapabilitySubject,
  type AgentProfileSubject,
  type Did,
  type ToolGrant,
} from "@roguezero/core";
import { loadBundle } from "./bundle.js";
import { createKeystore, loadSigner, saveKeystore, type Keystore } from "./keystore.js";

async function readJwt(path: string): Promise<string> {
  return (await readFile(path, "utf8")).trim();
}

function decodeJwtPayload(jwt: string): { jti?: string; exp?: number } {
  const segment = jwt.split(".")[1] ?? "";
  return JSON.parse(Buffer.from(segment, "base64url").toString("utf8")) as {
    jti?: string;
    exp?: number;
  };
}

/** Read a JWT VC's id (jti) from its payload without a JWT dependency. */
export function credentialIdFromJwt(jwt: string): string {
  const jti = decodeJwtPayload(jwt).jti;
  if (!jti) throw new Error("credential has no id (jti)");
  return jti;
}

/** Read a JWT VC's own expiry (unix seconds), if it has one. */
export function credentialExpiryFromJwt(jwt: string): number | undefined {
  return decodeJwtPayload(jwt).exp;
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
  /** `undefined` when no revocation list was supplied — the check did not run. */
  revoked?: boolean;
}

/**
 * Verify a credential offline. Revocation is only checked when a list is supplied: the guard
 * always checks it at request time, but `verify` has no way to guess where the list lives, and
 * silently reporting `OK` for a revoked credential would be a lie. When no list is given the
 * caller is told the check was skipped rather than left to assume it passed.
 */
export async function verifyCommand(opts: {
  jwtPath: string;
  revocationsPath?: string;
}): Promise<VerifyResult> {
  const jwt = await readJwt(opts.jwtPath);
  const resolver = createResolver();
  const env = await verifyCredentialEnvelope(jwt, resolver);

  const checkRevoked = async (): Promise<boolean | undefined> => {
    if (!opts.revocationsPath) return undefined;
    const revoked = await loadRevocationListFromFile(opts.revocationsPath);
    return revoked.has(credentialIdFromJwt(jwt));
  };

  if (env.types.includes(CREDENTIAL_TYPES.agentProfile)) {
    const v = await verifyAgentProfileCredential(jwt, resolver);
    return {
      type: CREDENTIAL_TYPES.agentProfile,
      issuer: v.issuer,
      subject: v.subject,
      expiresAt: v.expiresAt,
      revoked: await checkRevoked(),
    };
  }
  if (env.types.includes(CREDENTIAL_TYPES.agentCapability)) {
    const v = await verifyAgentCapabilityCredential(jwt, resolver);
    return {
      type: CREDENTIAL_TYPES.agentCapability,
      issuer: v.issuer,
      subject: v.subject,
      expiresAt: v.expiresAt,
      revoked: await checkRevoked(),
    };
  }
  throw new Error(`unsupported credential type: [${env.types.join(", ")}]`);
}

// --- revoke ----------------------------------------------------------------------

export async function revokeCommand(opts: {
  listPath: string;
  id?: string;
  jwtPath?: string;
  /** An agent bundle; its `capabilityId` is revoked. The kill switch, by name. */
  bundlePath?: string;
}): Promise<{ revokedId: string }> {
  let id = opts.id;
  // The credential's own expiry, recorded so a publisher can prune the entry once the
  // credential could no longer be presented anyway. Only known when we can see the credential.
  let expiresAt: number | undefined;

  if (!id && opts.jwtPath) {
    const jwt = await readJwt(opts.jwtPath);
    id = credentialIdFromJwt(jwt);
    expiresAt = credentialExpiryFromJwt(jwt);
  }
  if (!id && opts.bundlePath) {
    const bundle = await loadBundle(opts.bundlePath);
    id = bundle.capabilityId;
    expiresAt = credentialExpiryFromJwt(bundle.capabilityVc);
  }
  if (!id) throw new Error("revoke requires --agent, --jwt, or --id");
  await revokeCredential(opts.listPath, id, { expiresAt });
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

/**
 * Decode (without verifying) a signed revocation list, and say plainly whether a verifier would
 * still accept it. Staleness is the failure operators will actually hit — the publisher stopped
 * re-signing — so lead with it.
 */
export async function inspectRevocationsCommand(opts: { path: string }): Promise<string> {
  const jwt = (await readFile(opts.path, "utf8")).trim();
  const segment = jwt.split(".")[1] ?? "";
  const payload = JSON.parse(Buffer.from(segment, "base64url").toString("utf8")) as {
    iss?: string;
    seq?: number;
    iat?: number;
    exp?: number;
    revoked?: Array<{ id: string; expiresAt?: number }>;
  };
  if (payload.exp === undefined || payload.seq === undefined) {
    throw new Error(`${opts.path} is not a signed RogueZero revocation list.`);
  }

  const now = Math.floor(Date.now() / 1000);
  const remaining = payload.exp - now;
  const freshness =
    remaining > 0
      ? `fresh for another ${remaining}s`
      : `STALE by ${-remaining}s — verifiers are denying every call; re-publish`;

  const entries = payload.revoked ?? [];
  const lines = [
    `signed revocation list  ${opts.path}`,
    `  issuer:  ${payload.iss ?? "(none)"}`,
    `  seq:     ${payload.seq}`,
    `  issued:  ${payload.iat ? new Date(payload.iat * 1000).toISOString() : "(none)"}`,
    `  expires: ${new Date(payload.exp * 1000).toISOString()}  (${freshness})`,
    `  revoked: ${entries.length} credential${entries.length === 1 ? "" : "s"}`,
  ];
  for (const entry of entries) {
    const expiry = entry.expiresAt
      ? ` (credential expires ${new Date(entry.expiresAt * 1000).toISOString()})`
      : "";
    lines.push(`    ${entry.id}${expiry}`);
  }
  return lines.join("\n");
}

interface AuditLine {
  ts: string;
  decision: string;
  tool: string;
  actor: string;
  reason: string;
  correlationId: string;
  attempt?: {
    args?: Record<string, unknown>;
    target?: { method: string; url: string };
    truncated?: boolean;
  };
}

/** Pretty-print an append-only JSONL audit log, one decision per line. */
export async function inspectAuditCommand(opts: { auditPath: string }): Promise<string> {
  let content: string;
  try {
    content = await readFile(opts.auditPath, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      throw new Error(
        `No audit log at ${opts.auditPath}. Audit events are written by a protected tool ` +
          `when it handles a call — run \`pnpm demo\` (or point a middleware guard at this ` +
          `path) to generate one, then inspect it.`,
      );
    }
    throw err;
  }
  const lines = content.split("\n").filter((l) => l.trim());
  if (lines.length === 0) return `(no audit events in ${opts.auditPath})`;
  return lines
    .map((line) => {
      const e = JSON.parse(line) as AuditLine;
      const head = `${e.ts}  ${e.decision.toUpperCase().padEnd(5)} ${e.tool.padEnd(16)} actor=${e.actor} reason=${e.reason} cid=${e.correlationId}`;
      // Show what the agent tried, so a denied call reads as "blocked from doing X", not just "denied".
      const a = e.attempt;
      if (!a) return head;
      const detail: string[] = [];
      if (a.target) detail.push(`${a.target.method} ${a.target.url}`);
      if (a.args) detail.push(`args=${JSON.stringify(a.args)}`);
      else if (a.truncated) detail.push("args=(omitted — exceeded audit size cap)");
      return detail.length > 0 ? `${head}\n         ↳ attempted: ${detail.join("  ")}` : head;
    })
    .join("\n");
}
