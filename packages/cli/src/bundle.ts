/**
 * The agent bundle (`<name>.rz.json`): everything one agent needs to prove who it is, in a
 * single file it can mount. Deliberately the shape platform engineers already know — a
 * kubeconfig, a service-account key — so the deployment story needs no explanation.
 *
 * It carries a private key, so it is written `0600` and belongs wherever that team already
 * puts secrets. The two credentials ride along because a presentation needs both, and making
 * the operator marshal them separately is the copy-paste class of error `onboard` exists to
 * delete.
 *
 * `capabilityId` is denormalized from the capability JWT on purpose: revoking an agent should
 * not require decoding a JWT to find out what to revoke.
 */

import { readFile, writeFile } from "node:fs/promises";
import { z } from "zod";
import type { CredentialSigner, Did, ToolGrant } from "@roguezero/core";

export const BUNDLE_VERSION = 1;

export const agentBundleSchema = z.object({
  version: z.literal(BUNDLE_VERSION),
  name: z.string().min(1),
  /** The agent's own DID (the presentation holder). */
  did: z.string().min(1),
  /** The operator that issued this agent's credentials. */
  controller: z.string().min(1),
  /** The one tool endpoint these credentials are bound to. */
  audience: z.string().min(1),
  /** Ed25519 private key seed, base64url. SECRET. */
  privateKey: z.string().min(1),
  profileVc: z.string().min(1),
  capabilityVc: z.string().min(1),
  /** The capability credential's `jti`, so `revoke --agent` needs no JWT decoding. */
  capabilityId: z.string().min(1),
  /** Capability expiry, ISO 8601 — informational; the guard enforces the JWT's own `exp`. */
  expiresAt: z.string().optional(),
});

export type AgentBundle = z.infer<typeof agentBundleSchema>;

export async function saveBundle(path: string, bundle: AgentBundle): Promise<void> {
  await writeFile(path, `${JSON.stringify(agentBundleSchema.parse(bundle), null, 2)}\n`, {
    encoding: "utf8",
    mode: 0o600,
  });
}

export async function loadBundle(path: string): Promise<AgentBundle> {
  let raw: string;
  try {
    raw = await readFile(path, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      throw new Error(`No agent bundle at ${path}. Create one with \`roguezero onboard\`.`);
    }
    throw err;
  }
  return agentBundleSchema.parse(JSON.parse(raw));
}

/** The bundle's agent identity, as a signer for presentations. */
export function bundleSigner(bundle: AgentBundle): CredentialSigner {
  return {
    did: bundle.did as Did,
    privateKey: new Uint8Array(Buffer.from(bundle.privateKey, "base64url")),
  };
}

/** The tools this bundle's capability grants — read back out so `renew` reissues the same ones. */
export function bundleGrants(bundle: AgentBundle): ToolGrant[] {
  const segment = bundle.capabilityVc.split(".")[1] ?? "";
  const payload = JSON.parse(Buffer.from(segment, "base64url").toString("utf8")) as {
    vc?: { credentialSubject?: { tools?: ToolGrant[] } };
  };
  const tools = payload.vc?.credentialSubject?.tools;
  if (!tools?.length) {
    throw new Error(`${bundle.name}'s capability grants no tools; re-run \`roguezero onboard\`.`);
  }
  return tools;
}

/** Whether a bundle's capability has expired (unix seconds), and when. */
export function bundleExpiry(bundle: AgentBundle): { expiresAt?: number; expired: boolean } {
  const segment = bundle.capabilityVc.split(".")[1] ?? "";
  const { exp } = JSON.parse(Buffer.from(segment, "base64url").toString("utf8")) as {
    exp?: number;
  };
  return { expiresAt: exp, expired: exp !== undefined && exp <= Math.floor(Date.now() / 1000) };
}
