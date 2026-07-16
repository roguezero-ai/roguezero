/**
 * `init` and `onboard` — the two commands that remove the manual steps.
 *
 * Before these, standing up an agent meant: create two identities, read a DID off the terminal,
 * paste it into `issue profile`, paste it again into `issue capability`, then paste it a third
 * time into `policy.json`. A single typo produced a silent `policy:default-deny`, which looks
 * exactly like a working system that has decided to say no.
 *
 * `init` writes the deployment's trust settings once. `onboard` generates an agent, issues both
 * credentials, appends the matching policy rule with the DID already in place, and emits one
 * bundle file. No DID is ever typed by a human.
 *
 * `onboard` is additive: every run mints a fresh DID, so its rules cannot collide with an
 * earlier agent's. Re-onboarding a name therefore creates a *second* agent — the first one's
 * credentials keep working until revoked, which is the honest behavior for a credential system
 * (nothing silently loses access) but means `revoke` is the tool for retiring the old one.
 */

import { mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import {
  CONFIG_VERSION,
  createDidKey,
  DEFAULT_LIFETIMES,
  guardConfigSchema,
  issueAgentCapabilityCredential,
  issueAgentProfileCredential,
  loadGuardConfig,
  loadRevocationListFromFile,
  policySchema,
  revokeCredential,
  writableRevocationPath,
  type Did,
  type GuardConfig,
  type Policy,
  type ToolGrant,
} from "@roguezero/core";
import {
  BUNDLE_VERSION,
  bundleExpiry,
  bundleGrants,
  loadBundle,
  saveBundle,
  type AgentBundle,
} from "./bundle.js";
import { credentialIdFromJwt } from "./commands.js";
import { createKeystore, loadSigner, saveKeystore } from "./keystore.js";

export const CONFIG_FILENAME = "roguezero.config.json";

export interface InitResult {
  configPath: string;
  controllerPath: string;
  policyPath: string;
  revocationPath: string;
  controllerDid: Did;
}

/** Scaffold a workspace: controller identity, trust config, empty (default-deny) policy. */
export async function initCommand(opts: {
  dir: string;
  audience: string;
  controllerName?: string;
}): Promise<InitResult> {
  const dir = resolve(opts.dir);
  // Create the workspace directory if it doesn't exist — `roguezero init myruntime` is the first
  // command a new user runs, and it must not require them to `mkdir` first.
  await mkdir(dir, { recursive: true });
  const controllerPath = join(dir, opts.controllerName ?? "controller.key.json");
  const configPath = join(dir, CONFIG_FILENAME);
  const policyPath = join(dir, "policy.json");
  const revocationPath = join(dir, "revocations.json");

  const controller = createKeystore();
  await saveKeystore(controllerPath, controller);

  // A workspace holds secrets (the controller key, the sealed vault, its passphrase, agent bundles
  // that carry an agent's private key). If a user runs `init`/`quickstart` inside a git repo, none of
  // these must be committable. Write a .gitignore that excludes them by default.
  await writeFile(
    join(dir, ".gitignore"),
    ["controller.key.json", "vault.json", "vault.pass", "*.rz.json", "audit.jsonl", ""].join("\n"),
    "utf8",
  );

  await writeFile(
    configPath,
    `${JSON.stringify(
      guardConfigSchema.parse({
        version: CONFIG_VERSION,
        audience: opts.audience,
        trustedIssuers: [controller.did],
        // Relative on purpose: the whole directory is movable, and paths resolve against
        // this file rather than whatever cwd the tool happens to be spawned with.
        policy: { path: "policy.json" },
        // A local file and an unsigned list are the right defaults for one machine. Point
        // `revocation` at a signed URL to make the kill switch work across a fleet; nothing
        // else about the guard changes.
        audit: { sink: "file", path: "audit.jsonl" },
        revocation: { source: "file", path: "revocations.json" },
      }),
      null,
      2,
    )}\n`,
    "utf8",
  );

  // An empty rule list is a default-deny policy, which is the correct starting posture.
  await writeFile(policyPath, `${JSON.stringify({ rules: [] }, null, 2)}\n`, "utf8");
  await writeFile(revocationPath, `${JSON.stringify({ revoked: [] }, null, 2)}\n`, "utf8");

  return { configPath, controllerPath, policyPath, revocationPath, controllerDid: controller.did };
}

async function readPolicy(path: string): Promise<Policy> {
  try {
    return policySchema.parse(JSON.parse(await readFile(path, "utf8")));
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return { rules: [] };
    throw err;
  }
}

export interface OnboardResult {
  bundlePath: string;
  agentDid: Did;
  capabilityId: string;
  tools: ToolGrant[];
}

/**
 * Create an agent, issue its credentials, grant it exactly the tools named, and write one
 * bundle file. The policy gains an allow rule per tool, scoped to that agent's DID.
 */
export async function onboardCommand(opts: {
  name: string;
  configPath: string;
  controllerPath: string;
  tools: ToolGrant[];
  expiresInSeconds?: number;
  outPath?: string;
}): Promise<OnboardResult> {
  if (opts.tools.length === 0) {
    throw new Error("onboard requires at least one --tool (an agent with no tools cannot act)");
  }
  const config = await loadGuardConfig(opts.configPath);
  const controller = await loadSigner(opts.controllerPath);

  if (!config.trustedIssuers.includes(controller.did)) {
    throw new Error(
      `${opts.controllerPath} (${controller.did}) is not a trusted issuer in ${opts.configPath}. ` +
        `A credential it issues would be denied with reason verify:untrusted-issuer.`,
    );
  }

  const agent = createDidKey();
  const expiresInSeconds = opts.expiresInSeconds ?? DEFAULT_LIFETIMES.capabilitySeconds;

  const profileVc = await issueAgentProfileCredential(
    controller,
    { id: agent.did, controller: controller.did, name: opts.name },
    { expiresInSeconds },
  );
  const capabilityVc = await issueAgentCapabilityCredential(
    controller,
    { id: agent.did, tools: opts.tools, audience: config.audience },
    { expiresInSeconds },
  );

  const bundle: AgentBundle = {
    version: BUNDLE_VERSION,
    name: opts.name,
    did: agent.did,
    controller: controller.did,
    audience: config.audience,
    privateKey: Buffer.from(agent.privateKey).toString("base64url"),
    profileVc,
    capabilityVc,
    capabilityId: credentialIdFromJwt(capabilityVc),
    expiresAt: new Date(Date.now() + expiresInSeconds * 1000).toISOString(),
  };

  const bundlePath = resolve(
    opts.outPath ?? join(dirname(opts.configPath), `${opts.name}.rz.json`),
  );
  await saveBundle(bundlePath, bundle);

  // Policy: one allow rule per granted tool, with the DID already in place — this is the
  // copy-paste step that used to fail silently as `policy:default-deny`.
  const policyPath = config.policyPath;
  const policy = await readPolicy(policyPath);
  for (const tool of opts.tools) {
    policy.rules.push({
      agent: agent.did,
      tool: tool.name,
      scopes: tool.scopes,
      effect: "allow",
    });
  }
  await writeFile(policyPath, `${JSON.stringify(policySchema.parse(policy), null, 2)}\n`, "utf8");

  return { bundlePath, agentDid: agent.did, capabilityId: bundle.capabilityId, tools: opts.tools };
}

// --- renew --------------------------------------------------------------------------

export interface RenewResult {
  bundlePath: string;
  agentDid: Did;
  previousCapabilityId: string;
  capabilityId: string;
  expiresAt: number;
  /** Whether the superseded capability was revoked, and where — see the note below. */
  revokedPrevious: boolean;
  revocationListPath?: string;
}

/**
 * Reissue an agent's credentials in place: same DID, same private key, same grants, new expiry.
 *
 * This is *rotation*, and it runs where the controller's signing key lives — an operator's
 * machine, a CI job, a cron. It deliberately does **not** live in `connect`. An agent that can
 * mint its own capabilities cannot be killed: revocation would just be followed by a fresh
 * credential. Automatic issuance needs an authority the agent must ask, and that authority is a
 * control plane, not a proxy holding the controller key.
 *
 * Both credentials are reissued, not just the capability: a live capability behind an expired
 * AgentProfile still fails verification, so renewing one without the other renews nothing.
 *
 * The superseded capability is revoked by default. Rotation that leaves the old credential alive
 * has not reduced anything — it has doubled the number of valid credentials.
 */
export async function renewCommand(opts: {
  bundlePath: string;
  configPath: string;
  controllerPath: string;
  expiresInSeconds?: number;
  /** Leave the superseded capability valid until its own expiry. Rarely what you want. */
  keepPrevious?: boolean;
}): Promise<RenewResult> {
  const config = await loadGuardConfig(opts.configPath);
  const controller = await loadSigner(opts.controllerPath);
  const bundle = await loadBundle(opts.bundlePath);

  if (!config.trustedIssuers.includes(controller.did)) {
    throw new Error(
      `${opts.controllerPath} (${controller.did}) is not a trusted issuer in ${opts.configPath}.`,
    );
  }
  if (bundle.controller !== controller.did) {
    throw new Error(
      `${bundle.name} was issued by ${bundle.controller}, not ${controller.did}. ` +
        `Renew with the controller that issued it, or re-onboard the agent.`,
    );
  }

  // The kill-switch invariant (ADR 0004): a revoked agent must never be renewed, or renewal
  // resurrects an agent someone killed. Re-onboarding (a fresh identity) is the way back.
  if (await capabilityRevoked(config, bundle.capabilityId)) {
    throw new Error(
      `${bundle.name} has been revoked; renewing it would resurrect a killed agent. ` +
        `Re-onboard it with \`roguezero onboard\` if it should run again.`,
    );
  }

  const previousCapabilityId = bundle.capabilityId;
  const previousExpiry = bundleExpiry(bundle).expiresAt;
  const tools = bundleGrants(bundle);
  const expiresInSeconds = opts.expiresInSeconds ?? DEFAULT_LIFETIMES.capabilitySeconds;

  const profileVc = await issueAgentProfileCredential(
    controller,
    { id: bundle.did as Did, controller: controller.did, name: bundle.name },
    { expiresInSeconds },
  );
  const capabilityVc = await issueAgentCapabilityCredential(
    controller,
    { id: bundle.did as Did, tools, audience: bundle.audience },
    { expiresInSeconds },
  );

  const expiresAtMs = Date.now() + expiresInSeconds * 1000;
  await saveBundle(opts.bundlePath, {
    ...bundle,
    profileVc,
    capabilityVc,
    capabilityId: credentialIdFromJwt(capabilityVc),
    expiresAt: new Date(expiresAtMs).toISOString(),
  });

  // Retire the superseded capability. If this deployment reads revocation from somewhere we
  // cannot write, say so rather than silently leaving two live credentials.
  let revokedPrevious = false;
  const listPath = writableRevocationPath(config);
  if (!opts.keepPrevious && listPath) {
    await revokeCredential(listPath, previousCapabilityId, { expiresAt: previousExpiry });
    revokedPrevious = true;
  }

  return {
    bundlePath: opts.bundlePath,
    agentDid: bundle.did as Did,
    previousCapabilityId,
    capabilityId: credentialIdFromJwt(capabilityVc),
    expiresAt: Math.floor(expiresAtMs / 1000),
    revokedPrevious,
    revocationListPath: listPath,
  };
}

/**
 * Whether a capability id sits on the deployment's revocation list. Reads the local writable
 * list (the one `revoke` writes and the guard reads on the controller host). A url-sourced
 * deployment cannot be consulted here — that path belongs to the future control plane, not the
 * local scheduler — so it returns false and the caller decides whether that is acceptable.
 * A read failure propagates: we would rather abort a renewal than resurrect a killed agent.
 */
async function capabilityRevoked(config: GuardConfig, capabilityId: string): Promise<boolean> {
  const listPath = writableRevocationPath(config);
  if (!listPath) return false;
  return (await loadRevocationListFromFile(listPath)).has(capabilityId);
}

// --- renew --all (the controller-side scheduler) -----------------------------------

export type RenewOutcome = "renewed" | "skipped-fresh" | "skipped-revoked" | "error";

export interface RenewAllOutcome {
  name: string;
  bundlePath: string;
  outcome: RenewOutcome;
  capabilityId?: string;
  error?: string;
}

export interface RenewAllResult {
  outcomes: RenewAllOutcome[];
}

/**
 * The controller-side scheduler (ADR 0004): renew every bundle in a directory that is inside its
 * renewal window, **skipping any the operator has revoked**. This is what a cron runs. It lives
 * where the controller key lives — never on an agent — so an agent can never mint its own
 * credentials, and a killed agent is never brought back.
 *
 * A writable revocation list is required: without one the scheduler has no way to tell a killed
 * agent from a living one, so it refuses to run rather than renew blindly (fail closed).
 */
export async function renewAllCommand(opts: {
  dir: string;
  configPath: string;
  controllerPath: string;
  /** Renew a bundle when less than this many seconds of life remain. Default: ⅓ of the grant. */
  withinSeconds?: number;
  expiresInSeconds?: number;
}): Promise<RenewAllResult> {
  const config = await loadGuardConfig(opts.configPath);
  if (!writableRevocationPath(config)) {
    throw new Error(
      `renew --all needs a writable revocation list to tell a killed agent from a living one, ` +
        `but ${opts.configPath} reads revocation from a remote source. Run the scheduler where ` +
        `the list is writable, or renew agents individually with \`renew --agent\`.`,
    );
  }

  const within = opts.withinSeconds ?? Math.floor(DEFAULT_LIFETIMES.capabilitySeconds / 3);
  const now = Math.floor(Date.now() / 1000);

  const dirEntries = await readdir(opts.dir, { withFileTypes: true });
  const bundlePaths = dirEntries
    .filter((e) => e.isFile() && e.name.endsWith(".rz.json"))
    .map((e) => join(opts.dir, e.name))
    .sort();

  const outcomes: RenewAllOutcome[] = [];
  for (const bundlePath of bundlePaths) {
    let name = bundlePath;
    try {
      const bundle = await loadBundle(bundlePath);
      name = bundle.name;

      // Guard first — before the window check — so a revoked agent is never a renewal candidate.
      if (await capabilityRevoked(config, bundle.capabilityId)) {
        outcomes.push({ name, bundlePath, outcome: "skipped-revoked" });
        continue;
      }

      const { expiresAt, expired } = bundleExpiry(bundle);
      const remaining = (expiresAt ?? 0) - now;
      if (!expired && remaining > within) {
        outcomes.push({ name, bundlePath, outcome: "skipped-fresh" });
        continue;
      }

      const result = await renewCommand({
        bundlePath,
        configPath: opts.configPath,
        controllerPath: opts.controllerPath,
        expiresInSeconds: opts.expiresInSeconds,
      });
      outcomes.push({ name, bundlePath, outcome: "renewed", capabilityId: result.capabilityId });
    } catch (err) {
      outcomes.push({
        name,
        bundlePath,
        outcome: "error",
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  return { outcomes };
}
