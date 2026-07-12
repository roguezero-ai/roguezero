/**
 * Runtime operator commands: scaffold a runtime, register tools, store their credentials in the
 * vault, and serve them. This is the "self-host in <15 min" path — one workspace, four verbs:
 *
 *   roguezero runtime init <dir> --audience <aud>     controller + config + policy + registry + vault
 *   roguezero runtime tool add <id> --url <u> ...      pin a tool; agents name it, never a URL
 *   roguezero runtime secret set --tool <id> --ref <r> store the tool's downstream credential (vault)
 *   roguezero runtime serve                            expose the tools over HTTP (createRuntimeServer)
 *
 * The vault passphrase comes from `RZ_VAULT_PASSPHRASE` (env), never argv. Credentials go in via env
 * or stdin, never argv — a secret in shell history is a leak.
 */

import { readFile, writeFile } from "node:fs/promises";
import type { Server } from "node:http";
import { dirname, join, resolve } from "node:path";
import {
  argon2idKeyProvider,
  ARGON2ID_DEFAULT,
  createFileRevocationChecker,
  createInMemoryNonceStore,
  createJsonlAuditSink,
  createResolver,
  createVault,
  loadGuardConfig,
  parseToolRegistry,
  policySchema,
  putCredential,
  readVaultFromFile,
  saveVaultToFile,
  writableRevocationPath,
  type Argon2idParams,
  type Policy,
} from "@roguezero/core";
import { initCommand } from "./workspace.js";
import { getIntegration, listIntegrations } from "./integrations.js";
import { createRuntimeServer, type RuntimeServerOptions } from "./runtime-server.js";

const REGISTRY_FILE = "registry.json";
const VAULT_FILE = "vault.json";

const registryPathFor = (configPath: string): string =>
  join(dirname(resolve(configPath)), REGISTRY_FILE);
const vaultPathFor = (configPath: string): string => join(dirname(resolve(configPath)), VAULT_FILE);

/** A tool as the CLI accepts it. Full definitions (params, etc.) can be edited in registry.json. */
export interface ToolInput {
  id: string;
  method: string;
  url: string; // https://host[:port]/path
  credentialRef: string;
  placement?: "bearer" | "basic" | "header";
  header?: string;
  internal?: boolean;
}

function toolFromInput(t: ToolInput): Record<string, unknown> {
  const u = new URL(t.url);
  return {
    id: t.id,
    method: t.method.toUpperCase(),
    scheme: u.protocol.replace(":", ""),
    host: u.hostname,
    ...(u.port ? { port: Number(u.port) } : {}),
    path: u.pathname || "/",
    ...(u.search ? { query: Object.fromEntries(u.searchParams) } : {}),
    credential: {
      ref: t.credentialRef,
      placement: t.placement ?? "bearer",
      ...(t.header ? { header: t.header } : {}),
    },
    ...(t.internal ? { internal: true } : {}),
  };
}

export interface RuntimeInitResult {
  configPath: string;
  controllerPath: string;
  controllerDid: string;
  registryPath: string;
  vaultPath: string;
}

/** Scaffold a runtime workspace: the identity/config/policy base, an empty registry, and a sealed vault. */
export async function runtimeInitCommand(opts: {
  dir: string;
  audience: string;
  passphrase: string;
  /** argon2id cost for sealing the vault; the blob records it, so opens stay fast regardless. */
  argonParams?: Argon2idParams;
}): Promise<RuntimeInitResult> {
  const base = await initCommand({ dir: opts.dir, audience: opts.audience });
  const dir = resolve(opts.dir);

  const registryPath = join(dir, REGISTRY_FILE);
  await writeFile(registryPath, `${JSON.stringify({ tools: [] }, null, 2)}\n`, "utf8");

  const vaultPath = join(dir, VAULT_FILE);
  const vault = await createVault(
    argon2idKeyProvider(opts.passphrase, opts.argonParams ?? ARGON2ID_DEFAULT),
  );
  await saveVaultToFile(vaultPath, vault.file);

  return {
    configPath: base.configPath,
    controllerPath: base.controllerPath,
    controllerDid: base.controllerDid,
    registryPath,
    vaultPath,
  };
}

/** Register a tool. Validated as part of the whole registry (rejects bad defs, dup ids, http-not-internal). */
export async function toolAddCommand(opts: { configPath: string; tool: ToolInput }): Promise<void> {
  const registryPath = registryPathFor(opts.configPath);
  const raw = JSON.parse(await readFile(registryPath, "utf8")) as { tools: unknown[] };
  raw.tools.push(toolFromInput(opts.tool));
  parseToolRegistry(raw); // throws on any invalid/colliding definition before we write
  await writeFile(registryPath, `${JSON.stringify(raw, null, 2)}\n`, "utf8");
}

export interface AddIntegrationResult {
  integration: string;
  addedTools: string[];
  /** True when the credential was supplied and stored; false when the user must `secret set` later. */
  secretStored: boolean;
  secretRefs: string[];
}

/**
 * Add a curated starter-pack integration to a runtime workspace: register its tool(s), and — if a
 * secret and passphrase are supplied — store the credential in the vault, bound to each tool. This
 * is the one-command "in the door" path (`roguezero add github`). Fails closed: an unknown
 * integration, a colliding tool id, or any invalid definition throws before anything is written.
 */
export async function addIntegrationCommand(opts: {
  configPath: string;
  integration: string;
  /** Credential value; when present (with a passphrase) it is stored in the vault. Never from argv. */
  secret?: string;
  passphrase?: string;
}): Promise<AddIntegrationResult> {
  const template = getIntegration(opts.integration);
  if (!template) {
    const available = listIntegrations()
      .map((i) => i.id)
      .join(", ");
    throw new Error(`unknown integration "${opts.integration}"; available: ${available}`);
  }

  const registryPath = registryPathFor(opts.configPath);
  const raw = JSON.parse(await readFile(registryPath, "utf8")) as { tools: { id?: string }[] };
  const existing = new Set(raw.tools.map((t) => t.id));
  for (const tool of template.tools) {
    if (existing.has(tool.id)) {
      throw new Error(`tool "${tool.id}" is already in the registry; remove it first to re-add`);
    }
    raw.tools.push(tool as unknown as { id?: string });
  }
  parseToolRegistry(raw); // validates every definition (incl. the new ones) before writing
  await writeFile(registryPath, `${JSON.stringify(raw, null, 2)}\n`, "utf8");

  const secretRefs = [...new Set(template.tools.map((t) => t.credential.ref))];
  let secretStored = false;
  if (opts.secret !== undefined && opts.passphrase !== undefined) {
    const vaultPath = vaultPathFor(opts.configPath);
    const vault = await readVaultFromFile(vaultPath, argon2idKeyProvider(opts.passphrase));
    // One credential value, bound to each tool that uses it (the vault binds a secret to a tool id).
    for (const tool of template.tools) {
      await putCredential(vault, { ref: tool.credential.ref, toolId: tool.id, value: opts.secret });
    }
    await saveVaultToFile(vaultPath, vault.file);
    secretStored = true;
  }

  return {
    integration: template.id,
    addedTools: template.tools.map((t) => t.id),
    secretStored,
    secretRefs,
  };
}

/** Store a tool's downstream credential in the vault, cryptographically bound to that tool. */
export async function secretSetCommand(opts: {
  configPath: string;
  tool: string;
  ref: string;
  value: string;
  passphrase: string;
}): Promise<void> {
  const vaultPath = vaultPathFor(opts.configPath);
  const vault = await readVaultFromFile(vaultPath, argon2idKeyProvider(opts.passphrase));
  await putCredential(vault, { ref: opts.ref, toolId: opts.tool, value: opts.value });
  await saveVaultToFile(vaultPath, vault.file);
}

/** Assemble the runtime's options from a workspace on disk (fail closed on any missing/invalid piece). */
export async function buildRuntimeOptions(opts: {
  configPath: string;
  passphrase: string;
}): Promise<RuntimeServerOptions> {
  const config = await loadGuardConfig(opts.configPath);
  const policy = policySchema.parse(
    JSON.parse(await readFile(config.policyPath, "utf8")),
  ) as Policy;
  const registry = parseToolRegistry(
    JSON.parse(await readFile(registryPathFor(opts.configPath), "utf8")),
  );
  const vault = await readVaultFromFile(
    vaultPathFor(opts.configPath),
    argon2idKeyProvider(opts.passphrase),
  );

  if (config.audit.sink !== "file") {
    throw new Error("`runtime serve` currently supports a file audit sink only");
  }
  const revPath = writableRevocationPath(config);
  if (config.revocation.source !== "file" || !revPath) {
    throw new Error("`runtime serve` currently supports a local file revocation source only");
  }

  return {
    audience: config.audience,
    resolver: createResolver({}), // did:key issuers/agents resolve without config
    trustedIssuers: config.trustedIssuers,
    nonceStore: createInMemoryNonceStore(),
    policy,
    auditSink: createJsonlAuditSink(config.audit.path),
    isRevoked: createFileRevocationChecker(revPath),
    registry,
    vault,
  };
}

/** Start the runtime HTTP server. Resolves once it is listening; the process stays alive on it. */
export async function serveCommand(opts: {
  configPath: string;
  passphrase: string;
  port: number;
  log?: (message: string) => void;
}): Promise<Server> {
  const log = opts.log ?? ((m: string) => process.stderr.write(`${m}\n`));
  const options = await buildRuntimeOptions(opts);
  const server = createRuntimeServer(options);
  await new Promise<void>((r) => server.listen(opts.port, "127.0.0.1", r));
  const addr = server.address();
  const port = typeof addr === "object" && addr ? addr.port : opts.port;
  log(
    `[roguezero] runtime serving ${options.registry.byId.size} tool(s) on http://127.0.0.1:${port}`,
  );
  log(`[roguezero] audience ${options.audience}; agents present a credential on every call.`);
  return server;
}
