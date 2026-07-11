import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CONFIG_VERSION, loadGuardConfig, writableRevocationPath } from "./config.js";

const dirs: string[] = [];
async function configWith(body: Record<string, unknown>): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "rz-config-"));
  dirs.push(dir);
  const path = join(dir, "roguezero.config.json");
  await writeFile(
    path,
    JSON.stringify({
      version: CONFIG_VERSION,
      audience: "mcp://reports.local",
      trustedIssuers: ["did:key:zCtl"],
      policy: { path: "policy.json" },
      audit: { sink: "file", path: "audit.jsonl" },
      revocation: { source: "file", path: "revocations.json" },
      ...body,
    }),
    "utf8",
  );
  return path;
}

afterEach(async () => {
  delete process.env.RZ_TEST_AUDIT_TOKEN;
  await Promise.all(dirs.splice(0).map((d) => rm(d, { recursive: true, force: true })));
});

describe("loadGuardConfig", () => {
  it("resolves paths against the config file, not the working directory", async () => {
    // A tool spawned by an MCP client inherits that client's cwd; policy does not live there.
    const path = await configWith({});
    const config = await loadGuardConfig(path);
    expect(config.policyPath.startsWith("/")).toBe(true);
    expect(config.policyPath.endsWith("/policy.json")).toBe(true);
    expect(config.policyPath).not.toBe("policy.json");
  });

  it("accepts a signed list over HTTP and leaves the URL alone", async () => {
    const path = await configWith({
      revocation: {
        source: "url",
        url: "https://revocations.roguezero.ai/acme.jwt",
        cacheTtlSeconds: 30,
        maxAgeSeconds: 120,
      },
    });
    const config = await loadGuardConfig(path);
    expect(config.revocation).toEqual({
      source: "url",
      url: "https://revocations.roguezero.ai/acme.jwt",
      cacheTtlSeconds: 30,
      maxAgeSeconds: 120,
      timeoutMs: undefined,
    });
    // Nothing local to write: revoke must say so rather than write a file nobody reads.
    expect(writableRevocationPath(config)).toBeUndefined();
  });

  it("exposes a writable path for local revocation sources", async () => {
    const file = await loadGuardConfig(await configWith({}));
    expect(writableRevocationPath(file)?.endsWith("/revocations.json")).toBe(true);

    const signed = await loadGuardConfig(
      await configWith({ revocation: { source: "signed-file", path: "revocations.jwt" } }),
    );
    expect(writableRevocationPath(signed)?.endsWith("/revocations.jwt")).toBe(true);
  });

  it("carries a remote audit sink's secret by env-var NAME, and never reads it here", async () => {
    // Loading a config must not depend on the environment: `revoke` needs the revocation path
    // and would otherwise die because an unrelated audit token happens to be unset.
    const path = await configWith({
      audit: {
        sink: "http",
        url: "https://audit.roguezero.ai/events",
        authorizationEnv: "RZ_TEST_AUDIT_TOKEN",
      },
      revocation: { source: "file", path: "revocations.json" },
    });
    const config = await loadGuardConfig(path);
    expect(config.audit).toEqual({
      sink: "http",
      url: "https://audit.roguezero.ai/events",
      timeoutMs: undefined,
      authorizationEnv: "RZ_TEST_AUDIT_TOKEN",
    });
    expect(writableRevocationPath(config)?.endsWith("/revocations.json")).toBe(true);
  });

  it("rejects an unknown revocation source rather than guessing", async () => {
    const path = await configWith({ revocation: { source: "carrier-pigeon", path: "x" } });
    await expect(loadGuardConfig(path)).rejects.toThrow();
  });

  it("points at `roguezero init` when there is no config", async () => {
    await expect(loadGuardConfig("/nonexistent/roguezero.config.json")).rejects.toThrow(
      /roguezero init/,
    );
  });
});
