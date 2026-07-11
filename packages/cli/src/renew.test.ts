import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadRevocationListFromFile } from "@roguezero/core";
import { bundleExpiry, bundleGrants, loadBundle } from "./bundle.js";
import { parseToolSpec, revokeCommand } from "./commands.js";
import { initCommand, onboardCommand, renewAllCommand, renewCommand } from "./workspace.js";

let dir = "";
async function workspace() {
  dir = await mkdtemp(join(tmpdir(), "rz-renew-"));
  const { configPath, controllerPath, revocationPath } = await initCommand({
    dir,
    audience: "mcp://reports.local",
  });
  const { bundlePath } = await onboardCommand({
    name: "reporter",
    configPath,
    controllerPath,
    tools: [parseToolSpec("read_report=reports:read")],
    // A deliberately short grant, so a renewal to the default lifetime visibly extends it.
    expiresInSeconds: 3600,
  });
  return { configPath, controllerPath, bundlePath, revocationPath };
}

afterEach(async () => {
  if (dir) await rm(dir, { recursive: true, force: true });
  dir = "";
});

describe("renew", () => {
  it("keeps the identity and grants, replaces the credentials, and retires the old capability", async () => {
    const ws = await workspace();
    const before = await loadBundle(ws.bundlePath);

    const result = await renewCommand({
      bundlePath: ws.bundlePath,
      configPath: ws.configPath,
      controllerPath: ws.controllerPath,
    });

    const after = await loadBundle(ws.bundlePath);
    // Same agent: the DID and its private key are what the policy and the audit trail name.
    expect(after.did).toBe(before.did);
    expect(after.privateKey).toBe(before.privateKey);
    expect(bundleGrants(after)).toEqual(bundleGrants(before));

    // New credentials, further expiry.
    expect(after.capabilityId).not.toBe(before.capabilityId);
    expect(after.capabilityVc).not.toBe(before.capabilityVc);
    // Both are reissued: a live capability behind an expired profile still fails verification.
    expect(after.profileVc).not.toBe(before.profileVc);
    expect(bundleExpiry(after).expiresAt!).toBeGreaterThan(bundleExpiry(before).expiresAt!);

    // Rotation that leaves the old credential valid has doubled the credentials, not rotated.
    expect(result.revokedPrevious).toBe(true);
    const revoked = await loadRevocationListFromFile(ws.revocationPath);
    expect(revoked.has(before.capabilityId)).toBe(true);
    expect(revoked.has(after.capabilityId)).toBe(false);
  });

  it("leaves the old capability alive only when asked, explicitly", async () => {
    const ws = await workspace();
    const before = await loadBundle(ws.bundlePath);

    const result = await renewCommand({
      bundlePath: ws.bundlePath,
      configPath: ws.configPath,
      controllerPath: ws.controllerPath,
      keepPrevious: true,
    });

    expect(result.revokedPrevious).toBe(false);
    const revoked = await loadRevocationListFromFile(ws.revocationPath);
    expect(revoked.has(before.capabilityId)).toBe(false);
  });

  it("refuses a controller that did not issue this bundle", async () => {
    const ws = await workspace();
    const other = await mkdtemp(join(tmpdir(), "rz-renew-other-"));
    const rogue = await initCommand({ dir: other, audience: "mcp://reports.local" });
    try {
      await expect(
        renewCommand({
          bundlePath: ws.bundlePath,
          configPath: ws.configPath,
          controllerPath: rogue.controllerPath,
        }),
      ).rejects.toThrow(/not a trusted issuer/);
    } finally {
      await rm(other, { recursive: true, force: true });
    }
  });

  it("records the retired capability's own expiry so a publisher can prune it", async () => {
    const ws = await workspace();
    const before = await loadBundle(ws.bundlePath);
    await renewCommand({
      bundlePath: ws.bundlePath,
      configPath: ws.configPath,
      controllerPath: ws.controllerPath,
    });
    const { readFile } = await import("node:fs/promises");
    const list = JSON.parse(await readFile(ws.revocationPath, "utf8")) as {
      revoked: Array<{ id: string; expiresAt?: number }>;
    };
    const entry = list.revoked.find((e) => e.id === before.capabilityId);
    expect(entry?.expiresAt).toBe(bundleExpiry(before).expiresAt);
  });
});

describe("renew — kill-switch integrity (ADR 0004)", () => {
  it("refuses to renew a revoked agent (renewal must not resurrect a kill)", async () => {
    const ws = await workspace();
    const bundle = await loadBundle(ws.bundlePath);

    // Kill it: revoke the current capability, as `revoke --agent` does.
    await revokeCommand({ listPath: ws.revocationPath, bundlePath: ws.bundlePath });

    await expect(
      renewCommand({
        bundlePath: ws.bundlePath,
        configPath: ws.configPath,
        controllerPath: ws.controllerPath,
      }),
    ).rejects.toThrow(/revoked.*resurrect a killed agent/s);

    // And nothing changed: the bundle still holds the revoked capability, still dead.
    const after = await loadBundle(ws.bundlePath);
    expect(after.capabilityId).toBe(bundle.capabilityId);
    const revoked = await loadRevocationListFromFile(ws.revocationPath);
    expect(revoked.has(after.capabilityId)).toBe(true);
  });

  it("the scheduler renews a living agent but never resurrects a revoked one", async () => {
    const ws = await workspace(); // onboards "reporter" with a short (in-window) grant
    const worker = await onboardCommand({
      name: "worker",
      configPath: ws.configPath,
      controllerPath: ws.controllerPath,
      tools: [parseToolSpec("read_report=reports:read")],
      expiresInSeconds: 3600,
    });

    const reporterBefore = await loadBundle(ws.bundlePath);
    const workerBefore = await loadBundle(worker.bundlePath);

    // Kill the worker, then run the controller-side scheduler over the whole directory.
    await revokeCommand({ listPath: ws.revocationPath, bundlePath: worker.bundlePath });
    const { outcomes } = await renewAllCommand({
      dir: dir,
      configPath: ws.configPath,
      controllerPath: ws.controllerPath,
    });

    const byName = Object.fromEntries(outcomes.map((o) => [o.name, o.outcome]));
    expect(byName.reporter).toBe("renewed");
    expect(byName.worker).toBe("skipped-revoked");

    // The living agent got fresh credentials; the killed one did not — it stays dead.
    const reporterAfter = await loadBundle(ws.bundlePath);
    const workerAfter = await loadBundle(worker.bundlePath);
    expect(reporterAfter.capabilityId).not.toBe(reporterBefore.capabilityId);
    expect(workerAfter.capabilityId).toBe(workerBefore.capabilityId);
    const revoked = await loadRevocationListFromFile(ws.revocationPath);
    expect(revoked.has(workerAfter.capabilityId)).toBe(true);
  });
});
