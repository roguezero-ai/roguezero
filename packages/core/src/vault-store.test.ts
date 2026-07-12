import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { createVault, getCredential, localKeyProvider, putCredential } from "./vault.js";
import { readVaultFromFile, saveVaultToFile } from "./vault-store.js";

const rootKey = () => new Uint8Array(randomBytes(32));
const text = (u: Uint8Array) => new TextDecoder().decode(u);

let dir = "";
afterEach(async () => {
  if (dir) await rm(dir, { recursive: true, force: true });
  dir = "";
});

describe("vault-store", () => {
  it("saves and reads back a vault, credential intact", async () => {
    dir = await mkdtemp(join(tmpdir(), "rz-vault-"));
    const path = join(dir, "vault.json");
    const key = rootKey();

    const vault = await createVault(localKeyProvider(key));
    await putCredential(vault, { ref: "github", toolId: "gh-api", value: "ghp_x" });
    await saveVaultToFile(path, vault.file);

    const reopened = await readVaultFromFile(path, localKeyProvider(key));
    expect(text(await getCredential(reopened, { ref: "github", toolId: "gh-api" }))).toBe("ghp_x");
  });

  it("writes the vault file mode 0600", async () => {
    dir = await mkdtemp(join(tmpdir(), "rz-vault-"));
    const path = join(dir, "vault.json");
    const vault = await createVault(localKeyProvider(rootKey()));
    await saveVaultToFile(path, vault.file);
    expect((await stat(path)).mode & 0o777).toBe(0o600);
  });

  it("detects a rolled-back vault (generation regressed below the sidecar)", async () => {
    dir = await mkdtemp(join(tmpdir(), "rz-vault-"));
    const path = join(dir, "vault.json");
    const key = rootKey();

    const vault = await createVault(localKeyProvider(key));
    const snapshotOld = JSON.stringify(vault.file, null, 2); // generation 1

    await putCredential(vault, { ref: "a", toolId: "t", value: "x" });
    await saveVaultToFile(path, vault.file); // generation 2 → sidecar advances to 2

    // Attacker (or a stale backup) restores the earlier, still-MAC-valid file — without touching the
    // sidecar. It parses and its manifest verifies, but the generation regressed → rejected.
    await writeFile(path, snapshotOld, "utf8");
    await expect(readVaultFromFile(path, localKeyProvider(key))).rejects.toThrow(/rolled back/);
  });

  it("honors an explicit external generation floor", async () => {
    dir = await mkdtemp(join(tmpdir(), "rz-vault-"));
    const path = join(dir, "vault.json");
    const key = rootKey();
    const vault = await createVault(localKeyProvider(key)); // generation 1
    await saveVaultToFile(path, vault.file);
    await expect(
      readVaultFromFile(path, localKeyProvider(key), { expectedMinGeneration: 5 }),
    ).rejects.toThrow(/rolled back/);
  });

  it("fails closed on a missing file", async () => {
    dir = await mkdtemp(join(tmpdir(), "rz-vault-"));
    await expect(
      readVaultFromFile(join(dir, "nope.json"), localKeyProvider(rootKey())),
    ).rejects.toThrow();
  });
});
