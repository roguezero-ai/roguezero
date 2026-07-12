import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  createVault,
  getCredential,
  listCredentialRefs,
  loadVault,
  localKeyProvider,
  putCredential,
  removeCredential,
  type Vault,
  type VaultFile,
} from "./vault.js";

const rootKey = () => new Uint8Array(randomBytes(32));
const text = (u: Uint8Array) => new TextDecoder().decode(u);
const clone = (v: Vault): VaultFile => JSON.parse(JSON.stringify(v.file)) as VaultFile;

/** Flip one base64-decoded byte, to simulate at-rest tampering. */
function tamper(b64: string): string {
  const bytes = new Uint8Array(Buffer.from(b64, "base64"));
  bytes[0] = bytes[0] ^ 0xff;
  return Buffer.from(bytes).toString("base64");
}

describe("vault — round trip", () => {
  it("stores and retrieves a credential as bytes, and never exposes it in the file", async () => {
    const vault = await createVault(localKeyProvider(rootKey()));
    await putCredential(vault, { ref: "github", toolId: "gh-api", value: "ghp_SECRET_TOKEN" });

    const got = await getCredential(vault, { ref: "github", toolId: "gh-api" });
    expect(got).toBeInstanceOf(Uint8Array); // bytes, not an unzeroable string
    expect(text(got)).toBe("ghp_SECRET_TOKEN");
    expect(listCredentialRefs(vault)).toEqual(["github"]);
    expect(JSON.stringify(vault.file)).not.toContain("ghp_SECRET_TOKEN");
  });

  it("survives serialize → load, verifying the manifest", async () => {
    const key = rootKey();
    const vault = await createVault(localKeyProvider(key));
    await putCredential(vault, { ref: "stripe", toolId: "stripe-api", value: "sk_live_XYZ" });

    const reloaded = await loadVault(clone(vault), localKeyProvider(key));
    expect(text(await getCredential(reloaded, { ref: "stripe", toolId: "stripe-api" }))).toBe(
      "sk_live_XYZ",
    );
  });

  it("bumps the generation on every mutation", async () => {
    const vault = await createVault(localKeyProvider(rootKey()));
    const g0 = vault.file.generation;
    await putCredential(vault, { ref: "a", toolId: "t", value: "x" });
    await putCredential(vault, { ref: "b", toolId: "t", value: "y" });
    await removeCredential(vault, "a");
    expect(vault.file.generation).toBe(g0 + 3);
  });

  it("stores a reserved-name ref safely (null-prototype entries)", async () => {
    const vault = await createVault(localKeyProvider(rootKey()));
    await putCredential(vault, { ref: "__proto__", toolId: "t", value: "safe" });
    expect(text(await getCredential(vault, { ref: "__proto__", toolId: "t" }))).toBe("safe");
    expect(listCredentialRefs(vault)).toContain("__proto__");
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });
});

describe("vault — fails closed (the tests that must fail)", () => {
  it("rejects a wrong-size root key", () => {
    expect(() => localKeyProvider(new Uint8Array(16))).toThrow(/32 bytes/);
  });

  it("rejects ids outside the safe charset (closes the AAD-collision vector)", async () => {
    const vault = await createVault(localKeyProvider(rootKey()));
    await expect(putCredential(vault, { ref: "a\nb", toolId: "t", value: "x" })).rejects.toThrow();
    await expect(putCredential(vault, { ref: "ok", toolId: "t\nx", value: "x" })).rejects.toThrow();
  });

  it("cannot load with a different root key", async () => {
    const vault = await createVault(localKeyProvider(rootKey()));
    await putCredential(vault, { ref: "github", toolId: "gh-api", value: "ghp_x" });
    await expect(loadVault(clone(vault), localKeyProvider(rootKey()))).rejects.toThrow();
  });

  it("detects a tampered ciphertext at load (manifest MAC)", async () => {
    const vault = await createVault(localKeyProvider(rootKey()));
    await putCredential(vault, { ref: "github", toolId: "gh-api", value: "ghp_x" });
    const file = clone(vault);
    file.entries.github.ciphertext = tamper(file.entries.github.ciphertext);
    await expect(loadVault(file, vault.keyProvider)).rejects.toThrow(/integrity/);
  });

  it("detects a deleted entry at load (rollback/deletion)", async () => {
    const key = rootKey();
    const vault = await createVault(localKeyProvider(key));
    await putCredential(vault, { ref: "a", toolId: "t", value: "x" });
    await putCredential(vault, { ref: "b", toolId: "t", value: "y" });
    const file = clone(vault);
    delete file.entries.a; // attacker with write access drops an entry
    await expect(loadVault(file, localKeyProvider(key))).rejects.toThrow(/integrity/);
  });

  it("detects an injected entry at load", async () => {
    const key = rootKey();
    const vault = await createVault(localKeyProvider(key));
    await putCredential(vault, { ref: "a", toolId: "t", value: "x" });
    const file = clone(vault);
    file.entries.evil = { ...file.entries.a }; // copy a sealed entry to a new ref
    await expect(loadVault(file, localKeyProvider(key))).rejects.toThrow(/integrity/);
  });

  it("detects a rewound generation counter at load", async () => {
    const key = rootKey();
    const vault = await createVault(localKeyProvider(key));
    await putCredential(vault, { ref: "a", toolId: "t", value: "x" });
    const file = clone(vault);
    file.generation = 1; // roll back the counter without re-MACing (attacker lacks the MAC key)
    await expect(loadVault(file, localKeyProvider(key))).rejects.toThrow(/integrity/);
  });

  it("gives a uniform error for a missing ref and a wrong-tool request (no oracle)", async () => {
    const vault = await createVault(localKeyProvider(rootKey()));
    await putCredential(vault, { ref: "github", toolId: "gh-api", value: "ghp_x" });

    const missing = await getCredential(vault, { ref: "nope", toolId: "gh-api" }).catch((e) => e);
    const wrongTool = await getCredential(vault, { ref: "github", toolId: "other" }).catch(
      (e) => e,
    );
    expect(String(missing.message)).toBe(String(wrongTool.message));
    expect(String(missing.message)).toMatch(/no credential available/);
  });

  it("rejects a malformed / unknown-version vault file", async () => {
    const vault = await createVault(localKeyProvider(rootKey()));
    await expect(loadVault({ nonsense: true }, vault.keyProvider)).rejects.toThrow();
    await expect(loadVault({ ...clone(vault), version: 99 }, vault.keyProvider)).rejects.toThrow();
  });

  it("removes a credential", async () => {
    const vault = await createVault(localKeyProvider(rootKey()));
    await putCredential(vault, { ref: "github", toolId: "gh-api", value: "ghp_x" });
    await removeCredential(vault, "github");
    expect(listCredentialRefs(vault)).toEqual([]);
    await expect(getCredential(vault, { ref: "github", toolId: "gh-api" })).rejects.toThrow();
  });
});
