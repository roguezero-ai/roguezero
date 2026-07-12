import { describe, expect, it } from "vitest";
import {
  argon2idKeyProvider,
  ARGON2ID_DEFAULT,
  kmsKeyProvider,
  type Argon2idParams,
  type KmsAdapter,
} from "./vault-keys.js";
import { createVault, getCredential, loadVault, localKeyProvider, putCredential } from "./vault.js";

// Fast argon2id for tests; the shipped default is far stronger (asserted separately).
const FAST: Argon2idParams = { t: 1, m: 8 * 1024, p: 1 };
const text = (u: Uint8Array) => new TextDecoder().decode(u);

describe("argon2idKeyProvider", () => {
  it("seals and opens a vault with nothing secret at rest", async () => {
    const vault = await createVault(argon2idKeyProvider("correct horse battery staple", FAST));
    await putCredential(vault, { ref: "github", toolId: "gh-api", value: "ghp_x" });

    // The passphrase is nowhere in the serialized file; only salt + params + ciphertext.
    expect(JSON.stringify(vault.file)).not.toContain("correct horse");

    const reopened = await loadVault(
      JSON.parse(JSON.stringify(vault.file)),
      argon2idKeyProvider("correct horse battery staple", FAST),
    );
    expect(text(await getCredential(reopened, { ref: "github", toolId: "gh-api" }))).toBe("ghp_x");
  });

  it("fails closed on the wrong passphrase", async () => {
    const vault = await createVault(argon2idKeyProvider("right", FAST));
    await putCredential(vault, { ref: "a", toolId: "t", value: "x" });
    await expect(
      loadVault(JSON.parse(JSON.stringify(vault.file)), argon2idKeyProvider("wrong", FAST)),
    ).rejects.toThrow();
  });

  it("reads cost params from the blob, not the provider (upgrade-safe)", async () => {
    // Sealed with FAST params; opened by a provider configured with different params. `unwrap` must
    // use the blob's params (else it would derive the wrong KEK and fail).
    const vault = await createVault(argon2idKeyProvider("pw", FAST));
    await putCredential(vault, { ref: "a", toolId: "t", value: "x" });
    const opener = argon2idKeyProvider("pw", { t: 2, m: 16 * 1024, p: 1 });
    const reopened = await loadVault(JSON.parse(JSON.stringify(vault.file)), opener);
    expect(text(await getCredential(reopened, { ref: "a", toolId: "t" }))).toBe("x");
  });

  it("ships a strong default (above the OWASP argon2id floor)", () => {
    expect(ARGON2ID_DEFAULT.m).toBeGreaterThanOrEqual(19 * 1024); // ≥ 19 MiB
    expect(ARGON2ID_DEFAULT.t).toBeGreaterThanOrEqual(2);
  });
});

describe("kmsKeyProvider", () => {
  /** A stand-in KMS: seals under a fixed local provider, prefixing a tag to prove it's "our" blob. */
  function mockKms(secretKey: Uint8Array): KmsAdapter {
    const inner = localKeyProvider(secretKey);
    return { encrypt: (p) => inner.wrap(p), decrypt: (c) => inner.unwrap(c) };
  }

  it("round-trips a vault through a KMS adapter", async () => {
    const key = new Uint8Array(32).fill(7);
    const vault = await createVault(kmsKeyProvider(mockKms(key)));
    await putCredential(vault, { ref: "stripe", toolId: "stripe-api", value: "sk_x" });
    const reopened = await loadVault(
      JSON.parse(JSON.stringify(vault.file)),
      kmsKeyProvider(mockKms(key)),
    );
    expect(text(await getCredential(reopened, { ref: "stripe", toolId: "stripe-api" }))).toBe(
      "sk_x",
    );
  });

  it("fails closed if the KMS key differs", async () => {
    const vault = await createVault(kmsKeyProvider(mockKms(new Uint8Array(32).fill(1))));
    await putCredential(vault, { ref: "a", toolId: "t", value: "x" });
    await expect(
      loadVault(
        JSON.parse(JSON.stringify(vault.file)),
        kmsKeyProvider(mockKms(new Uint8Array(32).fill(2))),
      ),
    ).rejects.toThrow();
  });

  it("propagates a KMS outage as a throw (fail closed)", async () => {
    const down: KmsAdapter = {
      encrypt: () => Promise.reject(new Error("kms unavailable")),
      decrypt: () => Promise.reject(new Error("kms unavailable")),
    };
    await expect(createVault(kmsKeyProvider(down))).rejects.toThrow(/kms unavailable/);
  });
});
