import { describe, expect, it } from "vitest";
import { createInMemoryNonceStore } from "./nonce.js";

describe("InMemoryNonceStore", () => {
  it("consumes a valid challenge exactly once", async () => {
    const store = createInMemoryNonceStore();
    const c = await store.issue("mcp://a");
    expect(await store.consume(c.nonce, "mcp://a")).toBe("ok");
  });

  it("reports a replay on the second consume", async () => {
    const store = createInMemoryNonceStore();
    const c = await store.issue("mcp://a");
    await store.consume(c.nonce, "mcp://a");
    expect(await store.consume(c.nonce, "mcp://a")).toBe("replayed");
  });

  it("reports unknown for a forged nonce", async () => {
    const store = createInMemoryNonceStore();
    expect(await store.consume("forged", "mcp://a")).toBe("unknown");
  });

  it("reports audience-mismatch when consumed for a different audience", async () => {
    const store = createInMemoryNonceStore();
    const c = await store.issue("mcp://a");
    expect(await store.consume(c.nonce, "mcp://b")).toBe("audience-mismatch");
  });

  it("reports expired past its TTL", async () => {
    const store = createInMemoryNonceStore();
    const c = await store.issue("mcp://a", -1);
    expect(await store.consume(c.nonce, "mcp://a")).toBe("expired");
  });

  it("issues unique, high-entropy nonces", async () => {
    const store = createInMemoryNonceStore();
    const a = await store.issue("mcp://a");
    const b = await store.issue("mcp://a");
    expect(a.nonce).not.toBe(b.nonce);
    expect(a.nonce.length).toBeGreaterThanOrEqual(43); // 32 random bytes, base64url
  });
});

describe("InMemoryNonceStore — bounded memory", () => {
  it("evicts expired entries on issue instead of leaking them", async () => {
    let t = 1000;
    const store = createInMemoryNonceStore({ now: () => t });
    // Two short-lived challenges that are never consumed.
    const stale = await store.issue("mcp://a", 5);
    await store.issue("mcp://a", 5);
    // Advance past their TTL; a new issue triggers the sweep.
    t = 1100;
    await store.issue("mcp://a", 5);
    // The stale, unconsumed challenge is gone (swept), not lingering forever.
    expect(await store.consume(stale.nonce, "mcp://a")).toBe("unknown");
  });

  it("enforces a hard cap on stored challenges", async () => {
    const store = createInMemoryNonceStore({ maxEntries: 2 });
    const first = await store.issue("mcp://a");
    await store.issue("mcp://a");
    await store.issue("mcp://a"); // exceeds cap -> soonest-expiring evicted
    // The oldest is evicted, keeping memory bounded under a flood.
    expect(await store.consume(first.nonce, "mcp://a")).toBe("unknown");
  });
});
