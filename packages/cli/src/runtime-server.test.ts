import { afterEach, describe, expect, it } from "vitest";
import { type Server } from "node:http";
import { type AddressInfo } from "node:net";
import { createRateLimiter, type NonceStore } from "@roguezero/core";
import { createRuntimeServer, type RuntimeServerOptions } from "./runtime-server.js";

const AUDIENCE = "runtime://acme.test";

/** A stub nonce store — the /challenge path only calls `issue`; `consume` is never reached here. */
const stubNonceStore: NonceStore = {
  issue: async (audience) => ({ nonce: "n", audience, expiresAt: 0 }),
  consume: async () => "ok",
};

/** Minimal options: the /challenge branch touches only `nonceStore` + `audience`. */
function baseOptions(extra: Partial<RuntimeServerOptions>): RuntimeServerOptions {
  return {
    nonceStore: stubNonceStore,
    audience: AUDIENCE,
    ...extra,
  } as RuntimeServerOptions;
}

let server: Server | undefined;
afterEach(() => {
  server?.close();
  server = undefined;
});

async function listen(options: RuntimeServerOptions): Promise<string> {
  server = createRuntimeServer(options);
  const port = await new Promise<number>((r) =>
    server!.listen(0, "127.0.0.1", () => r((server!.address() as AddressInfo).port)),
  );
  return `http://127.0.0.1:${port}`;
}

describe("createRuntimeServer — /challenge rate limiting", () => {
  it("throttles a flood of challenge requests with 429 + Retry-After", async () => {
    // Tiny limiter: 2-burst, slow refill, so the third rapid call is throttled.
    const base = await listen(
      baseOptions({
        challengeRateLimiter: createRateLimiter({ capacity: 2, refillPerSecond: 0.1 }),
      }),
    );

    const first = await fetch(`${base}/challenge`);
    const second = await fetch(`${base}/challenge`);
    const third = await fetch(`${base}/challenge`);

    expect(first.status).toBe(200);
    expect(second.status).toBe(200);
    expect(third.status).toBe(429);
    expect(Number(third.headers.get("retry-after"))).toBeGreaterThan(0);
  });

  it("applies a secure default limiter when none is configured (fail-closed, not open)", async () => {
    // No limiter passed → default 20-burst. The 21st rapid call must be throttled.
    const base = await listen(baseOptions({}));
    let sawThrottle = false;
    for (let i = 0; i < 25; i++) {
      const res = await fetch(`${base}/challenge`);
      if (res.status === 429) {
        sawThrottle = true;
        break;
      }
    }
    expect(sawThrottle).toBe(true);
  });

  it("can be explicitly disabled for deployments behind a throttling gateway", async () => {
    const base = await listen(baseOptions({ challengeRateLimiter: false }));
    for (let i = 0; i < 50; i++) {
      expect((await fetch(`${base}/challenge`)).status).toBe(200);
    }
  });
});
