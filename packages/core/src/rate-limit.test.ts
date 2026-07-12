import { describe, it, expect } from "vitest";
import { createRateLimiter } from "./rate-limit.js";

/** A controllable millisecond clock for deterministic throttle/recover assertions. */
function fakeClock(startMs = 0) {
  let t = startMs;
  return { now: () => t, advance: (ms: number) => (t += ms) };
}

describe("createRateLimiter", () => {
  it("rejects a non-positive configuration (no silently-open limiter)", () => {
    expect(() => createRateLimiter({ capacity: 0, refillPerSecond: 1 })).toThrow();
    expect(() => createRateLimiter({ capacity: 5, refillPerSecond: 0 })).toThrow();
    expect(() => createRateLimiter({ capacity: -1, refillPerSecond: 1 })).toThrow();
  });

  it("permits a burst up to capacity, then throttles the next call", () => {
    const clock = fakeClock();
    const limiter = createRateLimiter({ capacity: 3, refillPerSecond: 1, now: clock.now });

    expect(limiter.check("ip").allowed).toBe(true);
    expect(limiter.check("ip").allowed).toBe(true);
    expect(limiter.check("ip").allowed).toBe(true);

    const throttled = limiter.check("ip");
    expect(throttled.allowed).toBe(false);
    expect(throttled.retryAfterSeconds).toBeGreaterThan(0);
  });

  it("recovers after enough time has passed to refill a token", () => {
    const clock = fakeClock();
    const limiter = createRateLimiter({ capacity: 1, refillPerSecond: 1, now: clock.now });

    expect(limiter.check("ip").allowed).toBe(true);
    expect(limiter.check("ip").allowed).toBe(false); // bucket empty

    clock.advance(1000); // one token refills at 1/sec
    expect(limiter.check("ip").allowed).toBe(true);
  });

  it("reports a retry-after that actually clears the throttle", () => {
    const clock = fakeClock();
    const limiter = createRateLimiter({ capacity: 2, refillPerSecond: 0.5, now: clock.now });

    limiter.check("ip");
    limiter.check("ip");
    const denied = limiter.check("ip");
    expect(denied.allowed).toBe(false);

    // Wait exactly the advertised hint; the next call must succeed.
    clock.advance(denied.retryAfterSeconds * 1000);
    expect(limiter.check("ip").allowed).toBe(true);
  });

  it("throttles keys independently — one client's flood doesn't block another", () => {
    const clock = fakeClock();
    const limiter = createRateLimiter({ capacity: 1, refillPerSecond: 1, now: clock.now });

    expect(limiter.check("attacker").allowed).toBe(true);
    expect(limiter.check("attacker").allowed).toBe(false);
    // A different source is unaffected.
    expect(limiter.check("honest-client").allowed).toBe(true);
  });

  it("does not over-fill: idle time can't bank more than capacity tokens", () => {
    const clock = fakeClock();
    const limiter = createRateLimiter({ capacity: 2, refillPerSecond: 1, now: clock.now });

    clock.advance(60_000); // a minute idle
    expect(limiter.check("ip").allowed).toBe(true);
    expect(limiter.check("ip").allowed).toBe(true);
    expect(limiter.check("ip").allowed).toBe(false); // capacity is still just 2
  });

  it("bounds its own memory: sprayed distinct keys can't grow state without limit", () => {
    const clock = fakeClock();
    const limiter = createRateLimiter({
      capacity: 1,
      refillPerSecond: 1,
      maxKeys: 10,
      now: clock.now,
    });

    // Spray 10k distinct source addresses, advancing time so buckets refill and become sweepable.
    for (let i = 0; i < 10_000; i++) {
      clock.advance(2000); // > full-refill window (1 token / 1 per-sec = 1s)
      expect(limiter.check(`ip-${i}`).allowed).toBe(true);
    }
    // A brand-new key still works — eviction only ever forgives, never wrongly throttles.
    expect(limiter.check("fresh").allowed).toBe(true);
  });

  it("eviction backstop holds even when live keys exceed the cap in the same instant", () => {
    const clock = fakeClock();
    const limiter = createRateLimiter({
      capacity: 1,
      refillPerSecond: 1,
      maxKeys: 5,
      now: clock.now,
    });

    // No time advances: every bucket stays empty (non-sweepable), forcing the LRU backstop.
    for (let i = 0; i < 100; i++) limiter.check(`ip-${i}`);
    // Still serves new keys rather than throwing or leaking unbounded memory.
    expect(limiter.check("newcomer").allowed).toBe(true);
  });
});
