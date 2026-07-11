import { describe, expect, it } from "vitest";
import {
  CREDENTIAL_TYPES,
  DEFAULT_LIFETIMES,
  SCHEMA_BASE_URI,
  SUPPORTED_DID_METHODS,
} from "./constants.js";

describe("constants", () => {
  it("exposes exactly the two MVP credential types", () => {
    expect(Object.values(CREDENTIAL_TYPES)).toEqual(["AgentProfile", "AgentCapability"]);
  });

  it("supports only did:key and did:web in the MVP", () => {
    expect(SUPPORTED_DID_METHODS).toEqual(["key", "web"]);
  });

  it("mints schema URIs under the product domain, centralized", () => {
    expect(SCHEMA_BASE_URI).toContain("roguezero.ai");
    expect(SCHEMA_BASE_URI.endsWith("/")).toBe(true);
    // The retired "AgentDID" working title must not leak into credential payloads.
    expect(SCHEMA_BASE_URI.toLowerCase()).not.toContain("agentdid");
  });

  // The lifetimes encode a security argument, so assert the argument rather than the numbers.
  //
  // The presentation is the *proof*, and its lifetime is the replay window — the one place where
  // "short" is the control itself. The capability is the *grant*, and its lifetime is only a
  // backstop, because `isRevoked` runs on every call and fails closed. Revocation is the kill
  // switch. See DEFAULT_LIFETIMES.
  it("keeps the replay window short: challenge < presentation", () => {
    expect(DEFAULT_LIFETIMES.challengeSeconds).toBeLessThan(DEFAULT_LIFETIMES.presentationSeconds);
    expect(DEFAULT_LIFETIMES.presentationSeconds).toBeLessThanOrEqual(15 * 60);
  });

  it("makes the grant outlive the proof by a wide margin, so rotation is not a per-call concern", () => {
    expect(DEFAULT_LIFETIMES.presentationSeconds * 100).toBeLessThan(
      DEFAULT_LIFETIMES.capabilitySeconds,
    );
  });

  it("still bounds the grant, because expiry is the backstop when revocation cannot be consulted", () => {
    expect(DEFAULT_LIFETIMES.capabilitySeconds).toBeLessThanOrEqual(90 * 24 * 60 * 60);
  });

  it("requires a signed revocation list to be re-published far more often than a grant lives", () => {
    expect(DEFAULT_LIFETIMES.revocationListSeconds).toBeLessThan(
      DEFAULT_LIFETIMES.capabilitySeconds,
    );
  });
});
