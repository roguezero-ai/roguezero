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

  it("defaults to short credential and presentation lifetimes", () => {
    expect(DEFAULT_LIFETIMES.presentationSeconds).toBeLessThanOrEqual(
      DEFAULT_LIFETIMES.capabilitySeconds,
    );
    expect(DEFAULT_LIFETIMES.capabilitySeconds).toBeLessThanOrEqual(24 * 60 * 60);
  });
});
