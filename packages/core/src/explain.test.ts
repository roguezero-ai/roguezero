import { describe, expect, it } from "vitest";
import { explainDenial } from "./explain.js";
import type { VerificationFailureReason } from "./types.js";

// Every reason a user can actually see surfaced.
const ALL_REASONS: string[] = [
  "verify:bad-signature",
  "verify:untrusted-issuer",
  "verify:expired",
  "verify:not-yet-valid",
  "verify:audience-mismatch",
  "verify:nonce-invalid",
  "verify:nonce-replayed",
  "verify:revoked",
  "verify:malformed-credential",
  "verify:unresolvable-did",
  "verify:holder-mismatch",
  "verify:internal-error",
  "capability:tool-not-granted",
  "policy:default-deny",
  "policy:rule-0:deny",
  "audit-write-failed",
];

describe("explainDenial", () => {
  it("gives every surfaced reason a non-empty summary and an actionable fix", () => {
    for (const reason of ALL_REASONS) {
      const e = explainDenial(reason);
      expect(e.reason).toBe(reason);
      expect(e.summary.length).toBeGreaterThan(10);
      expect(e.fix.length).toBeGreaterThan(10);
    }
  });

  it("normalizes the verify: prefix", () => {
    expect(explainDenial("verify:revoked").summary).toBe(explainDenial("revoked").summary);
  });

  it("maps any policy:* reason to the policy explanation", () => {
    expect(explainDenial("policy:rule-3:deny").summary).toContain("Policy");
    expect(explainDenial("policy:default-deny").fix).toContain("allow rule");
  });

  it("explains a raw VerificationFailureReason", () => {
    const reason: VerificationFailureReason = "holder-mismatch";
    expect(explainDenial(reason).fix).toContain("agent's own key");
  });

  it("falls back safely for an unknown reason", () => {
    const e = explainDenial("something-new");
    expect(e.summary.length).toBeGreaterThan(0);
    expect(e.fix.length).toBeGreaterThan(0);
  });

  // The fallback exists so an unknown reason never crashes — but a reason we *ship* must never
  // reach it. Adding a VerificationFailureReason without an explanation is a product bug.
  it("has a specific explanation for every shipped failure reason", () => {
    const reasons: VerificationFailureReason[] = [
      "bad-signature",
      "untrusted-issuer",
      "expired",
      "not-yet-valid",
      "audience-mismatch",
      "nonce-invalid",
      "nonce-replayed",
      "revoked",
      "revocation-list-unavailable",
      "revocation-list-stale",
      "revocation-list-untrusted",
      "revocation-list-invalid",
      "revocation-list-rollback",
      "malformed-credential",
      "unresolvable-did",
      "holder-mismatch",
      "policy-deny",
    ];
    const generic = explainDenial("definitely-not-a-real-reason").summary;
    for (const reason of reasons) {
      expect(explainDenial(reason).summary, `${reason} has no explanation`).not.toBe(generic);
    }
  });
});
