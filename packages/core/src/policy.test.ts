import { describe, expect, it } from "vitest";
import { evaluatePolicy, type Policy } from "./policy.js";

const AGENT = "did:key:z6MkAgent";

describe("evaluatePolicy", () => {
  it("allows when a rule matches agent, tool, and scopes", () => {
    const policy: Policy = {
      rules: [{ agent: AGENT, tool: "read_report", scopes: ["reports:read"], effect: "allow" }],
    };
    const d = evaluatePolicy(policy, {
      agent: AGENT,
      tool: "read_report",
      scopes: ["reports:read"],
    });
    expect(d.decision).toBe("allow");
    expect(d.reason).toBe("policy:rule-0:allow");
  });

  it("defaults to deny when no rule matches", () => {
    const policy: Policy = { rules: [] };
    const d = evaluatePolicy(policy, { agent: AGENT, tool: "delete_report", scopes: [] });
    expect(d.decision).toBe("deny");
    expect(d.reason).toBe("policy:default-deny");
  });

  it("honors an explicit deny rule", () => {
    const policy: Policy = {
      rules: [{ agent: AGENT, tool: "delete_report", scopes: ["reports:delete"], effect: "deny" }],
    };
    const d = evaluatePolicy(policy, {
      agent: AGENT,
      tool: "delete_report",
      scopes: ["reports:delete"],
    });
    expect(d.decision).toBe("deny");
    expect(d.reason).toBe("policy:rule-0:deny");
  });

  it("applies first-match precedence (deny before a later allow)", () => {
    const policy: Policy = {
      rules: [
        { agent: "*", tool: "delete_report", scopes: ["*"], effect: "deny" },
        { agent: AGENT, tool: "delete_report", scopes: ["reports:delete"], effect: "allow" },
      ],
    };
    const d = evaluatePolicy(policy, {
      agent: AGENT,
      tool: "delete_report",
      scopes: ["reports:delete"],
    });
    expect(d.decision).toBe("deny");
    expect(d.reason).toBe("policy:rule-0:deny");
  });

  it("supports wildcards for agent, tool, and scope", () => {
    const policy: Policy = { rules: [{ agent: "*", tool: "*", scopes: ["*"], effect: "allow" }] };
    const d = evaluatePolicy(policy, { agent: "did:key:anyone", tool: "anything", scopes: ["x"] });
    expect(d.decision).toBe("allow");
  });

  it("denies when a required scope is not granted by the matching rule", () => {
    const policy: Policy = {
      rules: [{ agent: AGENT, tool: "read_report", scopes: ["reports:read"], effect: "allow" }],
    };
    // Requests an extra scope the rule does not grant -> no match -> default deny.
    const d = evaluatePolicy(policy, {
      agent: AGENT,
      tool: "read_report",
      scopes: ["reports:read", "reports:write"],
    });
    expect(d.decision).toBe("deny");
    expect(d.reason).toBe("policy:default-deny");
  });
});
