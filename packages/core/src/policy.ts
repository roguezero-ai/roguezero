/**
 * Policy: a declarative allow/deny decision over (agent × tool × scopes).
 *
 * Deliberately the smallest engine that makes the golden path real: an ordered rule list,
 * first match wins, default deny. `*` wildcards are allowed for agent, tool, and scope. A
 * richer engine (Cedar/OPA) can sit behind this same `evaluatePolicy` shape later
 * (deferred) — we do not build for it now. Default deny is the security-critical default:
 * absence of a matching allow is a denial, never an allow.
 */

import { readFile } from "node:fs/promises";
import { z } from "zod";
import type { Decision, PolicyDecision, PolicyRule } from "./types.js";

export const policyRuleSchema = z.object({
  agent: z.string().min(1),
  tool: z.string().min(1),
  scopes: z.array(z.string()),
  effect: z.enum(["allow", "deny"]),
});

export const policySchema = z.object({
  rules: z.array(policyRuleSchema),
});

export interface Policy {
  rules: PolicyRule[];
}

export interface PolicyRequest {
  agent: string;
  tool: string;
  /** Scopes the tool call requires; all must be permitted by a matching rule. */
  scopes: string[];
}

const WILDCARD = "*";

function ruleMatches(rule: PolicyRule, request: PolicyRequest): boolean {
  const agentMatches = rule.agent === WILDCARD || rule.agent === request.agent;
  const toolMatches = rule.tool === WILDCARD || rule.tool === request.tool;
  const scopesMatch =
    rule.scopes.includes(WILDCARD) || request.scopes.every((scope) => rule.scopes.includes(scope));
  return agentMatches && toolMatches && scopesMatch;
}

/**
 * Evaluate a request against a policy. First matching rule wins; if none matches, the
 * decision is deny (`policy:default-deny`). The reason is precise and stable so denials
 * are explainable and audit-friendly.
 */
export function evaluatePolicy(policy: Policy, request: PolicyRequest): PolicyDecision {
  for (const [index, rule] of policy.rules.entries()) {
    if (ruleMatches(rule, request)) {
      const decision: Decision = rule.effect;
      return { decision, reason: `policy:rule-${index}:${rule.effect}` };
    }
  }
  return { decision: "deny", reason: "policy:default-deny" };
}

/** Load and validate a policy from a local JSON file. */
export async function loadPolicyFromFile(path: string): Promise<Policy> {
  const raw = await readFile(path, "utf8");
  return policySchema.parse(JSON.parse(raw));
}
