/**
 * authorizeToolCall: the one place that composes the full decision for a protected tool
 * call — verify → capability-grants-tool → policy → audit — so middleware (MCP, HTTP) stays
 * thin transport glue and can't accidentally skip a step.
 *
 * Three guarantees live here, tested once instead of in every transport:
 * - Fail closed: any verification error is a deny, never a throw that a caller might swallow.
 * - Every allow/deny path emits an audit event, including verification failures.
 * - Audit is load-bearing: if the sink itself fails, the call is denied with reason
 *   `audit-write-failed` rather than proceeding — an unauditable decision does not count.
 *
 * Two gates, defense in depth: the *capability* says what the agent was delegated (which
 * tools/scopes), and *policy* says what this deployment permits (default deny). Both must
 * pass.
 */

import type { Resolvable } from "did-resolver";
import {
  buildAuditEvent,
  newCorrelationId,
  type AuditEventInput,
  type AuditSink,
} from "./audit.js";
import { VerificationError } from "./errors.js";
import { sha256Hex } from "./hash.js";
import type { NonceStore } from "./nonce.js";
import { evaluatePolicy, type Policy } from "./policy.js";
import type { Decision, Did } from "./types.js";
import { verifyRequest, type RevocationChecker, type VerifiedRequest } from "./verify.js";

export interface AuthorizeToolCallOptions {
  /** The holder-signed presentation presented with the call. */
  presentation: string;
  /** The tool being invoked. */
  tool: string;
  /** This tool endpoint's audience; the presentation must be bound to it. */
  audience: string;
  resolver: Resolvable;
  trustedIssuers: Iterable<Did>;
  nonceStore: NonceStore;
  policy: Policy;
  auditSink: AuditSink;
  /**
   * Required, not optional. Grants are long-lived because this runs on every call and fails
   * closed; a guard without it has no kill switch. Pass `neverRevoked` to say so on purpose.
   */
  isRevoked: RevocationChecker;
  /** Correlation id linking challenge → call → decision; generated if omitted. */
  correlationId?: string;
}

export interface AuthorizeToolCallResult {
  decision: Decision;
  /** Precise, stable reason (e.g. `verify:revoked`, `capability:tool-not-granted`, `policy:rule-0:allow`). */
  reason: string;
  correlationId: string;
  /** The verified request — present only when the decision is `allow`. */
  request?: VerifiedRequest;
}

export async function authorizeToolCall(
  options: AuthorizeToolCallOptions,
): Promise<AuthorizeToolCallResult> {
  const { tool, auditSink } = options;
  const correlationId = options.correlationId ?? newCorrelationId();

  /**
   * Write an audit event; if the sink fails, the decision is void. Returns the intended
   * result on success, or an `audit-write-failed` deny — so an unauditable call never
   * proceeds and never throws an unhandled error at the transport.
   */
  const auditThen = async (
    input: AuditEventInput,
    intended: AuthorizeToolCallResult,
  ): Promise<AuthorizeToolCallResult> => {
    try {
      await auditSink.write(buildAuditEvent(input));
      return intended;
    } catch {
      return { decision: "deny", reason: "audit-write-failed", correlationId };
    }
  };

  // 1. Verify identity + capability + presentation (fail closed).
  let request: VerifiedRequest;
  try {
    request = await verifyRequest({
      presentation: options.presentation,
      audience: options.audience,
      resolver: options.resolver,
      trustedIssuers: options.trustedIssuers,
      nonceStore: options.nonceStore,
      isRevoked: options.isRevoked,
    });
  } catch (error) {
    const reason =
      error instanceof VerificationError ? `verify:${error.reason}` : "verify:internal-error";
    // If verification confirmed who the presenter is (e.g. a revoked credential passed
    // binding), name them; otherwise the actor is genuinely unknown and we log the
    // attempted-presentation hash so repeated attempts stay correlatable.
    const ctx = error instanceof VerificationError ? error.context : undefined;
    return auditThen(
      {
        actor: ctx?.agent ?? "unknown",
        subject: ctx?.controller ?? "unknown",
        tool,
        decision: "deny",
        reason,
        evidence: ctx?.evidence ?? { presentation: sha256Hex(options.presentation) },
        correlationId,
      },
      { decision: "deny", reason, correlationId },
    );
  }

  // 2. The capability must actually grant this tool (delegated authority).
  const grant = request.tools.find((t) => t.name === tool);
  if (!grant) {
    const reason = "capability:tool-not-granted";
    return auditThen(
      {
        actor: request.agent,
        subject: request.controller,
        tool,
        decision: "deny",
        reason,
        evidence: request.evidence,
        correlationId,
      },
      { decision: "deny", reason, correlationId },
    );
  }

  // 3. Policy decides (default deny), scoped to what the capability grants for this tool.
  const policyDecision = evaluatePolicy(options.policy, {
    agent: request.agent,
    tool,
    scopes: grant.scopes,
  });

  return auditThen(
    {
      actor: request.agent,
      subject: request.controller,
      tool,
      decision: policyDecision.decision,
      reason: policyDecision.reason,
      evidence: request.evidence,
      correlationId,
    },
    {
      decision: policyDecision.decision,
      reason: policyDecision.reason,
      correlationId,
      request: policyDecision.decision === "allow" ? request : undefined,
    },
  );
}
