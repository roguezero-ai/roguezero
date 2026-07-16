/**
 * The runtime spine (ADR 0005 D0) — the one handler that runs a protected tool call end to end, in
 * the fail-closed order, composing the trust spine with the new runtime pieces:
 *
 *   authenticate agent + capability + policy + revocation   (authorizeToolCall — reused as-is)
 *     └─ only if ALLOWED ─▶ resolve the pinned request (registry, SSRF-contained)
 *                          └─▶ decrypt the credential (vault)   ← the FIRST time we touch a secret
 *                             └─▶ inject + dispatch (proxy)
 *                                └─▶ audit the outcome; zero the credential bytes
 *
 * The ordering is the security property: **decrypt is last.** A call that fails authentication,
 * capability, policy, or revocation never causes a credential to be decrypted (T-INJ-10). The
 * authorization decision is audited by `authorizeToolCall`; the execution outcome is a supplementary
 * audit event here.
 */

import { authorizeToolCall, type AuthorizeToolCallOptions } from "./authorize.js";
import { buildAuditEvent, summarizeAttempt } from "./audit.js";
import { dispatchToolCall, type DispatchResult } from "./proxy.js";
import { getCredential, type Vault } from "./vault.js";
import { resolveRequest, type RequestPlan, type ToolRegistry } from "./registry.js";
import type { Decision } from "./types.js";

export interface RuntimeToolCallOptions extends AuthorizeToolCallOptions {
  /** How to reach each tool (pinned target + credential ref). */
  registry: ToolRegistry;
  /** Where the downstream credentials live, encrypted. */
  vault: Vault;
  /** Agent-supplied tool arguments (validated by the registry, never trusted raw). */
  args?: Record<string, unknown>;
  timeoutMs?: number;
  maxBytes?: number;
}

export interface RuntimeToolCallResult {
  /** True only when authorized AND the downstream call executed and returned. */
  ok: boolean;
  decision: Decision;
  reason: string;
  correlationId: string;
  /** The downstream response, when `ok`. */
  response?: DispatchResult;
  /** A denial reason or execution error, for the agent. Never contains a credential. */
  error?: string;
}

export async function handleToolCall(
  options: RuntimeToolCallOptions,
): Promise<RuntimeToolCallResult> {
  // 1–4. Authenticate + capability + policy + revocation (fails closed, audits the decision).
  const auth = await authorizeToolCall(options);
  if (auth.decision !== "allow" || !auth.request) {
    return {
      ok: false,
      decision: auth.decision,
      reason: auth.reason,
      correlationId: auth.correlationId,
      error: auth.reason,
    };
  }

  const { registry, vault, args = {}, tool, auditSink, timeoutMs, maxBytes } = options;
  const req = auth.request;
  const correlationId = auth.correlationId;

  // Resolved once step 5 succeeds, so outcome events can record the target actually dispatched.
  let plan: RequestPlan | undefined;

  // Supplementary, best-effort audit of the execution outcome (the *decision* was already audited).
  const auditOutcome = async (decision: Decision, reason: string): Promise<void> => {
    try {
      await auditSink.write(
        buildAuditEvent({
          actor: req.agent,
          subject: req.controller,
          tool,
          decision,
          reason,
          evidence: req.evidence,
          attempt: summarizeAttempt({
            args,
            target: plan ? { method: plan.method, url: plan.url } : undefined,
          }),
          correlationId,
        }),
      );
    } catch {
      /* the load-bearing authorization audit already succeeded; this outcome event is additive */
    }
  };

  // 5. Resolve the pinned request from the agent's args (SSRF-contained). Bad args → deny, no decrypt.
  try {
    plan = resolveRequest(registry, tool, args);
  } catch (err) {
    await auditOutcome("deny", "request:invalid-arguments");
    return {
      ok: false,
      decision: "deny",
      reason: "request:invalid-arguments",
      correlationId,
      error: err instanceof Error ? err.message : String(err),
    };
  }

  // 6. Decrypt the credential — the FIRST time we touch a secret, and only now (authz + revocation
  //    already passed). Missing credential is an operator misconfig, not an authz failure.
  let credential: Uint8Array;
  try {
    credential = await getCredential(vault, { ref: plan.credential.ref, toolId: tool });
  } catch {
    await auditOutcome("deny", "runtime:no-credential");
    return {
      ok: false,
      decision: "deny",
      reason: "runtime:no-credential",
      correlationId,
      error: `no credential for tool '${tool}'`,
    };
  }

  // 7–8. Inject + dispatch, then audit the outcome and zero the decrypted bytes (D3).
  try {
    const response = await dispatchToolCall(plan, { credential, timeoutMs, maxBytes });
    await auditOutcome("allow", `executed:${response.status}`);
    return { ok: true, decision: "allow", reason: auth.reason, correlationId, response };
  } catch (err) {
    await auditOutcome("deny", "runtime:execution-failed");
    return {
      ok: false,
      decision: "allow",
      reason: "runtime:execution-failed",
      correlationId,
      error: err instanceof Error ? err.message : String(err),
    };
  } finally {
    credential.fill(0);
  }
}
