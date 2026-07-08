/**
 * Plain-language explanations for every denial reason — the single source of truth for
 * "what happened and how do I fix it." This is the ease-of-use wedge in code: a denial
 * should never leave a developer guessing. The CLI and both middlewares render these, so
 * the same helpful message appears everywhere.
 *
 * Input is a surfaced reason string: a raw VerificationFailureReason, or a prefixed one
 * (`verify:<reason>`, `policy:<rule>`), or an authorize-level reason
 * (`capability:tool-not-granted`, `audit-write-failed`).
 */

export interface DenialExplanation {
  /** The raw reason string, unchanged. */
  reason: string;
  /** What happened, in one plain sentence. */
  summary: string;
  /** The most likely fix, actionable. */
  fix: string;
}

const EXPLANATIONS: Record<string, { summary: string; fix: string }> = {
  "bad-signature": {
    summary: "The presentation's signature didn't verify.",
    fix: "Sign with the agent's private key that matches its DID, and don't modify the credential after issuing it.",
  },
  "untrusted-issuer": {
    summary:
      "The credential's issuer isn't trusted by this server (or isn't the agent's declared controller).",
    fix: "Add the issuer DID to the server's trustedIssuers, and make sure the capability was issued by the same operator that controls the agent.",
  },
  expired: {
    summary: "A credential or the presentation has expired.",
    fix: "Re-issue the capability or mint a fresh presentation, and check the clocks on both machines.",
  },
  "not-yet-valid": {
    summary: "A credential isn't valid yet — its start time is in the future.",
    fix: "Wait until the credential's start time, or check the issuer's clock.",
  },
  "audience-mismatch": {
    summary:
      "The presentation isn't bound to this tool, or the capability is scoped to a different one.",
    fix: "Request a challenge from THIS server and bind the presentation to its audience, and issue the capability with a matching audience.",
  },
  "nonce-invalid": {
    summary: "The challenge nonce is unknown or expired.",
    fix: "Call request_challenge and use that nonce immediately — challenges are single-use and short-lived.",
  },
  "nonce-replayed": {
    summary: "This challenge was already used.",
    fix: "Get a fresh challenge for every call — nonces can't be reused.",
  },
  revoked: {
    summary: "A presented credential has been revoked.",
    fix: "Issue a new capability; a revoked one is permanently dead.",
  },
  "malformed-credential": {
    summary: "A credential or presentation couldn't be parsed or failed validation.",
    fix: "Send a valid JWT credential of the expected type (AgentProfile + AgentCapability) with a well-formed subject.",
  },
  "unresolvable-did": {
    summary: "An issuer or agent DID couldn't be resolved to its keys.",
    fix: "For did:web, make sure the DID document is reachable over HTTPS; for did:key, check the identifier isn't corrupted.",
  },
  "holder-mismatch": {
    summary: "The presenter isn't the agent the credential was issued to.",
    fix: "Present with the agent's own key — the capability's subject must be the presenter, and its issuer must be the agent's controller.",
  },
  "policy-deny": {
    summary: "Policy didn't allow this agent to use this tool with these scopes.",
    fix: "Add an allow rule for this agent, tool, and scopes (policy is default-deny), or grant the scope the tool needs.",
  },
  "capability:tool-not-granted": {
    summary: "The agent's capability doesn't grant this tool at all.",
    fix: "Issue a capability that includes this tool and the scopes it requires.",
  },
  "audit-write-failed": {
    summary: "The decision couldn't be written to the audit log, so it was denied.",
    fix: "Check the audit sink — disk space, file permissions, or connectivity. An unauditable decision fails closed by design.",
  },
  "internal-error": {
    summary: "Verification failed for an unexpected reason.",
    fix: "Check the server logs for the underlying error; this is not a normal denial.",
  },
};

function normalizeReason(reason: string): string {
  if (reason.startsWith("verify:")) return reason.slice("verify:".length);
  if (reason.startsWith("policy:")) return "policy-deny";
  return reason;
}

/** Explain a denial reason in plain language, with the most likely fix. */
export function explainDenial(reason: string): DenialExplanation {
  const known = EXPLANATIONS[normalizeReason(reason)];
  return {
    reason,
    summary: known?.summary ?? "The request was denied.",
    fix: known?.fix ?? "Check the reason code above and the server's audit log.",
  };
}
