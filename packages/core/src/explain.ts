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
  "revocation-list-unavailable": {
    summary: "The revocation list couldn't be read, so the call was denied rather than allowed.",
    fix: "Check that the revocation source (file path or URL) is reachable. Verification fails closed: an unreadable revocation list is never treated as 'nothing is revoked'.",
  },
  "revocation-list-stale": {
    summary: "The revocation list is past its freshness window, so it can no longer be trusted.",
    fix: "Re-publish (re-sign) the list — publishers must re-sign on a schedule even when nothing changed. If you host it yourself, shorten the publish interval or lengthen the list's validity window.",
  },
  "revocation-list-untrusted": {
    summary: "The revocation list is signed by a DID that isn't on this server's trusted list.",
    fix: "Sign the list with a controller in trustedIssuers, or add its DID to trustedIssuers. A list signed by anyone else could hide a revocation.",
  },
  "revocation-list-invalid": {
    summary: "The revocation list's signature or format didn't verify.",
    fix: "Publish a list signed with `signRevocationList`. Remote lists must be signed — transport security alone would make whoever hosts the list able to forge it.",
  },
  "revocation-list-rollback": {
    summary: "The revocation list went backwards: an older list was served than one already seen.",
    fix: "Treat this as an attack or a broken cache/mirror — an old-but-still-valid list is how an attacker resurrects a revoked credential. Check who serves the list.",
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
