/**
 * Typed errors thrown by core. Middleware and CLI map these to protocol-appropriate
 * responses. Each carries a stable code so callers can branch without string-matching
 * messages — errors are product.
 */

import type { AuditEvent, Did, VerificationFailureReason } from "./types.js";

/** A DID could not be parsed, is an unsupported method, or failed to resolve. */
export class DidError extends Error {
  readonly code: string;
  constructor(message: string, code = "did-error") {
    super(message);
    this.name = "DidError";
    this.code = code;
  }
}

/**
 * A credential or presentation failed verification. `reason` names exactly which check
 * failed so callers (and audit events) can report and branch precisely — never collapse
 * these into a generic "invalid".
 */
/**
 * Identity known at the point of failure. Populated only once binding is confirmed (the
 * presenter cryptographically is the credential subject), so a post-binding denial — e.g.
 * a revoked credential — can name the actor instead of auditing "unknown".
 */
export interface VerificationErrorContext {
  agent?: Did;
  controller?: Did;
  evidence?: AuditEvent["evidence"];
}

export class VerificationError extends Error {
  readonly reason: VerificationFailureReason;
  readonly context?: VerificationErrorContext;
  constructor(
    message: string,
    reason: VerificationFailureReason,
    context?: VerificationErrorContext,
  ) {
    super(message);
    this.name = "VerificationError";
    this.reason = reason;
    this.context = context;
  }
}
