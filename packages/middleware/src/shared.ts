/**
 * Shared configuration and context for the transport guards (MCP, HTTP). Both transports
 * are thin shells over the same `authorizeToolCall`, so the verification context they need
 * is identical and lives here.
 */

import type {
  AuditSink,
  Did,
  NonceStore,
  Policy,
  Resolvable,
  RevocationChecker,
  VerifiedRequest,
} from "@roguezero/core";

export interface RogueZeroGuardOptions {
  /** This endpoint's audience; presentations must be bound to it. */
  audience: string;
  resolver: Resolvable;
  trustedIssuers: Iterable<Did>;
  nonceStore: NonceStore;
  policy: Policy;
  auditSink: AuditSink;
  /**
   * Required. A guard without a revocation source has no kill switch, and that must be a
   * decision someone typed — pass `neverRevoked` from `@roguezero/core` to opt out explicitly.
   */
  isRevoked: RevocationChecker;
}

/** What a protected handler receives once a call is authorized. */
export interface AuthorizedContext {
  authorized: VerifiedRequest;
  correlationId: string;
}
