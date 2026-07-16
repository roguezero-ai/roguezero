/**
 * Core domain types for the golden path.
 *
 * These are the in-memory shapes passed between core, middleware, and cli. Zod schemas
 * that validate these at trust boundaries (credential payloads, policy files, audit
 * events, middleware inputs) are added alongside the code that parses them (F4–F9); the
 * types here are the shared vocabulary those schemas will produce.
 */

import type { SUPPORTED_DID_METHODS } from "./constants.js";

/** A Decentralized Identifier, e.g. `did:key:z6Mk...` or `did:web:acme.example`. */
export type Did = string;

/** DID methods supported in the MVP. */
export type DidMethod = (typeof SUPPORTED_DID_METHODS)[number];

/** A generated agent key pair. Private material never leaves the process boundary. */
export interface AgentKeyPair {
  did: Did;
  /** multibase-encoded public key. */
  publicKeyMultibase: string;
  /** Opaque handle to the private key; never logged, never serialized to audit. */
  privateKey: Uint8Array;
}

// --- Credentials -----------------------------------------------------------------

/** Who the agent is and who controls it. Subject of an AgentProfile credential. */
export interface AgentProfileSubject {
  /** The agent's own DID. */
  id: Did;
  /** The controlling entity (operator/org) DID. */
  controller: Did;
  name: string;
  description?: string;
}

/** A single tool grant: a tool name and the scopes permitted on it. */
export interface ToolGrant {
  name: string;
  scopes: string[];
}

/** What the agent may do. Subject of an AgentCapability credential. */
export interface AgentCapabilitySubject {
  /** The agent DID this capability is granted to. */
  id: Did;
  tools: ToolGrant[];
  /** The resource server / tool endpoint this capability is bound to. */
  audience: string;
}

/** Pointer to a credential's entry in a revocation list. */
export interface CredentialStatus {
  type: string;
  /** List URL plus fragment index, e.g. `https://.../revocations.json#42`. */
  id: string;
}

// --- Policy ----------------------------------------------------------------------

export type PolicyEffect = "allow" | "deny";

/** One declarative rule. First match wins; absence of a match is default deny. */
export interface PolicyRule {
  agent: Did;
  tool: string;
  scopes: string[];
  effect: PolicyEffect;
}

export type Decision = "allow" | "deny";

/** Result of evaluating policy for a request. */
export interface PolicyDecision {
  decision: Decision;
  /** Machine + human readable reason, e.g. `policy:rule-3` or `policy:default-deny`. */
  reason: string;
}

// --- Verification ----------------------------------------------------------------

/**
 * Every distinct way verification can fail. Each maps to a precise, developer-facing
 * error message — errors are product. Never collapse these into a generic
 * "invalid credential".
 */
export type VerificationFailureReason =
  | "bad-signature"
  | "untrusted-issuer"
  | "expired"
  | "not-yet-valid"
  | "audience-mismatch"
  | "nonce-invalid"
  | "nonce-replayed"
  | "revoked"
  // Revocation *source* failures. Distinct from `revoked` because they are operational, not
  // a verdict about the credential — and distinct from each other because the response
  // differs: page someone, fix a config, or treat it as an attack.
  | "revocation-list-unavailable"
  | "revocation-list-stale"
  | "revocation-list-untrusted"
  | "revocation-list-invalid"
  | "revocation-list-rollback"
  | "malformed-credential"
  | "unresolvable-did"
  // Presenter is not the subject the credential was issued to (confused-deputy defense),
  // or an issuer does not match the agent's declared controller.
  | "holder-mismatch"
  | "policy-deny";

// --- Audit -----------------------------------------------------------------------

/**
 * An append-only audit event. Evidence carries credential hashes/IDs, never key material
 * or full secrets, so a decision can be reconstructed without leaking credentials.
 */
export interface AuditEvent {
  /** ISO 8601 timestamp. */
  ts: string;
  /** Correlation ID linking challenge → call → decision. */
  correlationId: string;
  /** The acting agent DID. */
  actor: Did;
  /** The credential issuer / controller DID. */
  subject: Did;
  tool: string;
  decision: Decision;
  /** Precise reason: which check failed, or which policy rule allowed. */
  reason: string;
  evidence: {
    profileVc?: string;
    capabilityVc?: string;
    nonce?: string;
    /** Hash of the attempted presentation — set on failures where credentials didn't verify,
     * so repeated attack attempts are correlatable even when actor/subject are unknown. */
    presentation?: string;
  };
  /**
   * What the agent tried to do — so a denied call shows *what was blocked*, not just that it was.
   * Agent-supplied only: `args` are the tool arguments the agent sent (the vault credential is
   * decrypted after authorization, so it is never here); `target` is the resolved request that was
   * (or would be) dispatched, never its Authorization header. Size-capped to bound the log.
   */
  attempt?: {
    args?: Record<string, unknown>;
    target?: { method: string; url: string };
    /** True when `args` was dropped because it exceeded the audit size cap. */
    truncated?: boolean;
  };
}
