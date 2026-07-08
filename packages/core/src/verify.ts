/**
 * The request verification pipeline: the single, ordered, fail-closed sequence every
 * protected tool call passes through. Any failure throws a typed VerificationError naming
 * the exact check that failed; nothing here returns a soft "maybe".
 *
 * Order (each step gates the next):
 *   1. Presentation: holder signature + audience/domain binding.
 *   2. Nonce: single-use consumption against the store (replay defense).
 *   3. Credentials: verify each embedded VC (signature, issuer resolution, expiry).
 *   4. Structure: exactly one AgentProfile + one AgentCapability.
 *   5. Issuer trust: both issuers on the allowlist.
 *   6. Binding (confused-deputy defense): holder == both subjects; profile issued by the
 *      agent's declared controller; capability issued by that same controller.
 *   7. Audience: the capability is scoped to this tool's audience.
 *   8. Revocation: neither credential is revoked.
 *
 * Revocation is injected (default: nothing revoked) so F7 fills it without touching this
 * file — the checker is the seam.
 */

import type { Resolvable } from "did-resolver";
import {
  parseCredentialSubject,
  verifyCredentialEnvelope,
  agentCapabilitySubjectSchema,
  agentProfileSubjectSchema,
  type VerifiedCredentialEnvelope,
} from "./credentials.js";
import { CREDENTIAL_TYPES } from "./constants.js";
import { VerificationError, type VerificationErrorContext } from "./errors.js";
import { sha256Hex } from "./hash.js";
import type { NonceStore } from "./nonce.js";
import { verifyPresentationJwt } from "./presentation.js";
import type { AuditEvent, Did, ToolGrant } from "./types.js";

/** Decides whether a verified credential has been revoked. Default: nothing revoked. */
export type RevocationChecker = (credential: { id?: string; issuer: Did }) => Promise<boolean>;

export interface VerifyRequestOptions {
  /** The holder-signed presentation JWT presented with the call. */
  presentation: string;
  /** The audience of the tool being called; the presentation must be bound to it. */
  audience: string;
  resolver: Resolvable;
  /** Issuer allowlist — only credentials from these DIDs are trusted. */
  trustedIssuers: Iterable<Did>;
  /** Single-use challenge store; the presentation's nonce is consumed here. */
  nonceStore: NonceStore;
  /** Revocation check (F7 provides the real one). */
  isRevoked?: RevocationChecker;
}

export interface VerifiedRequest {
  /** The agent (presentation holder) DID. */
  agent: Did;
  /** The controlling entity that authorized the agent. */
  controller: Did;
  /** The capability issuer DID. */
  issuer: Did;
  /** Tools + scopes this capability grants. */
  tools: ToolGrant[];
  /** The audience the capability (and this request) is bound to. */
  audience: string;
  /** The consumed challenge nonce. */
  nonce: string;
  /** Audit evidence: credential/nonce hashes, never raw tokens. */
  evidence: AuditEvent["evidence"];
}

const noRevocation: RevocationChecker = async () => false;

export async function verifyRequest(options: VerifyRequestOptions): Promise<VerifiedRequest> {
  const { presentation, audience, resolver, nonceStore, isRevoked = noRevocation } = options;
  const trusted = new Set(options.trustedIssuers);

  // 1. Presentation: holder signature + audience binding.
  const vp = await verifyPresentationJwt(presentation, resolver, audience);

  // 2. Nonce: single-use consumption (replay defense).
  const consumed = await nonceStore.consume(vp.nonce, audience);
  if (consumed !== "ok") {
    if (consumed === "replayed") {
      throw new VerificationError("challenge nonce already used", "nonce-replayed");
    }
    if (consumed === "audience-mismatch") {
      throw new VerificationError(
        "challenge nonce was issued for a different audience",
        "audience-mismatch",
      );
    }
    throw new VerificationError(`challenge nonce is ${consumed}`, "nonce-invalid");
  }

  // 3. Credentials: verify each embedded VC once (signature, issuer resolution, expiry).
  const envelopes = await Promise.all(
    vp.credentialJwts.map((jwt) => verifyCredentialEnvelope(jwt, resolver)),
  );

  // 4. Structure: exactly the two expected credential types.
  const profileEnv = findByType(envelopes, CREDENTIAL_TYPES.agentProfile);
  const capabilityEnv = findByType(envelopes, CREDENTIAL_TYPES.agentCapability);
  if (!profileEnv || !capabilityEnv) {
    throw new VerificationError(
      "presentation must include one AgentProfile and one AgentCapability credential",
      "malformed-credential",
    );
  }
  const profile = parseCredentialSubject(
    profileEnv,
    agentProfileSubjectSchema,
    CREDENTIAL_TYPES.agentProfile,
  );
  const capability = parseCredentialSubject(
    capabilityEnv,
    agentCapabilitySubjectSchema,
    CREDENTIAL_TYPES.agentCapability,
  );

  // 5. Issuer trust.
  if (!trusted.has(profileEnv.issuer) || !trusted.has(capabilityEnv.issuer)) {
    throw new VerificationError(
      `credential issuer is not on the trusted allowlist (profile: ${profileEnv.issuer}, capability: ${capabilityEnv.issuer})`,
      "untrusted-issuer",
    );
  }

  // 6. Binding (confused-deputy defense). Before this passes we cannot claim an "agent":
  // the presenter is authenticated, but not yet confirmed to be the credential subject.
  const agent = vp.holder;
  if (profile.id !== agent || capability.id !== agent) {
    throw new VerificationError(
      "presentation holder is not the subject of the presented credentials",
      "holder-mismatch",
    );
  }

  // Binding confirmed: the presenter IS the credential subject. From here, failures name the
  // actor and carry evidence — so a revoked denial audits the agent, not "unknown".
  const identified: VerificationErrorContext = {
    agent,
    controller: profile.controller,
    evidence: {
      profileVc: sha256Hex(profileEnv.jwt),
      capabilityVc: sha256Hex(capabilityEnv.jwt),
      nonce: sha256Hex(vp.nonce),
    },
  };

  if (profileEnv.issuer !== profile.controller) {
    throw new VerificationError(
      "AgentProfile was not issued by the agent's declared controller",
      "untrusted-issuer",
      identified,
    );
  }
  if (capabilityEnv.issuer !== profile.controller) {
    throw new VerificationError(
      "AgentCapability was not issued by the agent's controller",
      "untrusted-issuer",
      identified,
    );
  }

  // 7. Audience: the capability is scoped to this tool.
  if (capability.audience !== audience) {
    throw new VerificationError(
      `capability is scoped to ${capability.audience}, not ${audience}`,
      "audience-mismatch",
      identified,
    );
  }

  // 8. Revocation.
  if (
    (await isRevoked({ id: profileEnv.id, issuer: profileEnv.issuer })) ||
    (await isRevoked({ id: capabilityEnv.id, issuer: capabilityEnv.issuer }))
  ) {
    throw new VerificationError("a presented credential has been revoked", "revoked", identified);
  }

  return {
    agent,
    controller: profile.controller,
    issuer: capabilityEnv.issuer,
    tools: capability.tools,
    audience,
    nonce: vp.nonce,
    evidence: identified.evidence ?? {},
  };
}

function findByType(
  envelopes: VerifiedCredentialEnvelope[],
  type: string,
): VerifiedCredentialEnvelope | undefined {
  return envelopes.find((env) => env.types.includes(type));
}
