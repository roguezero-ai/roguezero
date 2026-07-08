/**
 * Issue and verify the two MVP credential types as JWT VCs (`did-jwt-vc`):
 * AgentProfile (who the agent is, who controls it) and AgentCapability (what tools +
 * scopes it may use, until when, bound to which audience).
 *
 * Signing uses our own EdDSA signer over `@noble/curves` (the same vetted library as
 * identity) rather than re-deriving key formats — no hand-rolled crypto, no guessing at
 * another library's secret-key encoding. Verification checks signature, issuer resolution,
 * and expiry via `did-jwt-vc`, then validates the credential type and subject shape with
 * Zod at the trust boundary. Issuer allowlist, audience/nonce binding, and revocation are
 * layered on in the F6 pipeline; this module is issuance + credential-intrinsic checks.
 */

import { randomUUID } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519";
import type { Signer } from "did-jwt";
import {
  createVerifiableCredentialJwt,
  verifyCredential,
  type Issuer,
  type JwtCredentialPayload,
} from "did-jwt-vc";
import type { Resolvable } from "did-resolver";
import { z } from "zod";
import {
  CREDENTIAL_TYPES,
  DEFAULT_CLOCK_SKEW_SECONDS,
  DEFAULT_LIFETIMES,
  VERIFIABLE_CREDENTIAL_TYPE,
} from "./constants.js";
import { VerificationError } from "./errors.js";
import type { AgentCapabilitySubject, AgentProfileSubject, Did } from "./types.js";

const VC_CONTEXT = "https://www.w3.org/2018/credentials/v1";
const SIGNING_ALG = "EdDSA";

// --- Schemas (trust boundary) ----------------------------------------------------

const didSchema = z.string().regex(/^did:(key|web):.+/, "must be a did:key or did:web identifier");

const toolGrantSchema = z.object({
  name: z.string().min(1),
  scopes: z.array(z.string().min(1)),
});

export const agentProfileSubjectSchema = z.object({
  id: didSchema,
  controller: didSchema,
  name: z.string().min(1),
  description: z.string().optional(),
});

export const agentCapabilitySubjectSchema = z.object({
  id: didSchema,
  tools: z.array(toolGrantSchema).min(1),
  audience: z.string().min(1),
});

// --- Issuance --------------------------------------------------------------------

/** A signing identity: its DID and the Ed25519 private key that DID resolves to. */
export interface CredentialSigner {
  did: Did;
  privateKey: Uint8Array;
}

/** Options controlling credential validity. Short-lived by default. */
export interface IssueOptions {
  /** Seconds until expiry (default: short, per DEFAULT_LIFETIMES). */
  expiresInSeconds?: number;
  /** Override issuance time (unix seconds); mainly for tests. */
  issuedAt?: number;
}

function edDsaSigner(privateKey: Uint8Array): Signer {
  return async (data) => {
    const message = typeof data === "string" ? new TextEncoder().encode(data) : data;
    return Buffer.from(ed25519.sign(message, privateKey)).toString("base64url");
  };
}

/** Build a did-jwt-vc Issuer from a signer. Exported so presentations can sign too. */
export function signerToIssuer(signer: CredentialSigner): Issuer {
  return { did: signer.did, alg: SIGNING_ALG, signer: edDsaSigner(signer.privateKey) };
}

async function issueCredential(
  signer: CredentialSigner,
  credentialType: string,
  credentialSubject: AgentProfileSubject | AgentCapabilitySubject,
  options: IssueOptions,
): Promise<string> {
  const nbf = options.issuedAt ?? Math.floor(Date.now() / 1000);
  const exp = nbf + (options.expiresInSeconds ?? DEFAULT_LIFETIMES.capabilitySeconds);
  const payload: JwtCredentialPayload = {
    sub: credentialSubject.id,
    // Stable per-credential id, used for revocation lookup and audit evidence.
    jti: `urn:uuid:${randomUUID()}`,
    nbf,
    exp,
    vc: {
      "@context": [VC_CONTEXT],
      type: [VERIFIABLE_CREDENTIAL_TYPE, credentialType],
      credentialSubject,
    },
  };
  return createVerifiableCredentialJwt(payload, signerToIssuer(signer));
}

/** Issue an AgentProfile credential. The signer is the controlling entity. */
export async function issueAgentProfileCredential(
  signer: CredentialSigner,
  subject: AgentProfileSubject,
  options: IssueOptions = {},
): Promise<string> {
  const parsed = agentProfileSubjectSchema.parse(subject);
  return issueCredential(signer, CREDENTIAL_TYPES.agentProfile, parsed, options);
}

/** Issue an AgentCapability credential (tools + scopes + audience). */
export async function issueAgentCapabilityCredential(
  signer: CredentialSigner,
  subject: AgentCapabilitySubject,
  options: IssueOptions = {},
): Promise<string> {
  const parsed = agentCapabilitySubjectSchema.parse(subject);
  return issueCredential(signer, CREDENTIAL_TYPES.agentCapability, parsed, options);
}

// --- Verification ----------------------------------------------------------------

interface VerifiedCredentialBase {
  jwt: string;
  /** Credential id (jti) — used for revocation lookup and audit evidence. */
  id?: string;
  /** The issuer DID (from `iss`, signature-verified). */
  issuer: Did;
  /** Unix-second issuance / expiry, when present. */
  issuedAt?: number;
  expiresAt?: number;
}

export interface VerifiedAgentProfile extends VerifiedCredentialBase {
  subject: AgentProfileSubject;
}

export interface VerifiedAgentCapability extends VerifiedCredentialBase {
  subject: AgentCapabilitySubject;
}

/**
 * A credential whose signature, issuer resolution, and expiry are verified, but whose
 * type and subject have not yet been interpreted. The pipeline verifies each embedded
 * credential once into an envelope, then classifies it — avoiding double verification.
 */
export interface VerifiedCredentialEnvelope {
  jwt: string;
  id?: string;
  issuer: Did;
  types: string[];
  credentialSubject: unknown;
  issuedAt?: number;
  expiresAt?: number;
}

/** Map an underlying did-jwt(-vc) verification error to a precise VerificationError. */
function mapVerifyError(error: unknown): VerificationError {
  const message = error instanceof Error ? error.message : String(error);
  if (/expired/i.test(message)) {
    return new VerificationError(`credential has expired: ${message}`, "expired");
  }
  if (/not valid before|nbf|early/i.test(message)) {
    return new VerificationError(`credential is not yet valid: ${message}`, "not-yet-valid");
  }
  if (/signature|invalid_signature/i.test(message)) {
    return new VerificationError(`credential signature is invalid: ${message}`, "bad-signature");
  }
  if (/resolve|resolver|DID document|no DID/i.test(message)) {
    return new VerificationError(
      `issuer DID could not be resolved: ${message}`,
      "unresolvable-did",
    );
  }
  return new VerificationError(
    `credential could not be verified: ${message}`,
    "malformed-credential",
  );
}

/**
 * Verify a credential's signature, issuer resolution, and expiry (type-agnostic). This is
 * the shared first stage for both the typed verifiers below and the request pipeline.
 */
export async function verifyCredentialEnvelope(
  jwt: string,
  resolver: Resolvable,
): Promise<VerifiedCredentialEnvelope> {
  let verified;
  try {
    // Explicit, tight clock-skew tolerance (seconds) — did-jwt's default is a loose 300s,
    // which would keep short-lived credentials valid minutes past expiry.
    verified = await verifyCredential(jwt, resolver, { skewTime: DEFAULT_CLOCK_SKEW_SECONDS });
  } catch (error) {
    throw mapVerifyError(error);
  }
  const vc = verified.verifiableCredential;
  const types = Array.isArray(vc.type) ? vc.type : [vc.type];
  const payload = verified.payload as { nbf?: number; exp?: number; jti?: string };
  return {
    jwt,
    id: vc.id ?? payload.jti,
    issuer: verified.issuer,
    types,
    credentialSubject: vc.credentialSubject,
    issuedAt: payload.nbf,
    expiresAt: payload.exp,
  };
}

/** Assert an envelope is of the expected credential type. */
export function requireCredentialType(env: VerifiedCredentialEnvelope, expectedType: string): void {
  if (!env.types.includes(expectedType)) {
    throw new VerificationError(
      `expected a ${expectedType} credential, got [${env.types.join(", ")}]`,
      "malformed-credential",
    );
  }
}

/** Validate an envelope's subject against a schema, or throw a precise VerificationError. */
export function parseCredentialSubject<T>(
  env: VerifiedCredentialEnvelope,
  schema: z.ZodType<T>,
  expectedType: string,
): T {
  const result = schema.safeParse(env.credentialSubject);
  if (!result.success) {
    throw new VerificationError(
      `${expectedType} subject failed validation: ${result.error.message}`,
      "malformed-credential",
    );
  }
  return result.data;
}

/** Verify an AgentProfile credential: signature, issuer resolution, expiry, shape. */
export async function verifyAgentProfileCredential(
  jwt: string,
  resolver: Resolvable,
): Promise<VerifiedAgentProfile> {
  const env = await verifyCredentialEnvelope(jwt, resolver);
  requireCredentialType(env, CREDENTIAL_TYPES.agentProfile);
  const subject = parseCredentialSubject(
    env,
    agentProfileSubjectSchema,
    CREDENTIAL_TYPES.agentProfile,
  );
  return {
    jwt,
    id: env.id,
    issuer: env.issuer,
    subject,
    issuedAt: env.issuedAt,
    expiresAt: env.expiresAt,
  };
}

/** Verify an AgentCapability credential: signature, issuer resolution, expiry, shape. */
export async function verifyAgentCapabilityCredential(
  jwt: string,
  resolver: Resolvable,
): Promise<VerifiedAgentCapability> {
  const env = await verifyCredentialEnvelope(jwt, resolver);
  requireCredentialType(env, CREDENTIAL_TYPES.agentCapability);
  const subject = parseCredentialSubject(
    env,
    agentCapabilitySubjectSchema,
    CREDENTIAL_TYPES.agentCapability,
  );
  return {
    jwt,
    id: env.id,
    issuer: env.issuer,
    subject,
    issuedAt: env.issuedAt,
    expiresAt: env.expiresAt,
  };
}
