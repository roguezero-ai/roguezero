/**
 * Verifiable Presentations: the per-call proof an agent presents to a protected tool.
 *
 * The agent (holder) signs a VP that wraps its AgentProfile + AgentCapability credentials
 * and binds the call to a one-time `challenge` (nonce) and a `domain` (the tool's
 * audience). Binding is what stops replay (nonce) and confused-deputy across tools (domain):
 * a presentation minted for tool A cannot be verified at tool B, and cannot be replayed at
 * tool A. Short-lived by default.
 *
 * After verifying the holder signature and domain, we re-extract the *raw* embedded
 * credential JWTs from the signed payload (via decodeJWT) so the pipeline can independently
 * verify each credential and hash it for audit — the parsed form loses the original JWT.
 */

import { decodeJWT } from "did-jwt";
import {
  createVerifiablePresentationJwt,
  verifyPresentation,
  type JwtPresentationPayload,
} from "did-jwt-vc";
import type { Resolvable } from "did-resolver";
import { DEFAULT_CLOCK_SKEW_SECONDS, DEFAULT_LIFETIMES } from "./constants.js";
import { signerToIssuer, type CredentialSigner } from "./credentials.js";
import { VerificationError } from "./errors.js";
import type { Did } from "./types.js";

const VC_CONTEXT = "https://www.w3.org/2018/credentials/v1";

export interface PresentationCredentials {
  profileVc: string;
  capabilityVc: string;
}

export interface CreatePresentationOptions {
  /** One-time nonce obtained from the verifier's challenge. */
  challenge: string;
  /** The tool/resource audience this presentation is bound to. */
  audience: string;
  expiresInSeconds?: number;
}

/** Create a holder-signed presentation bound to a challenge and audience. */
export async function createPresentation(
  holder: CredentialSigner,
  credentials: PresentationCredentials,
  options: CreatePresentationOptions,
): Promise<string> {
  const nbf = Math.floor(Date.now() / 1000);
  const payload: JwtPresentationPayload = {
    nbf,
    exp: nbf + (options.expiresInSeconds ?? DEFAULT_LIFETIMES.presentationSeconds),
    vp: {
      "@context": [VC_CONTEXT],
      type: ["VerifiablePresentation"],
      verifiableCredential: [credentials.profileVc, credentials.capabilityVc],
    },
  };
  return createVerifiablePresentationJwt(payload, signerToIssuer(holder), {
    challenge: options.challenge,
    domain: options.audience,
  });
}

export interface VerifiedPresentation {
  /** The holder (presenter) DID — signature-verified. */
  holder: Did;
  /** The one-time challenge nonce carried by the presentation. */
  nonce: string;
  /** Raw embedded credential JWTs, in presentation order. */
  credentialJwts: string[];
}

function mapPresentationError(error: unknown): VerificationError {
  const message = error instanceof Error ? error.message : String(error);
  if (/domain|audience/i.test(message)) {
    return new VerificationError(
      `presentation audience/domain mismatch: ${message}`,
      "audience-mismatch",
    );
  }
  if (/expired/i.test(message)) {
    return new VerificationError(`presentation has expired: ${message}`, "expired");
  }
  if (/signature|invalid_signature/i.test(message)) {
    return new VerificationError(`presentation signature is invalid: ${message}`, "bad-signature");
  }
  if (/resolve|resolver|DID document|no DID/i.test(message)) {
    return new VerificationError(
      `holder DID could not be resolved: ${message}`,
      "unresolvable-did",
    );
  }
  return new VerificationError(
    `presentation could not be verified: ${message}`,
    "malformed-credential",
  );
}

/**
 * Verify a presentation's holder signature and audience binding, returning the holder,
 * the nonce (validated against the NonceStore by the pipeline), and the raw embedded
 * credential JWTs. Does not consume the nonce or verify the embedded credentials — that is
 * the pipeline's job.
 */
export async function verifyPresentationJwt(
  presentationJwt: string,
  resolver: Resolvable,
  audience: string,
): Promise<VerifiedPresentation> {
  let result;
  try {
    result = await verifyPresentation(presentationJwt, resolver, {
      domain: audience,
      skewTime: DEFAULT_CLOCK_SKEW_SECONDS,
    });
  } catch (error) {
    throw mapPresentationError(error);
  }

  const nonce = (result.payload as { nonce?: string }).nonce;
  if (!nonce) {
    throw new VerificationError("presentation is missing its challenge nonce", "nonce-invalid");
  }

  // Signature is verified; re-read the raw embedded JWTs from the signed payload.
  const decoded = decodeJWT(presentationJwt);
  const embedded = (decoded.payload as { vp?: { verifiableCredential?: unknown } }).vp
    ?.verifiableCredential;
  const list = Array.isArray(embedded) ? embedded : embedded ? [embedded] : [];
  const credentialJwts = list.filter((c): c is string => typeof c === "string");

  return { holder: result.issuer, nonce, credentialJwts };
}
