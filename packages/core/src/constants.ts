/**
 * Centralized, brand-neutral constants.
 *
 * Naming convention: identifiers, schema URIs, and protocol strings live here
 * so a rename of the product (currently "RogueZero") is a single-file change and never
 * leaks the brand into credential payloads or on-the-wire types.
 */

/**
 * Base URI for credential type / context identifiers we mint. Centralized here so a
 * brand/domain change is a single-string swap. Trailing slash intentional.
 */
export const SCHEMA_BASE_URI = "https://schemas.roguezero.ai/";

/** The two — and only two — credential types the MVP issues and verifies. */
export const CREDENTIAL_TYPES = {
  agentProfile: "AgentProfile",
  agentCapability: "AgentCapability",
} as const;

/** W3C VC base type present on every credential's `type` array. */
export const VERIFIABLE_CREDENTIAL_TYPE = "VerifiableCredential";

/** DID methods supported in the MVP. did:key for local dev, did:web for orgs. */
export const SUPPORTED_DID_METHODS = ["key", "web"] as const;

/** credentialStatus.type for our simple JSON revocation list (not Bitstring Status List yet). */
export const REVOCATION_STATUS_TYPE = "RevocationList2026";

/**
 * Default credential / presentation lifetimes (seconds). Short by default per the
 * security principle "short lifetimes by default"; longer requires an explicit flag.
 */
export const DEFAULT_LIFETIMES = {
  /** AgentCapability credential validity. */
  capabilitySeconds: 60 * 60, // 1 hour
  /** Presentation (per-call proof) validity. */
  presentationSeconds: 5 * 60, // 5 minutes
  /** Verification challenge / nonce validity. */
  challengeSeconds: 2 * 60, // 2 minutes
} as const;

/** Allowed clock skew when validating time-based claims (seconds). */
export const DEFAULT_CLOCK_SKEW_SECONDS = 30;
