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
  /**
   * AgentCapability validity — the *grant*, not the proof.
   *
   * Thirty days, deliberately, and the reasoning matters because it looks like a weakening:
   *
   * Short-lived credentials are how a system that *cannot* check revocation bounds its damage.
   * An OAuth access token lives fifteen minutes because nothing consults a revocation list
   * before honouring it. We do: `isRevoked` runs on every single call, reads the list fresh,
   * and fails closed. **Revocation is the kill switch; expiry is a backstop** — for a verifier
   * with no revocation source, one that is offline, or a list that was lost.
   *
   * A one-hour grant did not make anything safer. It made every operator's first act be
   * `--expires 2592000`, which teaches them on day one that our defaults are to be overridden.
   * An agent that runs unattended at 3am is exactly the agent nobody is there to re-onboard.
   *
   * The security property that does the work is unchanged: revoke, and the very next call dies.
   * Rotate with `roguezero renew`, which supersedes the old capability and revokes it.
   */
  capabilitySeconds: 30 * 24 * 60 * 60, // 30 days
  /**
   * Presentation (per-call proof) validity. This is the replay window, and it stays short —
   * it is the one lifetime where "short" is the control rather than a backstop.
   */
  presentationSeconds: 5 * 60, // 5 minutes
  /** Verification challenge / nonce validity. */
  challengeSeconds: 2 * 60, // 2 minutes
  /**
   * How long a signed revocation list stays fresh (its `exp` — a CRL's `nextUpdate`).
   *
   * This single number is the revocation-propagation / outage-tolerance trade. A verifier
   * fails closed once the list is stale, so a *shorter* window bounds how long a revoked
   * credential can keep working (worst case: this long) at the cost of stopping every agent
   * if the publisher goes quiet for that long. The publisher must therefore re-sign on a
   * schedule **even when nothing has changed**.
   *
   * One hour is the self-hosted default: forgiving of a laptop, a cron job, or a CI runner.
   * A hosted publisher on a CDN can afford a far tighter window, and that tightness — not the
   * verification, which is local and free — is what's worth paying for.
   */
  revocationListSeconds: 60 * 60, // 1 hour
} as const;

/** Allowed clock skew when validating time-based claims (seconds). */
export const DEFAULT_CLOCK_SKEW_SECONDS = 30;
