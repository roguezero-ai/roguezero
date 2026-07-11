/**
 * Build a guard's options from a `roguezero.config.json`, so a protected server states its
 * trust settings once, in a file, instead of assembling seven collaborators by hand.
 *
 * This is the seam between the free, local enforcement path and a hosted control plane: the
 * same guard code runs either way, and which revocation source and audit sink it uses is a
 * config change. Nothing here reaches the network unless the config says to.
 *
 * The nonce store is in-memory and therefore per-process: correct for a stdio MCP server or a
 * single instance, wrong behind a load balancer (a challenge issued by one replica is unknown
 * to the next). Deployments that scale out pass their own shared store.
 */

import {
  createFileRevocationChecker,
  createHttpAuditSink,
  createInMemoryNonceStore,
  createJsonlAuditSink,
  createResolver,
  createSignedFileRevocationChecker,
  createUrlRevocationChecker,
  loadGuardConfig,
  loadPolicyFromFile,
  type AuditSink,
  type Did,
  type GuardConfig,
  type NonceStore,
  type Resolvable,
  type RevocationChecker,
} from "@roguezero/core";
import type { RogueZeroGuardOptions } from "./shared.js";

export interface GuardOptionsFromConfigOverrides {
  /** Replace the per-process nonce store (required for multi-instance deployments). */
  nonceStore?: NonceStore;
}

/**
 * A signed list is verified against the same `trustedIssuers` as the credentials themselves —
 * a list signed by anyone else could silently drop an entry and resurrect a revoked agent.
 */
function revocationCheckerFor(config: GuardConfig, resolver: Resolvable): RevocationChecker {
  const { revocation } = config;
  const trustedIssuers: Did[] = config.trustedIssuers;

  switch (revocation.source) {
    case "file":
      // Unsigned, local: the filesystem is the trust root.
      return createFileRevocationChecker(revocation.path, revocation.cacheTtlSeconds);
    case "signed-file":
      return createSignedFileRevocationChecker(revocation.path, {
        resolver,
        trustedIssuers,
        maxAgeSeconds: revocation.maxAgeSeconds,
        cacheTtlSeconds: revocation.cacheTtlSeconds,
      });
    case "url":
      return createUrlRevocationChecker(revocation.url, {
        resolver,
        trustedIssuers,
        maxAgeSeconds: revocation.maxAgeSeconds,
        cacheTtlSeconds: revocation.cacheTtlSeconds,
        timeoutMs: revocation.timeoutMs,
      });
  }
}

/**
 * The audit sink's credential is read here, from the environment, and never from the config
 * file — which gets committed. Missing it is fatal at guard construction rather than on the
 * first call: a sink that cannot authenticate makes every decision unauditable, and an
 * unauditable decision is denied. Better to refuse to start than to deny every call.
 */
function auditSinkFor(config: GuardConfig, configPath: string): AuditSink {
  const { audit } = config;
  if (audit.sink === "file") return createJsonlAuditSink(audit.path);

  let authorization: string | undefined;
  if (audit.authorizationEnv) {
    authorization = process.env[audit.authorizationEnv];
    if (!authorization) {
      throw new Error(
        `audit.authorizationEnv names ${audit.authorizationEnv}, but that environment variable ` +
          `is not set. The token belongs in the environment, never in ${configPath}.`,
      );
    }
  }
  return createHttpAuditSink({ url: audit.url, timeoutMs: audit.timeoutMs, authorization });
}

export async function guardOptionsFromConfig(
  configPath: string,
  overrides: GuardOptionsFromConfigOverrides = {},
): Promise<RogueZeroGuardOptions> {
  const config = await loadGuardConfig(configPath);
  const resolver = createResolver();
  return {
    audience: config.audience,
    resolver,
    trustedIssuers: config.trustedIssuers,
    nonceStore: overrides.nonceStore ?? createInMemoryNonceStore(),
    policy: await loadPolicyFromFile(config.policyPath),
    auditSink: auditSinkFor(config, configPath),
    isRevoked: revocationCheckerFor(config, resolver),
  };
}
