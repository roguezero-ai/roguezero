/**
 * Public API of @roguezero/core.
 *
 * Everything importable by middleware and cli is re-exported here; anything not exported
 * from this file is internal. Keeping this surface small is load-bearing (ADR 0001).
 */

export * from "./config.js";
export * from "./constants.js";
export * from "./types.js";
export * from "./errors.js";
export * from "./identity.js";
export * from "./did-web.js";
export * from "./resolver.js";
export * from "./credentials.js";
export * from "./hash.js";
export * from "./nonce.js";
export * from "./rate-limit.js";
export * from "./presentation.js";
export * from "./verify.js";
export * from "./revocation.js";
export * from "./vault.js";
export * from "./vault-keys.js";
export * from "./vault-store.js";
export * from "./registry.js";
export * from "./proxy.js";
export * from "./runtime.js";
export * from "./policy.js";
export * from "./audit.js";
export * from "./authorize.js";
export * from "./explain.js";
