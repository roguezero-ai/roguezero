# Changelog

All notable changes to `@roguezero/core`, `@roguezero/middleware`, and `@roguezero/cli` are
recorded here. The three packages are versioned together. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) (pre-1.0: minor versions may carry
breaking changes, called out below).

## [0.2.0] — 2026-07-10

Unattended agents: credentials that rotate on a schedule and a kill switch automation can't undo.

### Added

- **`roguezero renew --all`** — a controller-side scheduler for a cron. Renews every agent bundle
  in a directory that is due for renewal, and **refuses to renew a revoked agent**, so automation
  can never bring back an agent you killed. Fails closed if it has no writable revocation list to
  consult.
- **Live credential pickup:** `roguezero connect` now re-reads the agent bundle on every call, so
  a renewed credential reaches a running agent with no restart.
- **`docs/TRUST.md`** — a production-trust reference for security reviewers: measured per-call
  overhead, key-handling model, revocation and audit behavior, and the gaps consciously accepted
  (with the safe posture for each).
- **`scripts/bench-overhead.mjs`** — a reproducible benchmark of the per-call verification cost
  (~3 ms of CPU on the reference machine; run it on your own hardware to confirm).

### Changed

- **BREAKING (data format): `revocations.json` entries are now objects `{ id, expiresAt? }`**
  instead of bare id strings. The reader still accepts the old string form, so existing lists keep
  working — but lists **written** by 0.2.0 (`revoke`, `renew`) use objects. Update any external
  tooling that parsed the `revoked` array as an array of strings. The `expiresAt` field lets a
  publisher prune entries once the credential could no longer be presented anyway.
- `renew` now refuses to renew a credential that has been revoked, and reports why. Re-onboard the
  agent (a fresh identity) if it should run again.

### Notes

- No changes to credential, presentation, DID, or policy formats. A 0.1.0 agent bundle continues
  to verify unchanged.

## [0.1.0] — 2026-07-09

Initial public release.

- **`@roguezero/core`** — Ed25519 `did:key` / `did:web` identities; AgentProfile and
  AgentCapability credentials as JWT VCs; the fail-closed verification pipeline (signature →
  replay nonce → issuer allowlist → holder/controller binding → audience → revocation); declarative
  default-deny policy; append-only audit; signed and unsigned revocation lists.
- **`@roguezero/middleware`** — MCP and HTTP guards over the shared core (`./mcp`, `./http`
  subpaths; the SDK and Hono are optional peer dependencies).
- **`@roguezero/cli`** — `init`, `onboard`, `connect`, `renew`, `revoke`, `create`, `issue`,
  `verify`, `inspect`, and `revocations publish`.
- Published from CI over OIDC trusted publishing with provenance attestations.

[0.2.0]: https://github.com/roguezero-ai/roguezero/releases/tag/v0.2.0
[0.1.0]: https://github.com/roguezero-ai/roguezero/releases/tag/v0.1.0
