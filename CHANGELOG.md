# Changelog

All notable changes to `@roguezero/core`, `@roguezero/middleware`, and `@roguezero/cli` are
recorded here. The three packages are versioned together. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) (pre-1.0: minor versions may carry
breaking changes, called out below).

## [0.4.0] — 2026-07-12

**Popular integrations, real APIs, and a hardened challenge endpoint.** Additive over 0.3.0 — from an
empty runtime to "my agent uses GitHub/Stripe/OpenAI without ever holding my token" in one command.

### Added

- **Starter-pack integrations + `roguezero add`** (`@roguezero/cli`) — a curated, security-reviewed,
  least-privilege set of eight popular tools (GitHub, Slack, Stripe, Notion, Sentry, HubSpot,
  Airtable, OpenAI). `roguezero add <name>` registers the tool and, with `RZ_SECRET`/stdin +
  `RZ_VAULT_PASSPHRASE`, vaults its credential — bound to the tool. `roguezero add` lists the pack.
  Not a catalog: a fixed reviewed set; the long tail stays a user's own `registry.json`.
- **Static request headers on a tool definition** (`@roguezero/core`) — `headers` on a tool def sets
  operator headers a real API demands (`Accept`, `User-Agent`, an API-version header). Guarded: a
  static header can't impersonate the credential/`authorization` header, and can't carry CRLF.
- **`bodyTemplate` — nested JSON request bodies** (`@roguezero/core`) — a tool def may declare a
  nested body with `{param}` placeholders filled by `in: "body"` params, for APIs whose payload
  isn't a flat object (OpenAI chat, GraphQL, SendGrid). Agent values only occupy leaf slots and are
  typed/validated, so they can't reshape the JSON; a lone placeholder keeps its param's type (a
  number stays a JSON number). The flat-object body remains the default.

### Security

- **Per-client rate limit on `GET /challenge`** (`@roguezero/core`, `createRuntimeServer`) — the one
  unauthenticated endpoint (nonce minting) is now throttled by a self-bounding token bucket
  (`createRateLimiter`), secure by default, keyed on the socket address (never a spoofable
  `X-Forwarded-For`); returns `429` + `Retry-After`. Configurable, or disable behind a gateway.

## [0.3.0] — 2026-07-12

**The tool runtime.** Give an agent scoped access to a tool without handing it the credential: the
runtime holds the tool's secret, authenticates the agent, injects the secret server-side per call,
audits it, and revokes per call. Additive over 0.2.0 — the identity/MCP APIs are unchanged.

### Added

- **Credential vault** (`@roguezero/core`) — envelope encryption for downstream secrets:
  XChaCha20-Poly1305 per credential (AAD-bound to the tool), a whole-file HMAC manifest that detects
  tampering and rollback, and pluggable root keys — `argon2idKeyProvider` (passphrase-derived,
  nothing secret at rest; recommended) or `kmsKeyProvider` (bring your own KMS). Atomic on-disk store
  (`saveVaultToFile`/`readVaultFromFile`, `0600`, rollback-aware).
- **Tool registry** — `parseToolRegistry` / `resolveRequest`: agents name a **tool** and supply
  typed params; the runtime pins scheme/host/path/method. No agent-supplied URLs (SSRF-contained).
- **Injection proxy** — `dispatchToolCall`: resolves the pinned host, refuses private/metadata
  addresses (unless a tool is `internal`), connects to the validated IP (no DNS-rebind window), does
  not follow redirects, and injects the credential as bearer/basic/header (never a query param).
- **Runtime spine** — `handleToolCall`: authenticate → policy → revocation → resolve → **decrypt
  (last)** → inject → dispatch → audit. A denied or revoked call never decrypts a credential.
- **CLI + entrypoint** (`@roguezero/cli`) — `roguezero runtime init | tool add | secret set | serve`
  and `createRuntimeServer` (a framework-free HTTP entrypoint). Vault passphrase from
  `RZ_VAULT_PASSPHRASE`; secrets from `RZ_SECRET` or stdin — never argv.

### Notes

- New `@roguezero/core` dependencies: `@noble/ciphers`, `@noble/hashes` (audited, pure-JS).
- No breaking changes; `revocations.json`, credential, and presentation formats are unchanged.

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

[0.3.0]: https://github.com/roguezero-ai/roguezero/releases/tag/v0.3.0
[0.2.0]: https://github.com/roguezero-ai/roguezero/releases/tag/v0.2.0
[0.1.0]: https://github.com/roguezero-ai/roguezero/releases/tag/v0.1.0
