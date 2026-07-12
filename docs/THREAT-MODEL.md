# Threat Model — implemented controls, mapped to code and tests

This is the **review of [SECURITY.md](SECURITY.md) against the actual implementation**: for
each threat, the control that exists today, the file it lives in, and the test that *attacks*
it. It is deliberately honest about what is verified versus what is still a gap — a control
you can't point a failing-attack test at is not a control yet.

Last reviewed: 2026-07-07 (MVP golden path complete). Verification is a single fail-closed
pipeline: `packages/core/src/verify.ts` (`verifyRequest`) composed by
`packages/core/src/authorize.ts` (`authorizeToolCall`); every deny carries a typed reason.

**Status legend**
✅ Implemented & attack-tested · 🟡 Partial (control present; hardening tracked) ·
⛔ Accepted gap (MVP scope) · ⏳ Deferred (roadmap)

## Threats → controls → evidence

| # | Threat | Control (where) | Attack test | Status |
|---|---|---|---|---|
| T1 | **Forged / tampered credential** — fabricate or modify a VC | Signature verified against the DID-resolved key via `did-jwt-vc` (`credentials.ts` `verifyCredentialEnvelope`); tampering changes the signature | `credentials.test.ts` "tampered signature"; `verify.test.ts` "tampered presentation" → `bad-signature` | ✅ |
| T2 | **Untrusted issuer** — valid signature from an issuer we never trusted | Explicit issuer allowlist; empty allowlist denies all (`verify.ts` step 5) | `verify.test.ts` "issuer not on the allowlist" → `untrusted-issuer` | ✅ |
| T3 | **Replayed presentation** — capture and reuse a presentation | Server-issued single-use nonce, consumed atomically (`nonce.ts`); consumed in `verify.ts` step 2 | `nonce.test.ts` replay; `verify.test.ts`, `mcp.test.ts`, `http.test.ts` "replayed" → `nonce-replayed` | ✅ |
| T4 | **Audience confusion** — replay a presentation for tool A at tool B | VP is domain-bound (`presentation.ts`); capability is audience-scoped (`verify.ts` step 7) | `verify.test.ts` cross-audience + capability-scope-mismatch → `audience-mismatch` | ✅ |
| T5 | **Expired authority** — honor an old credential | `exp`/`nbf` on every credential and presentation; **tight 30s clock skew** wired explicitly (did-jwt's loose 300s default overridden) | `credentials.test.ts` expired + skew-window (accept/reject); `verify.test.ts` expired capability → `expired` | ✅ |
| T6 | **Revoked-but-cached** — keep calling a revoked capability | Revocation checked on every verify (`verify.ts` step 8); checker is **fresh by default** (`revocation.ts`), so revocation is immediate; TTL cache is opt-in | `revocation.test.ts` revoke→deny; all three demos → `revoked` | ✅ |
| T7 | **Scope escalation / confused deputy** — do more than granted | Two gates: capability must grant the tool (`authorize.ts`), then default-deny policy must allow it (`policy.ts`) | `authorize.test.ts` tool-not-granted; `policy.test.ts` default-deny + precedence | ✅ |
| T8 | **Stolen bearer credential** — present a capability issued to *another* agent | Holder binding: the presenter must sign the VP with the agent key **and** be the credential subject; issuer must equal the agent's declared controller (`verify.ts` step 6) | `verify.test.ts` confused-deputy → `holder-mismatch`; controller-mismatch → `untrusted-issuer` | ✅ |
| T9 | **Unauditable decision** — a decision that can't be recorded | Audit is load-bearing: if the sink throws, the call is **denied** (`authorize.ts` `auditThen`), never allowed-then-lost | `authorize.test.ts` failing sink → `audit-write-failed` | ✅ |
| T10 | **Malformed / hostile input** — junk JWTs, bad subjects | Zod validation at every trust boundary (credential subjects, policy, audit); typed parse errors → deny | `credentials.test.ts` invalid subject (issue + verify side) → `malformed-credential` | 🟡 fuzz/size-limits pending |
| T11 | **`alg` downgrade / `alg:none`** — unsigned or weakened token | `did-jwt` requires a signature matching a resolved verification method; `none` is not accepted | — explicit regression test pending | 🟡 pending |
| T12 | **Availability / challenge flood** — exhaust verifier memory or monopolize the unauthenticated `/challenge` mint | Nonce store bounded: throttled sweep + hard `maxEntries` cap (`nonce.ts`); remote revocation fetch has a 3s timeout; **per-client token-bucket rate limiter on `/challenge`** (`rate-limit.ts`, wired in `runtime-server.ts`, secure-by-default, keyed on socket address not spoofable `X-Forwarded-For`), and the limiter bounds its own memory | `nonce.test.ts` bounded-memory (sweep + cap); `rate-limit.test.ts` burst→throttle→recover + self-bounded memory; `runtime-server.test.ts` `/challenge` → 429 + `Retry-After` | ✅ |
| T13 | **Audit tampering** — erase evidence after the fact | Append-only JSONL sink; evidence carries hashes, never raw tokens/keys | append-only by construction | 🟡 hash-chaining deferred |
| T14 | **Agent key compromise** — private key leaked from disk/env | Short-lived capabilities bound blast radius; revocation kills the rest; keystores written mode `0600`, never logged | `revocation.test.ts` (kill switch) | 🟡 rotation deferred |

## Tool runtime — threats → controls → evidence

The runtime holds and injects downstream tool credentials, so it adds a threat surface with its own
controls, each backed by a negative-first test.

| Threat | Control | Evidence |
|---|---|---|
| Credential recovered from the vault at rest | Envelope encryption (`argon2id`/KMS root → data key → per-credential XChaCha20-Poly1305, AAD-bound); whole-file HMAC manifest | `core/vault*.test.ts` — wrong key, tampered ciphertext/nonce/manifest, deleted/injected entry, rolled-back generation all fail closed |
| Credential decrypted for a call that is then denied | Ordered spine: authenticate → policy → revocation → **then** decrypt | `core/runtime.test.ts` — a revoked call is denied with the downstream never contacted (credential never decrypted) |
| SSRF: agent points the credential at a private/metadata host | Agent names a tool, not a URL; registry pins target; private/metadata IPs refused unless `internal`; resolve-then-pin the IP; no redirects | `core/registry.test.ts`, `core/proxy.test.ts` — agent input can't reach host/scheme; blocked IPs (direct + via DNS) rejected; redirect not followed |
| Path traversal / header (CRLF) injection via params | Typed params; path traversal + control chars rejected | `core/registry.test.ts` |
| Credential leaks to the agent or logs | Injected server-side; never returned/logged; audit stores hashes, not secrets | `core/runtime.test.ts` (`demo-runtime`/`demo-runtime-mcp` assert the agent never receives the token) |

## Consciously accepted gaps (MVP)

Unchanged from [SECURITY.md](SECURITY.md#consciously-accepted-gaps-mvp-local-only-demo) and restated so nobody mistakes the MVP for a production deployment:

- **Local file key storage** (mode `0600`), not KMS/HSM/Vault.
- **No per-instance runtime identity / attestation** — identity binds to the logical agent, not the process.
- **No delegation chains** — one hop (controller → agent); sub-agent attenuation is deferred, and its threats with it.
- **No multitenancy / tenant isolation** — single-operator assumption.
- **`did:web` inherits DNS/HTTPS trust** — a domain hijack forges an org identity (the method's documented tradeoff).
- The unauthenticated challenge endpoint is **rate-limited per client** (token bucket, secure default) and memory is bounded, but a **distributed** flood from many source addresses is only partially mitigated in-process — a shared/gateway throttle is the horizontal-scale path (same interface).

## What CI proves on every commit

Not a claim — an enforced fact. `pnpm test` runs the negative tests above (tampered, expired,
replayed, cross-audience, untrusted-issuer, confused-deputy, controller-mismatch, revoked,
audit-write-failure), and CI then runs the golden path in **three transports** (in-process
MCP, real stdio MCP subprocess, HTTP) asserting allow → policy-deny → revoked-deny. A broken
control turns CI red.

## Before public launch

The 🟡 items above are the pending hardening work: key rotation, audit hash-chaining,
credential-parsing fuzz tests plus an explicit `alg:none` regression test,
input size limits, distinct 401/403 responses, and revoked-actor attribution.
(Challenge-endpoint rate-limiting is now done — see T12.)
Public launch is gated on closing them, plus CI secrets scanning. (A root `SECURITY.md` with a
disclosure contact is already in place.) None of these block a private design-partner pilot.

## Incident lens

For any new feature or shortcut: *if this agent were malicious or hijacked (AutoJack-style),
what does this let it do, and what evidence would remain?* If a decision can't be reconstructed
from the audit log afterward, the feature isn't done.
