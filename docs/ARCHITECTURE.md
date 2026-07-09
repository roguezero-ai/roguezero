# Architecture v0

Scope: the MVP golden path only. Anything beyond it is in [ROADMAP.md](ROADMAP.md#deferred). If this document and the code disagree, fix one of them in the same PR.

## Shape

One verification pipeline, one place. `core` owns all identity, credential, policy, and audit logic; everything else is a thin shell over it.

```
                 ┌──────────────────────────────────────────────┐
                 │                packages/core                 │
  packages/cli ─▶│  keys ─ did:key / did:web create + resolve   │
                 │  issue: AgentProfile VC · Capability VC (JWT)│
 packages/      ─▶  verify pipeline:                            │
 middleware      │   resolve DID → verify signature             │
  ├ MCP wrapper  │   → issuer allowlist → expiry                │
  └ HTTP (Hono)  │   → audience + nonce (replay)                │
                 │   → revocation list → policy (default deny)  │
                 │   → audit event (JSONL, append-only)         │
                 └──────────────────────────────────────────────┘
```

Dependency rule: `core` imports no server framework, no MCP SDK, nothing from `middleware`/`cli`. Middleware and CLI import `core` and stay thin. This boundary is the contract a future Rust/WASM core would have to satisfy (ADR 0001) — keeping `core`'s public API small is load-bearing.

## Components

| Component | Responsibility | Deliberately not |
|---|---|---|
| **Identity** | Ed25519 keygen; `did:key` create/resolve; `did:web` doc generation + resolution (+ local static-host dev helper) | No `did:pkh`, no universal resolver, no method plugin system |
| **Issuer** | Issue AgentProfile and AgentCapability as JWT VCs (`did-jwt-vc`) | No JSON-LD proofs, no schema registry, no third credential type |
| **Verifier** | The full check sequence below; typed error per failure mode | No trust negotiation, no presentation-exchange protocol |
| **Revocation** | JSON revocation list (local file or fetched URL); `revoke(credentialId)`; checked on every verify | No Bitstring Status List conformance yet (format kept swappable) |
| **Policy** | Declarative rules file: agent × tool × scope → allow/deny, default deny; decision + reason | No Cedar/OPA, no conditions/context language, no admin API |
| **Audit** | Zod-validated events → append-only JSONL sink | No dashboard, no SIEM export, no hash-chaining yet |
| **Middleware** | MCP server wrapper + Hono middleware: extract presentation → run core pipeline → allow through / deny with protocol-appropriate error | No gateway/proxy deployment mode, no session management |
| **CLI** | `create` · `issue` · `verify` · `revoke` · `inspect` | No interactive wizards, no config management |

## Request flow (per protected tool call)

```
agent client                     middleware                      core
     │  1. request challenge         │                             │
     │──────────────────────────────▶│  nonce + audience + TTL     │
     │◀──────────────────────────────│                             │
     │  2. tool call + presentation  │                             │
     │    (AgentProfile VC,          │                             │
     │     Capability VC,            │──── 3. verify ─────────────▶│
     │     nonce/audience binding)   │   resolve DID → signature   │
     │                               │   → issuer trust → expiry   │
     │                               │   → audience/nonce → status │
     │                               │──── 4. policy ─────────────▶│
     │                               │   (agent, tool, scope)      │
     │                               │──── 5. audit event ────────▶│  JSONL
     │  6a. ALLOW → tool executes    │                             │
     │◀──────────────────────────────│                             │
     │  6b. DENY  → typed reason     │                             │
     │◀──────────────────────────────│                             │
```

Every path — including verifier crashes and resolver failures — ends in an audit event. Errors deny; nothing fails open.

### Open design question (decide during D1, keep isolated)

**Where the presentation rides in MCP**: per-call in `_meta`/params vs. per-session at initialize with per-call re-check vs. transport header. MCP auth conventions are converging on OAuth 2.1 and may collide with any choice; whatever we pick lives in one adapter module so changing it is cheap. Start with per-call — it's the strongest security story (action-time verification) and the clearest demo.

## Data shapes (illustrative, Zod-defined in code)

**AgentCapability VC (JWT claims, abridged):**
```json
{
  "iss": "did:web:acme.example",
  "sub": "did:key:z6Mk...agent",
  "exp": 1751850000,
  "vc": {
    "type": ["VerifiableCredential", "AgentCapability"],
    "credentialSubject": {
      "tools": [{ "name": "read_report", "scopes": ["reports:read"] }],
      "audience": "mcp://reports.acme.example"
    },
    "credentialStatus": { "type": "RevocationList2026", "id": "https://.../revocations.json#42" }
  }
}
```

**Policy rule:**
```json
{ "agent": "did:key:z6Mk...", "tool": "read_report", "scopes": ["reports:read"], "effect": "allow" }
```
Default deny. First match wins. That's the whole engine for MVP.

**Audit event:**
```json
{
  "ts": "2026-07-06T10:04:33Z",
  "correlationId": "01J...",
  "actor": "did:key:z6Mk...agent",
  "subject": "did:web:acme.example",
  "tool": "read_report",
  "decision": "allow",
  "reason": "policy:rule-3",
  "evidence": { "profileVc": "sha256:...", "capabilityVc": "sha256:...", "nonce": "..." }
}
```
Evidence carries hashes/IDs, never key material or full secrets.

## What v1 adds (so v0 doesn't have to)

OAuth/OIDC on-behalf-of (actor/subject claims join the policy context), hosted verifier API, Bitstring Status List, Cedar behind the policy interface, delegation chains with scope attenuation. Each slots behind an existing seam (policy context, revocation checker, verifier service) — none requires restructuring v0. That claim is the test of this architecture; if a v1 item forces a rewrite, v0 was wrong and we say so in an ADR.
