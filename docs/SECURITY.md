# Security Model v0

This is security infrastructure: a crypto mistake here is worse than no product. This document lists the threats we defend against in the MVP, the controls that must exist, and — just as important — the gaps we consciously accept for a local-only demo. Before any public launch, the H-items in `BACKLOG.md` close and this document gets a full review.

> **See [THREAT-MODEL.md](THREAT-MODEL.md)** for the review of this model *against the actual code* — each threat mapped to the implemented control, the file it lives in, and the attack test that proves it, with honest ✅/🟡/⛔ status.

## Ground rules

1. **Never invent crypto.** Key generation, signing, verification go through vetted libraries (`did-jwt` family). No hand-rolled canonicalization, encoding, or comparison logic.
2. **Fail closed.** Any verification error, resolver failure, malformed input, or policy-engine exception results in deny + audit event. There is no code path where an error allows.
3. **Verify at request time, every time.** No session-level trust. Each protected call re-runs the full pipeline.
4. **Short lifetimes by default.** Capabilities and presentation bindings get short expiries unless explicitly overridden.
5. **Keys never leak.** No private keys in logs, audit events, error messages, or committed fixtures (test keys are generated or clearly marked throwaway).
6. **Negative tests outrank coverage.** Every threat below maps to at least one test that attacks the implementation.

## Threat model (MVP scope)

| # | Threat | Example | MVP control |
|---|---|---|---|
| T1 | **Forged credential** | Attacker fabricates a Capability VC | Signature verification against DID-resolved keys; `alg` allowlist (no `none`, no downgrade) |
| T2 | **Untrusted issuer** | Valid signature from an issuer we never trusted | Explicit issuer allowlist; empty allowlist = deny all |
| T3 | **Replayed presentation** | Captured presentation reused later or elsewhere | Server-issued nonce with TTL + used-nonce cache; audience binding checked |
| T4 | **Audience confusion** | Presentation for tool server A replayed at server B | Mandatory audience claim, exact match against the verifier's own identifier |
| T5 | **Expired authority** | Old Capability VC still honored | `exp` on every credential and presentation; bounded clock-skew tolerance |
| T6 | **Revoked-but-cached** | Capability revoked, agent keeps calling | Revocation list checked on every verify; revocation cache TTL ≤ 60 s when fetched over HTTP |
| T7 | **Scope escalation / confused deputy** | Agent with `reports:read` calls `delete_report` | Default-deny policy; tool + scope must match an explicit allow rule |
| T8 | **Tampered payload** | Modified claims inside a signed JWT | Inherent in JWT signature verification; malformed-input fuzz tests (H5) |
| T9 | **Malformed/hostile input** | Oversized JWTs, header tricks, junk presentations | Zod validation at every boundary; size limits; typed parse errors → deny |
| T10 | **Audit tampering** | Attacker erases evidence of an action | Append-only sink now; hash-chained entries before launch (H4) |
| T11 | **Key compromise (agent)** | Agent private key leaked from disk/env | Short-lived capabilities bound the blast radius; revocation kills the rest; rotation flow is H3 |

Every deny carries a typed reason naming the failed check (T1–T11 map to distinct error types). This is both a security property (auditability) and the product's developer experience.

## Consciously accepted gaps (MVP, local-only demo)

Stated so nobody mistakes the demo for a production deployment:

- **Key storage is local files** (permissions-restricted), not KMS/HSM/Vault. Acceptable for a laptop demo; a hosted or production deployment requires the KMS integration deferred in ROADMAP.
- **No per-instance runtime identity or attestation.** Identity binds to the logical agent, not the running process. CoSAI recommends per-instance identity; it's deferred until a design partner needs it.
- **No delegation chains.** One hop: controller issues to agent. Sub-agent delegation with scope attenuation and depth limits is deferred (and its threats — chain expansion, zombie delegation — with it).
- **No multitenancy or tenant isolation.** Single-operator assumption throughout.
- **Revocation list is a simple JSON document**, not Bitstring Status List; over HTTP it's only as available as its host. Format is behind an interface.
- **No rate limiting / DoS protection** in middleware. Out of scope for local demo.
- **did:web inherits HTTPS/DNS trust.** A domain hijack forges an org identity. This is the method's documented tradeoff, accepted at this stage.

## Pre-public-launch checklist

From `BACKLOG.md`: H1 threat-model review (this doc, versus code, line by line) · H2 replay cache + clock-skew policy tested · H3 key rotation flow · H4 audit hash-chaining · H5 credential-parsing fuzz/property tests · H6 lockfile audit + pinned CI actions. Plus: a `SECURITY.md` at repo root with a disclosure contact, and secrets scanning in CI.

## Incident lens

When evaluating any new feature or shortcut, ask: *if this agent were malicious or hijacked (AutoJack-style), what does this feature let it do, and what evidence would we have afterward?* If the answer to the second half is "not enough to reconstruct the decision," the feature isn't done.
