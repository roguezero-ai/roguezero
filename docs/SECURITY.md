# Security Model v0

This is security infrastructure: a crypto mistake here is worse than no product. This document lists the threats we defend against in the MVP, the controls that must exist, and — just as important — the gaps we consciously accept for a local-only demo. Before any public launch, the hardening items in the checklist below close and this document gets a full review.

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
| T8 | **Tampered payload** | Modified claims inside a signed JWT | Inherent in JWT signature verification; malformed-input fuzz tests planned |
| T9 | **Malformed/hostile input** | Oversized JWTs, header tricks, junk presentations | Zod validation at every boundary; size limits; typed parse errors → deny |
| T10 | **Audit tampering** | Attacker erases evidence of an action | Append-only sink now; hash-chained entries before launch |
| T11 | **Key compromise (agent)** | Agent private key leaked from disk/env | Short-lived capabilities bound the blast radius; revocation kills the rest; rotation flow is planned |

Every deny carries a typed reason naming the failed check (T1–T11 map to distinct error types). This is both a security property (auditability) and the product's developer experience.

**Audit records what the agent *attempted*** (`attempt.args` = the tool arguments the agent sent; `attempt.target` = the resolved method+URL on the executed path), so a denied call shows *what was blocked*, not merely that it was. Two invariants bound this: (1) it is **agent-supplied data only** — the vault credential is decrypted *after* authorization (decrypt-last), so it can never appear in `attempt`, and `target` never includes the `Authorization` header; (2) `attempt.args` is **size-capped** (a denied/attacking agent controls its arguments, so an unbounded copy would let it bloat the log — past the cap the args are dropped and `truncated` is flagged). Consequence for operators: the audit log may contain agent-chosen argument *values* (e.g., an issue title/body) — **treat the audit log as sensitive** and store it accordingly.

## Tool runtime (credential injection)

The runtime extends the model above: it also **holds downstream tool credentials** and injects them
so agents never do. That is a higher-stakes surface (a mistake leaks a live API key, not just an
identity assertion), so it has its own controls:

| # | Threat | Control |
|---|---|---|
| R1 | **Credential at rest** | Envelope encryption: a passphrase-derived (`argon2id`) or KMS root key wraps a data key; each credential sealed with XChaCha20-Poly1305, AAD-bound to its tool. A whole-file HMAC manifest detects tampering, deletion, and rollback. Written `0600`, atomically. |
| R2 | **Decrypt before authorization** | Ordering is the control: authenticate → policy → revocation → **then** decrypt. A denied or revoked call never decrypts a credential. |
| R3 | **Credential leak in transit** | Decrypted late, injected server-side (bearer/basic/header — never a query param), and never logged, returned to the agent, or placed in a URL. |
| R4 | **SSRF / metadata exfil** | Agents name a **tool**, never a URL. The registry pins scheme/host/path/method; private, loopback, link-local, and cloud-metadata addresses are refused unless a tool is explicitly `internal`. The runtime resolves the host once and connects to that exact IP (no DNS-rebind window) and does not follow redirects. |
| R5 | **Path / header injection via params** | Agent parameters are typed and validated; path params can't traverse, and control characters/CRLF are rejected everywhere. |

The root key at rest is the runtime's real boundary — protect it with `argon2id` (nothing secret at
rest) or a KMS, and keep any key file out of the vault's own backups.

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

Before a public launch, these hardening items close: threat-model review (this doc, versus code, line by line) · replay cache + clock-skew policy tested · key rotation flow · audit hash-chaining · credential-parsing fuzz/property tests · lockfile audit + pinned CI actions · secrets scanning in CI. (A root `SECURITY.md` with a disclosure contact is already in place.)

## Incident lens

When evaluating any new feature or shortcut, ask: *if this agent were malicious or hijacked (AutoJack-style), what does this feature let it do, and what evidence would we have afterward?* If the answer to the second half is "not enough to reconstruct the decision," the feature isn't done.
