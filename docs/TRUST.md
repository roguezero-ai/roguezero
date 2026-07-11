# Production Trust — the security review before you pilot

This is the page for the security engineer deciding whether to run RogueZero in staging. It
answers, plainly and with the gaps stated out loud: **what does this cost at runtime, where do
keys live, how do I kill an agent, what can I prove afterward, and what is *not* done yet.**

It is deliberately honest about limits. If a control isn't built, it says so and tells you the
safe posture until it is. For the attack-by-attack analysis (each threat → the control → the
test that proves it), see [THREAT-MODEL.md](THREAT-MODEL.md); for the security ground rules, see
[SECURITY.md](SECURITY.md). This page is the operator's decision doc, not a repeat of those.

## What RogueZero is, at the trust level

A **local-first, in-process** verification layer at your tool boundary. There is **no hosted
service, no IdP, and no account** in the free/OSS product — you run it, it runs beside your tool,
and nothing about your agents leaves your infrastructure. Every protected tool call re-runs a
full, ordered, **fail-closed** pipeline: presentation signature → single-use nonce (replay) →
credential verification → issuer allowlist → holder/controller binding (confused-deputy) →
audience binding → revocation. Any error at any step is a **deny plus an audit event**, never an
allow. There is no session-level trust to bypass.

Because identity is **self-certifying** (`did:key` — the identifier *is* the public key) you do
not stand up a directory or an OAuth issuer to use it. That is the point of the no-IdP posture:
the thing that authenticates an agent needs no central authority to have minted it.

## 1. Runtime cost

Measured on the real pipeline (`scripts/bench-overhead.mjs`, 500 iterations, Node 24, in-memory
DID resolution — pure compute, excluding network):

| Hop | p50 | p95 | What it is |
|---|---:|---:|---|
| Mint (agent side) | 0.27 ms | 0.31 ms | Obtain a nonce, sign a fresh presentation |
| Verify (server side) | 2.94 ms | 3.12 ms | 3 Ed25519 verifications + 2 VC parses + nonce + policy |
| **Total added compute** | **3.2 ms** | **3.4 ms** | |

**Interpretation, stated honestly:** RogueZero adds roughly **3 ms of CPU per protected call**.
Separately, the challenge handshake adds **one network round-trip** (the agent fetches a nonce
before presenting). For an LLM-driven tool call — already hundreds of milliseconds to seconds,
and network-bound — both are in the noise. The number to put in your capacity model is *3 ms of
CPU + one RTT on your existing transport*. Re-run the benchmark on your own hardware; it ships in
the repo precisely so you don't have to take ours.

## 2. Key handling — where private keys live

**RogueZero holds none of your keys, because there is nothing on our side to hold them.** Keys
are generated and stored on *your* machine, in files:

- **Controller/issuer key** (`*.key.json`) — the operator identity that signs credentials.
- **Agent bundle** (`*.rz.json`) — the one file an agent mounts: its private key plus its two
  credentials. Shaped like a kubeconfig / cloud service-account JSON on purpose — it *is* a
  secret, it belongs in whatever secret store you already run.

What we verified and what we don't do:

- Keys are written **`0600`** (owner read/write only) and are git-ignored.
- Keys **never cross the network**, and never appear in credentials, logs, audit events, or error
  messages (audit carries hashes, not secrets).
- Key generation is `@noble/curves` Ed25519 — a vetted library. We never invent crypto.
- **Honest gap — no encryption at rest.** The key files are the raw seed protected by filesystem
  permissions, not an encrypted vault. This is the same trust model as a kubeconfig or a GCP
  service-account key: the file is the secret. **Safe posture:** keep these in your existing
  secret store (Vault, sealed secrets, cloud secret manager) and mount them at runtime. A native
  KMS/HSM envelope is the first integration we will build against a design partner who needs it;
  it is not shipped.

## 3. Revocation — the kill switch

Revocation, not expiry, is the control that stops an agent. It is **checked on every single
call** and **fails closed**: if the list is unreachable, stale, unsigned, or rolled back, the
call is denied and the audit event names the agent — a source failure is never an allow.

| You have | Use | Note |
|---|---|---|
| One machine | Local JSON list (`revoke --agent <name>`) | Re-read every call; instant effect |
| A fleet | **Signed revocation lists** (JWT: freshness `exp`, `seq` rollback defense, per-entry expiry) | Trust rests on the *publisher*, not the host — a CDN can serve it |

**Operational contract you must honor:** a signed list has to be **re-published on a schedule
even when nothing changed**, because verifiers reject a stale list by design. The freshness
window is `DEFAULT_LIFETIMES.revocationListSeconds` (1 h default) — that cron entry is part of
running this, not an optional nicety. Grants are intentionally longer-lived (30 d default)
*because* revocation is checked fresh every call; the kill switch, not a short expiry, is the
security boundary. (Hosted, HA, globally-distributed revocation propagation with an SLA is the
first paid layer — the free local/self-hosted path above is complete on its own.)

## 4. Audit — what you can prove afterward

Every decision — allow *and* deny — emits an append-only JSONL event: timestamp, correlation ID,
actor (agent DID), subject (controller), tool, decision, precise reason, and **credential-hash
evidence** (never raw tokens or keys). A revoked or denied call names the actor once binding is
confirmed; genuinely pre-identity failures (a replayed nonce) record the presentation hash so
repeated attempts stay correlatable. You can reconstruct "what did agent X do, and why was it
allowed or denied" from the log alone.

- **Honest gap — not yet tamper-evident.** The log is append-only but **not hash-chained**, so a
  writer with filesystem access could rewrite history without a cryptographic tell. **Safe
  posture:** ship the JSONL to your existing append-only/WORM sink or SIEM (the sink is an
  interface; an HTTP sink ships). Hash-chained entries are on the roadmap (backlog H4); managed
  tamper-evident retention is a planned paid layer.

## 5. Multi-instance / HA

**Honest gap.** The bundled nonce store (`createInMemoryNonceStore`) is **single-process**. Two
verifier replicas behind a load balancer will reject each other's nonces, producing spurious
`nonce-unknown` denials (it fails *closed*, so this is an availability bug, not a security hole).
`NonceStore` is an async interface — the seam for a shared store (Redis, etc.) — but **no shared
implementation ships yet.** **Safe posture for staging:** run a single verifier instance, or
supply your own `NonceStore` against the interface. A shared store is built when a partner runs
multi-replica.

## 6. Key rotation

- **Credential rotation ships:** `roguezero renew` reissues both credentials on the same DID/key
  with a new expiry and **revokes the superseded capability** by default. Routine rotation is a
  cron job.
- **Honest gap — key rotation.** For `did:key`, the identifier *is* the key, so replacing the key
  means a new DID (re-onboard the agent). Rotating to a **new key under a stable `did:web`
  identity** is not yet implemented (backlog H3). **Safe posture:** treat a key compromise as
  re-onboard-and-revoke, not in-place key swap, until this lands.

## What CI proves on every commit

Not claims — the build is red if any of these regress: the full verify pipeline with its negative
cases (tampered signature, expired, wrong audience, replayed nonce, untrusted issuer,
confused-deputy, revoked), and three end-to-end demos including an **unmodified MCP client through
the proxy** running allow → not-granted-deny → revoked-deny with the audit trail asserted.

## Consciously accepted gaps

The full list — no KMS/HSM, no per-process attestation, no delegation chains, no multitenancy,
`did:web` inherits HTTPS/DNS trust, no built-in rate limiting — is enumerated in
[SECURITY.md](SECURITY.md) §"Consciously accepted gaps." Read it before you deploy; nothing there
is a surprise, and each item names the safe posture or the deferral trigger.

## Recommended staging posture (the short version)

1. Single verifier instance (until you supply a shared `NonceStore`).
2. Keys in your existing secret store, mounted `0600` at runtime.
3. Signed revocation list on a CDN, re-published on a ≤1 h cron.
4. Audit JSONL forwarded to your SIEM / append-only sink.
5. Treat agent-key compromise as re-onboard + revoke.

That configuration gives you: per-call fail-closed verification, a kill switch that lands on the
next call, and a reconstructable audit trail — with the four honest gaps above (encryption at
rest, audit tamper-evidence, HA nonce store, did:web key rotation) covered by your existing
infrastructure rather than pretended away.

## Reporting a vulnerability

See the root `SECURITY.md` disclosure contact. We would much rather hear it from you first.
