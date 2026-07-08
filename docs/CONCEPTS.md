# RogueZero concepts — in plain language

You don't need to know anything about cryptography or decentralized identity to use
RogueZero. This page explains the whole idea in five plain concepts. The technical terms
(DIDs, verifiable credentials) are real, but they live under the hood — like the
certificates behind HTTPS. We mention them once, at the end, for the curious.

## The one-paragraph version

An AI agent is about to call one of your tools. Before it runs, RogueZero asks three
questions — *is this really that agent, is it allowed to do this, and has that permission
expired or been revoked?* — allows or denies the call, and writes the decision to a log you
can prove later. You add it by putting a small piece of software in front of your tool.

## The five ideas

### 1. Identity — a name you can trust
Every agent (and every operator who authorizes agents) gets its own identity that anyone can
verify, without calling a central server or trusting a shared secret. An API key identifies a
*deployment*; an identity identifies the *agent that's acting*.

### 2. Capability — a permission slip
A capability is a signed permission: **these tools, these scopes, granted by this operator,
until this expiry.** It's scoped (not all-or-nothing), it expires on its own, and it can be
revoked at any moment. Think of it as a visitor badge, not a master key.

### 3. Verification — checked on every action
Every single call is checked at the moment it happens — signature, who issued the permission,
whether it's expired, whether it's for *this* tool, whether it's being replayed, and whether
it's been revoked. There's no "logged in once, trusted all session." If any check fails, the
call is denied, and you're told exactly which check and how to fix it.

### 4. Policy — your rules, default-deny
Verification proves *who* is asking and *what they were granted*. Policy is *your* decision
about what to permit here: simple rules matching an agent, a tool, and scopes. Anything that
doesn't match an allow rule is denied by default — the safe direction.

### 5. Audit — a decision you can prove
Every decision, allowed or denied, is written to an append-only log with enough evidence to
reconstruct it: who acted, on whose authority, which tool, the outcome, and why — never the
secret itself. When someone asks "what did this agent do, and could you have stopped it?", you
have the answer.

## The five verbs (the whole CLI)

| Verb | What it does | Concept |
|---|---|---|
| `create` | Make an identity for an agent or operator | Identity |
| `issue` | Grant a permission slip (profile / capability) | Capability |
| `verify` | Check a credential is valid | Verification |
| `revoke` | Kill a permission — instantly | Capability |
| `inspect` | Read a credential or the audit log | Audit |

## Who does what

- **The operator** (you, or your platform) *issues* an agent its identity and its capability.
- **The agent** *presents* its capability with each call it makes.
- **The tool server** (with RogueZero in front) *verifies*, applies *policy*, and *audits* —
  then runs the tool or denies the call.

One hop, one operator, one agent. (Chains of sub-agents are a later addition.)

## The one "moment" worth remembering

When a key leaks today, the only fix is to rotate it — which breaks everything else using it.
With RogueZero you `revoke` one agent's one capability, and its very next action is denied,
instantly, with the reason in the log. One agent, off. Nothing else touched.

---

## Under the hood (you can skip this)

The identities are **W3C Decentralized Identifiers (DIDs)** — `did:key` for local use,
`did:web` for organizations. The permission slips are **Verifiable Credentials (VCs)**,
signed as JWTs. The per-call proof is a **Verifiable Presentation** bound to a one-time
challenge so it can't be replayed. None of this requires a blockchain, an account, or a
token — it's the same standards-track cryptography that makes web certificates work, applied
to agents. If you never learn these words, RogueZero still works exactly the same.

| Plain word here | Technical term |
|---|---|
| Identity | Decentralized Identifier (DID) |
| Permission slip / capability | Verifiable Credential (AgentCapability) |
| Per-call proof | Verifiable Presentation |
| The "checked on every action" step | Request-time verification pipeline |
| The kill switch | Revocation list |
