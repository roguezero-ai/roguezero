# RogueZero concepts — in plain language

You don't need to know anything about cryptography or decentralized identity to use RogueZero. This
page explains the whole idea in plain concepts. The technical terms (DIDs, verifiable credentials)
are real, but they live under the hood — like the certificates behind HTTPS. We mention them once, at
the end, for the curious.

## The one-paragraph version

An AI agent needs to call one of your tools — GitHub, Stripe, an internal API — but you don't want to
hand it your API key. RogueZero **holds the key for you.** When the agent calls, RogueZero checks *is
this really that agent, is it allowed to do this, and has it been revoked?* — and only then injects
the key, calls the tool, and writes the decision to a log you can prove later. The agent gets the
*result*, never the secret. One command kills its access. You run all of this on your own machines.

## The big idea: the agent never holds your key

Today you hand an agent a long-lived API key in an environment variable. If it leaks, or the agent
goes rogue, that key can do anything — and rotating it breaks everything else that uses it. RogueZero
keeps the key in an **encrypted vault** on your own infrastructure. The agent gets only *its own
identity*, never the key. On each call the runtime authenticates the agent, then injects the key
**server-side**; the agent never sees it, it's never written to a log, and it never travels in a URL.
Revoke the agent and its next call is denied **before the key is even decrypted.**

And the agent can only reach the tools you registered: it names a **tool**, never a web address, so it
can't be tricked into pointing your credential somewhere it shouldn't go.

## How it decides — five ideas

### 1. Identity — a name you can trust
Every agent (and every operator who authorizes agents) gets its own identity that anyone can verify,
without calling a central server or trusting a shared secret. An API key identifies a *deployment*; an
identity identifies the *agent that's acting*.

### 2. Capability — a permission slip
A capability is a signed permission: **these tools, these scopes, granted by this operator, until this
expiry.** It's scoped (not all-or-nothing), it expires on its own, and it can be revoked at any moment.
A visitor badge, not a master key.

### 3. Verification — checked on every action
Every single call is checked at the moment it happens — signature, who issued the permission, whether
it's expired, whether it's for *this* tool, whether it's being replayed, and whether it's been revoked.
No "logged in once, trusted all session." If any check fails, the call is denied, with the exact reason.

### 4. Policy — your rules, default-deny
Verification proves *who* is asking and *what they were granted*. Policy is *your* decision about what
to permit: simple rules matching an agent, a tool, and scopes. Anything that doesn't match an allow
rule is denied by default — the safe direction.

### 5. Audit — a decision you can prove
Every decision, allowed or denied, is written to an append-only log with enough evidence to reconstruct
it: who acted, on whose authority, which tool, the outcome, and why — never the secret itself. When
someone asks "what did this agent do, and could you have stopped it?", you have the answer.

## Who does what

- **The operator** (you, or your platform) registers a tool, stores its credential in the vault, and
  grants an agent a scoped capability.
- **The agent** presents its identity with each call — and holds nothing else.
- **The runtime** (on your infrastructure) verifies, applies policy, checks revocation, injects the
  credential, calls the tool, and audits — or denies the call.

## The one "moment" worth remembering

When a key leaks today, the only fix is to rotate it — which breaks everything else using it. With
RogueZero you `revoke` one agent, and its very next action is denied, instantly, with the reason in
the log — and the credential it would have used is never even decrypted. One agent, off. Nothing else
touched.

---

## Under the hood (you can skip this)

The agent identities are **W3C Decentralized Identifiers (DIDs)** — `did:key` for local use, `did:web`
for organizations. The permission slips are **Verifiable Credentials (VCs)**, signed as JWTs. The
per-call proof is a **Verifiable Presentation** bound to a one-time challenge so it can't be replayed.
The tool credentials in the vault are sealed with authenticated encryption (XChaCha20-Poly1305) under a
key derived from your passphrase or held in your KMS. No blockchain, no account, no token — the same
standards-track cryptography that makes web certificates work, applied to agents.

| Plain word here | Technical term |
|---|---|
| Agent identity | Decentralized Identifier (DID) |
| Permission slip / capability | Verifiable Credential (AgentCapability) |
| Per-call proof | Verifiable Presentation |
| The vault | Envelope-encrypted credential store |
| "Checked on every action" | Request-time verification pipeline |
| The kill switch | Revocation list, checked per call |
