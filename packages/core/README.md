# @roguezero/core

The verification core: DID create/resolve (`did:key`, `did:web`), JWT-VC issue/verify
(AgentProfile, AgentCapability), revocation, policy, and audit. No server framework, no
MCP SDK — `@roguezero/middleware` and `@roguezero/cli` are thin shells over this package.

Status: **pre-MVP**. Currently exports domain types and centralized constants only; the
verification pipeline lands in F2–F9 (see `BACKLOG.md`).

```ts
import { CREDENTIAL_TYPES, type AgentCapabilitySubject } from "@roguezero/core";
```
