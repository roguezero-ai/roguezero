# @roguezero/core

The verification core: DID create/resolve (`did:key`, `did:web`), JWT-VC issue/verify
(AgentProfile, AgentCapability), revocation, policy, and audit. No server framework, no
MCP SDK — `@roguezero/middleware` and `@roguezero/cli` are thin shells over this package.

Status: **early beta**, pre-1.0. The full pipeline — identity, credential issue/verify,
request verification, policy, revocation, and audit — is implemented and covered by unit
tests (including the negative/attack cases) and the CI-enforced golden-path demo.

```ts
// one-shot verify → policy → audit, or compose the pieces yourself
import { authorizeToolCall, verifyRequest, evaluatePolicy } from "@roguezero/core";
```
