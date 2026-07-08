# ADR 0001: TypeScript-first, no Rust core for MVP

Date: 2026-07-06 · Status: accepted

## Context

The original strategy document (`docs/archive/Agent-DID-plan.pdf`) proposes a Rust policy/verification core (using the `ssi` crates) with a TypeScript SDK on top — roughly ten Rust crates plus seven TS packages. This project is currently a solo-founder MVP whose wedge is developer adoption through MCP/HTTP middleware.

## Decision

The MVP is TypeScript-only:

- **Ecosystem fit**: MCP's reference SDK, most MCP servers, and the target developers (AI app teams) are TypeScript-native. Middleware that isn't `npm install`-able loses the wedge.
- **Speed**: one language, one toolchain, one test runner. A dual-language repo roughly doubles CI, packaging, and interface-maintenance cost before the first user exists.
- **Sufficient libraries**: `did-jwt` / `did-jwt-vc` plus DIF `did-resolver` / `key-did-resolver` / `web-did-resolver` cover the golden path. They are wrapped behind our own interfaces in `packages/core` so any library can be swapped.
- **Performance is a non-problem**: verification sits next to LLM-latency-dominated tool calls; single-digit-millisecond JWT verification in Node is invisible there.

Rust is deferred until a concrete driver exists (embedding the verifier in a gateway/proxy, a customer's hard latency budget, or a WASM distribution need). The plan's `ssi`-based design remains the likely shape *if* that day comes.

## Consequences

- Fastest possible path to the golden-path demo; single `pnpm` workspace.
- We accept Node as a runtime dependency for all MVP components, including the CLI.
- If a Rust core is added later, `packages/core`'s public API is the contract it must satisfy; keeping that API small is therefore load-bearing.
