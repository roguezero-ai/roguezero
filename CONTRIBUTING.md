# Contributing to RogueZero

Thanks for your interest! RogueZero is [Apache-2.0](LICENSE) licensed; by contributing you
agree your contributions are licensed under the same terms.

## New here?

Read [`docs/CONCEPTS.md`](docs/CONCEPTS.md) — the whole idea in five plain concepts, no
cryptography or DID/VC knowledge required. Then run the demo.

## Develop

Requires Node ≥ 20 and [pnpm](https://pnpm.io) (`corepack enable` provides it).

```bash
pnpm install
pnpm build
pnpm test        # unit + integration tests
pnpm demo        # the end-to-end golden path
pnpm lint && pnpm format:check
```

The repo is a small pnpm workspace:

- `packages/core` — all identity, credential, verification, policy, and audit logic. No
  server framework. This is where correctness lives; changes here need tests.
- `packages/middleware` — thin MCP + HTTP transport wrappers over `core`.
- `packages/cli` — the developer CLI over `core`.
- `examples/protected-tool` — the runnable, CI-enforced demo.

## Ground rules

- **Security-critical code needs negative tests.** For anything in the verification path,
  add a test that *attacks* it (see `verify.test.ts`, `security.test.ts`).
- **Never invent crypto.** Signing, verification, and encoding go through vetted libraries.
- **Fail closed.** Any error is a deny, never an allow.
- Keep `core` free of framework dependencies; middleware and CLI stay thin.
- Match the surrounding code style; `pnpm lint` and `pnpm format:check` must pass.

## Reporting security issues

Please don't open a public issue — see [`SECURITY.md`](SECURITY.md).
