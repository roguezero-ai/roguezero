# Security policy

RogueZero is security infrastructure. We take reports seriously and appreciate responsible
disclosure.

## Reporting a vulnerability

**Please do not open a public issue for security reports.** Instead, email
**security@roguezero.ai** (or contact@roguezero.ai) with:

- a description of the issue and its impact,
- steps to reproduce (a minimal proof of concept if possible),
- any suggested remediation.

We aim to acknowledge reports within 3 business days and to keep you updated as we
investigate. We'll credit reporters who wish to be named once a fix ships.

## Scope

In scope: the `@roguezero/*` packages (`core`, `middleware`, `cli`) and the example.
Out of scope for this stage: the not-yet-implemented items in the roadmap, and issues that
require a threat model we explicitly document as out of scope.

## What we already defend against

The verification pipeline is fail-closed and covered by negative tests for replay,
cross-audience replay, forged/tampered credentials, untrusted issuers, confused-deputy,
expired and revoked credentials, unsigned (`alg:none`) tokens, and unauditable decisions.
See [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) for the threat-by-threat mapping to
controls and tests.

## Supported versions

This is pre-1.0 software under active development. Security fixes land on the latest
release; there is no long-term-support branch yet.
