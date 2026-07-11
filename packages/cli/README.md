# @roguezero/cli

Give an agent a scoped, revocable identity — without changing the agent.

```bash
npx @roguezero/cli init --audience "mcp://reports.local"
npx @roguezero/cli onboard reporter --tool read_report=reports:read
npx @roguezero/cli connect --agent reporter -- node ./your-mcp-server.js
npx @roguezero/cli revoke --agent reporter     # the next call is denied
```

`onboard` writes `reporter.rz.json` — one file (mode `0600`) holding the agent's key and
credentials, the way a kubeconfig holds a cluster's. `connect` is an MCP stdio proxy: your
agent speaks plain MCP to it, and it proves the agent's identity to the protected tool on
every call. The agent never sees a nonce, a credential, or a DID.

Point any MCP client at it — Cursor, VS Code, your own SDK code:

```jsonc
{
  "mcpServers": {
    "reports": {
      "command": "npx",
      "args": ["@roguezero/cli", "connect", "--agent", "reporter",
               "--", "node", "/path/to/your-mcp-server.js"]
    }
  }
}
```

`connect` needs `@modelcontextprotocol/sdk` (an optional peer). Every other command works
without it.

## Agents that run unattended

For agents nobody is watching, credentials still have to rotate — but an agent that can renew
itself can't be killed. So renewal runs **where the controller key lives** (a cron host, a CI
job), never on the agent:

```bash
# On the controller host, on a schedule:
roguezero renew --all            # renew every agent that's due; skip any you've revoked
```

`connect` re-reads the bundle on every call, so a renewed credential reaches a running agent
with no restart. And `renew --all` refuses to renew a revoked agent — so `revoke` is final:
automation can never bring back one you killed. The unattended loop (renew live → revoke → no
resurrection) is CI-enforced.

## Everything else

```
roguezero init      # scaffold config + controller + deny-everything policy
roguezero onboard   # create an agent, issue its credentials, grant it tools
roguezero connect   # run an MCP client through RogueZero (zero agent-side code)
roguezero renew     # rotate an agent's credentials (--all = fleet scheduler)
roguezero revoke    # kill an agent, a credential, or an id
roguezero create    # generate keys + a DID
roguezero issue     # issue an AgentProfile or AgentCapability credential
roguezero verify    # verify a credential (pass --revocations to check revocation too)
roguezero inspect   # pretty-print a VC or an audit log
```

Every command prints only its result on stdout, so `AGENT=$(roguezero create --out a.json)`
captures a DID and nothing else.

Status: **early beta**, pre-1.0. Exercised end-to-end by the golden-path demos, including an
unmodified MCP client driven through `connect` (CI-enforced). Run `roguezero --help` for flags.
