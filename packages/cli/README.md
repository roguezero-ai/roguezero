# @roguezero/cli

Developer CLI over `@roguezero/core`:

```
roguezero create   # generate keys + a DID
roguezero issue    # issue an AgentProfile or AgentCapability credential
roguezero verify   # verify a presentation
roguezero revoke   # revoke a credential
roguezero inspect  # pretty-print a DID doc / VC / audit log
```

Status: **early beta**, pre-1.0. All five commands are implemented and exercised
end-to-end by the golden-path demo (CI-enforced). See `examples/protected-tool` for a
worked example, and run `roguezero --help` for full flags.
