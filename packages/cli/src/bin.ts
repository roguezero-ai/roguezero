#!/usr/bin/env node
/**
 * CLI entrypoint: a thin argv parser (Node's built-in util.parseArgs) over the command
 * functions in commands.ts. Errors are printed clearly and set a non-zero exit code.
 */

import { stat } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { parseArgs } from "node:util";
import {
  explainDenial,
  loadGuardConfig,
  VerificationError,
  writableRevocationPath,
} from "@roguezero/core";
import {
  createCommand,
  inspectAuditCommand,
  inspectJwtCommand,
  inspectRevocationsCommand,
  issueCapabilityCommand,
  issueProfileCommand,
  parseToolSpec,
  revokeCommand,
  verifyCommand,
} from "./commands.js";
import { publishRevocationsCommand } from "./publish.js";
import {
  CONFIG_FILENAME,
  initCommand,
  onboardCommand,
  renewAllCommand,
  renewCommand,
} from "./workspace.js";

const HELP = `roguezero — verifiable agent identity & authorization

Getting started (no DIDs typed by hand):
  roguezero init --audience <aud>              scaffold config + controller + default-deny policy
  roguezero onboard <name> --tool <name=scope> create an agent, issue its credentials, allow it
  roguezero connect --agent <name> -- <cmd>    run an agent's MCP client through RogueZero
  roguezero renew --agent <name>               rotate its credentials; retires the old ones
  roguezero revoke --agent <name>              kill it; the next call is denied

Unattended fleets (run where the controller key lives — never on the agent):
  roguezero renew --all [--dir <d>] [--within <sec>]
      Scheduler for a cron: renew every bundle due for it, and refuse to renew a
      revoked one — so automation can never resurrect an agent you killed.

Lower level:
  roguezero create --out <file>
  roguezero issue profile    --issuer <keystore> --subject <did> --controller <did> --name <name> [--description <text>] [--expires <sec>] [--out <file>]
  roguezero issue capability --issuer <keystore> --subject <did> --audience <aud> --tool <name=scope1,scope2> [--tool ...] [--expires <sec>] [--out <file>]
  roguezero verify  --jwt <file> [--revocations <file>]
  roguezero revoke  (--agent <name> | --jwt <file> | --id <credentialId>) [--list <file>] [--config <file>]
  roguezero inspect (--jwt <file> | --audit <file> | --revocations <file>)

Publishing a fleet-wide kill switch:
  roguezero revocations publish [--sign-with <keystore>] [--out <file.jwt>] [--ttl <sec>]
      Signs the local list so verifiers anywhere can trust it. Re-publish on a
      schedule — a stale list is rejected, even if nothing has changed.
`;

function req(value: string | undefined, flag: string): string {
  if (!value) throw new Error(`missing required --${flag}`);
  return value;
}

/** Where a bundle lives: an explicit path, or `<name>.rz.json` beside the config. */
async function resolveBundlePath(agent: string, configPath: string): Promise<string> {
  const direct = resolve(agent);
  if (agent.endsWith(".json") && (await exists(direct))) return direct;
  return resolve(dirname(resolve(configPath)), `${agent}.rz.json`);
}

async function exists(path: string): Promise<boolean> {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
}

async function run(argv: string[]): Promise<number> {
  const [command, ...rest] = argv;

  switch (command) {
    case "init": {
      const { values } = parseArgs({
        args: rest,
        options: { audience: { type: "string" }, dir: { type: "string" } },
      });
      const result = await initCommand({
        dir: values.dir ?? ".",
        audience: req(values.audience, "audience"),
      });
      process.stdout.write(`${result.controllerDid}\n`);
      process.stderr.write(
        `initialized RogueZero workspace\n` +
          `  config:     ${result.configPath}\n` +
          `  controller: ${result.controllerPath}\n` +
          `  policy:     ${result.policyPath}  (empty = deny everything)\n\n` +
          `next: roguezero onboard <name> --tool <tool>=<scope>\n`,
      );
      return 0;
    }

    case "onboard": {
      const [name, ...onboardArgs] = rest;
      if (!name || name.startsWith("-")) throw new Error("onboard requires an agent name");
      const { values } = parseArgs({
        args: onboardArgs,
        options: {
          config: { type: "string" },
          controller: { type: "string" },
          tool: { type: "string", multiple: true },
          expires: { type: "string" },
          out: { type: "string" },
        },
      });
      const configPath = resolve(values.config ?? CONFIG_FILENAME);
      const result = await onboardCommand({
        name,
        configPath,
        controllerPath: values.controller ?? join(dirname(configPath), "controller.key.json"),
        tools: (values.tool ?? []).map(parseToolSpec),
        expiresInSeconds: values.expires ? Number(values.expires) : undefined,
        outPath: values.out,
      });
      process.stdout.write(`${result.agentDid}\n`);
      const grants = result.tools.map((t) => `${t.name} (${t.scopes.join(", ")})`).join("\n    ");
      process.stderr.write(
        `onboarded "${name}"\n` +
          `  bundle: ${result.bundlePath}\n` +
          `  grants: ${grants}\n` +
          `  policy updated; nothing else was granted.\n\n` +
          `next: roguezero connect --agent ${name} -- <your mcp server command>\n`,
      );
      return 0;
    }

    case "renew": {
      const { values } = parseArgs({
        args: rest,
        options: {
          agent: { type: "string" },
          all: { type: "boolean" },
          dir: { type: "string" },
          config: { type: "string" },
          controller: { type: "string" },
          expires: { type: "string" },
          within: { type: "string" },
          "keep-previous": { type: "boolean" },
        },
      });
      const configPath = resolve(values.config ?? CONFIG_FILENAME);
      const controllerPath = values.controller ?? join(dirname(configPath), "controller.key.json");

      // `renew --all` is the controller-side scheduler (ADR 0004) — the thing a cron runs to keep
      // an unattended fleet alive without ever resurrecting a revoked agent.
      if (values.all) {
        const { outcomes } = await renewAllCommand({
          dir: values.dir ? resolve(values.dir) : dirname(configPath),
          configPath,
          controllerPath,
          expiresInSeconds: values.expires ? Number(values.expires) : undefined,
          withinSeconds: values.within ? Number(values.within) : undefined,
        });
        for (const o of outcomes) {
          process.stderr.write(
            `  ${o.outcome.padEnd(16)} ${o.name}${o.error ? ` — ${o.error}` : ""}\n`,
          );
        }
        const count = (x: string) => outcomes.filter((o) => o.outcome === x).length;
        const errors = count("error");
        process.stderr.write(
          `renew --all: ${count("renewed")} renewed, ${count("skipped-fresh")} fresh, ` +
            `${count("skipped-revoked")} revoked (skipped), ${errors} errors\n`,
        );
        return errors > 0 ? 1 : 0;
      }

      const result = await renewCommand({
        bundlePath: await resolveBundlePath(req(values.agent, "agent"), configPath),
        configPath,
        controllerPath,
        expiresInSeconds: values.expires ? Number(values.expires) : undefined,
        keepPrevious: values["keep-previous"],
      });
      process.stdout.write(`${result.capabilityId}\n`);
      process.stderr.write(
        `renewed "${values.agent}" — same identity, new credentials\n` +
          `  bundle:  ${result.bundlePath}\n` +
          `  expires: ${new Date(result.expiresAt * 1000).toISOString()}\n` +
          (result.revokedPrevious
            ? `  retired: ${result.previousCapabilityId} (revoked)\n`
            : `  WARNING: the superseded capability ${result.previousCapabilityId} is still valid.\n` +
              `           ${
                result.revocationListPath
                  ? "Re-run without --keep-previous to retire it."
                  : "This deployment reads revocation from a remote source; retire it there."
              }\n`) +
          (result.revocationListPath
            ? `\nIf verifiers read a signed list, run: roguezero revocations publish\n`
            : ""),
      );
      return 0;
    }

    case "connect": {
      // Everything after `--` is the upstream server's command line.
      const sep = rest.indexOf("--");
      const flags = sep === -1 ? rest : rest.slice(0, sep);
      const upstream = sep === -1 ? [] : rest.slice(sep + 1);
      const { values } = parseArgs({
        args: flags,
        options: {
          agent: { type: "string" },
          config: { type: "string" },
          "challenge-tool": { type: "string" },
        },
      });
      if (upstream.length === 0) {
        throw new Error(
          "connect needs the protected server's command after `--`, e.g.\n" +
            "  roguezero connect --agent reporter -- node ./reports-server.js",
        );
      }
      const configPath = resolve(values.config ?? CONFIG_FILENAME);
      const bundlePath = await resolveBundlePath(req(values.agent, "agent"), configPath);
      // Imported lazily: the MCP SDK is an optional peer, so `import "@roguezero/cli"` and
      // every other command keep working without it installed.
      const [{ connect }, { loadBundle }] = await Promise.all([
        import("./connect.js"),
        import("./bundle.js"),
      ]);
      await connect({
        loadBundle: () => loadBundle(bundlePath),
        upstream,
        challengeTool: values["challenge-tool"],
      });
      return 0;
    }

    case "create": {
      const { values } = parseArgs({ args: rest, options: { out: { type: "string" } } });
      const keystore = await createCommand({ outPath: values.out });
      // stdout carries the DID and nothing else, so `AGENT=$(roguezero create --out a.json)`
      // captures an identifier rather than a progress message. Chatter goes to stderr.
      process.stdout.write(`${keystore.did}\n`);
      if (values.out) process.stderr.write(`saved keystore -> ${values.out}\n`);
      return 0;
    }

    case "issue": {
      const [kind, ...issueArgs] = rest;
      const { values } = parseArgs({
        args: issueArgs,
        options: {
          issuer: { type: "string" },
          subject: { type: "string" },
          controller: { type: "string" },
          name: { type: "string" },
          description: { type: "string" },
          audience: { type: "string" },
          tool: { type: "string", multiple: true },
          expires: { type: "string" },
          out: { type: "string" },
        },
      });
      const expiresInSeconds = values.expires ? Number(values.expires) : undefined;

      if (kind === "profile") {
        const { jwt } = await issueProfileCommand({
          issuerPath: req(values.issuer, "issuer"),
          subjectDid: req(values.subject, "subject"),
          controller: req(values.controller, "controller"),
          name: req(values.name, "name"),
          description: values.description,
          expiresInSeconds,
          outPath: values.out,
        });
        if (values.out) process.stderr.write(`saved AgentProfile -> ${values.out}\n`);
        else process.stdout.write(`${jwt}\n`);
        return 0;
      }
      if (kind === "capability") {
        const tools = (values.tool ?? []).map(parseToolSpec);
        if (tools.length === 0) throw new Error("capability requires at least one --tool");
        const { jwt } = await issueCapabilityCommand({
          issuerPath: req(values.issuer, "issuer"),
          subjectDid: req(values.subject, "subject"),
          audience: req(values.audience, "audience"),
          tools,
          expiresInSeconds,
          outPath: values.out,
        });
        if (values.out) process.stderr.write(`saved AgentCapability -> ${values.out}\n`);
        else process.stdout.write(`${jwt}\n`);
        return 0;
      }
      throw new Error(`unknown issue type "${kind ?? ""}"; expected profile|capability`);
    }

    case "verify": {
      const { values } = parseArgs({
        args: rest,
        options: { jwt: { type: "string" }, revocations: { type: "string" } },
      });
      const result = await verifyCommand({
        jwtPath: req(values.jwt, "jwt"),
        revocationsPath: values.revocations,
      });
      if (result.revoked) {
        process.stderr.write(
          `REVOKED  ${result.type}\n` +
            `  subject: ${result.subject.id}\n` +
            `  The signature is valid but this credential has been revoked; a guard will deny it.\n` +
            `  fix:     Issue a new capability; a revoked one is permanently dead.\n`,
        );
        return 1;
      }
      process.stdout.write(`OK  ${result.type}\n`);
      process.stdout.write(`  issuer:  ${result.issuer}\n`);
      process.stdout.write(`  subject: ${result.subject.id}\n`);
      if (result.expiresAt) {
        process.stdout.write(`  expires: ${new Date(result.expiresAt * 1000).toISOString()}\n`);
      }
      process.stdout.write(
        result.revoked === undefined
          ? `  revocation: not checked (pass --revocations <file>)\n`
          : `  revocation: not revoked\n`,
      );
      return 0;
    }

    case "revoke": {
      const { values } = parseArgs({
        args: rest,
        options: {
          list: { type: "string" },
          id: { type: "string" },
          jwt: { type: "string" },
          agent: { type: "string" },
          config: { type: "string" },
        },
      });
      const configPath = resolve(values.config ?? CONFIG_FILENAME);
      // The revocation list is a deployment fact, not something to retype: take it from the
      // config when there is one, and fall back to requiring --list when there isn't.
      let listPath = values.list;
      if (!listPath && (await exists(configPath))) {
        const config = await loadGuardConfig(configPath);
        listPath = writableRevocationPath(config);
        if (!listPath) {
          // Writing a local file here would look like it worked and revoke nothing.
          throw new Error(
            `${configPath} reads revocation from ${config.revocation.source === "url" ? config.revocation.url : "a remote source"}, ` +
              `which this command cannot write. Publish a signed list from wherever that URL is served, ` +
              `or pass --list <file> to write a local one.`,
          );
        }
      }
      const bundlePath = values.agent
        ? await resolveBundlePath(values.agent, configPath)
        : undefined;
      const { revokedId } = await revokeCommand({
        listPath: req(listPath, "list"),
        id: values.id,
        jwtPath: values.jwt,
        bundlePath,
      });
      process.stdout.write(`revoked ${revokedId}\n`);
      if (values.agent) {
        process.stderr.write(`"${values.agent}" is dead; its next call is denied.\n`);
      }
      return 0;
    }

    case "revocations": {
      const [sub, ...subArgs] = rest;
      if (sub !== "publish") {
        throw new Error(`unknown revocations command "${sub ?? ""}"; expected publish`);
      }
      const { values } = parseArgs({
        args: subArgs,
        options: {
          config: { type: "string" },
          list: { type: "string" },
          "sign-with": { type: "string" },
          out: { type: "string" },
          ttl: { type: "string" },
        },
      });
      const configPath = resolve(values.config ?? CONFIG_FILENAME);
      const configDir = dirname(configPath);

      let listPath = values.list;
      if (!listPath && (await exists(configPath))) {
        listPath = writableRevocationPath(await loadGuardConfig(configPath));
      }
      if (!listPath) {
        throw new Error("revocations publish requires --list <unsigned revocations.json>");
      }

      const result = await publishRevocationsCommand({
        listPath: resolve(listPath),
        signWithPath: resolve(values["sign-with"] ?? join(configDir, "controller.key.json")),
        outPath: resolve(values.out ?? join(configDir, "revocations.jwt")),
        ttlSeconds: values.ttl ? Number(values.ttl) : undefined,
      });

      process.stdout.write(`${result.outPath}\n`);
      process.stderr.write(
        `published signed revocation list\n` +
          `  issuer:  ${result.issuer}\n` +
          `  seq:     ${result.seq}\n` +
          `  revoked: ${result.published.length}` +
          (result.pruned.length ? `  (pruned ${result.pruned.length} expired)` : "") +
          `\n  expires: ${new Date(result.expiresAt * 1000).toISOString()}\n\n` +
          `Verifiers reject a stale list, so re-publish before then — even if nothing changed.\n`,
      );
      return 0;
    }

    case "inspect": {
      const { values } = parseArgs({
        args: rest,
        options: {
          jwt: { type: "string" },
          audit: { type: "string" },
          revocations: { type: "string" },
        },
      });
      if (values.revocations) {
        process.stdout.write(`${await inspectRevocationsCommand({ path: values.revocations })}\n`);
        return 0;
      }
      if (values.audit) {
        process.stdout.write(`${await inspectAuditCommand({ auditPath: values.audit })}\n`);
        return 0;
      }
      if (values.jwt) {
        process.stdout.write(`${await inspectJwtCommand({ jwtPath: values.jwt })}\n`);
        return 0;
      }
      throw new Error("inspect requires --jwt, --audit, or --revocations");
    }

    case undefined:
    case "--help":
    case "-h":
      process.stdout.write(HELP);
      return 0;

    default:
      process.stderr.write(`unknown command: ${command}\n\n${HELP}`);
      return 1;
  }
}

run(process.argv.slice(2))
  .then((code) => {
    process.exitCode = code;
  })
  .catch((error: unknown) => {
    if (error instanceof VerificationError) {
      const e = explainDenial(error.reason);
      process.stderr.write(
        `verification failed: ${e.summary}\n  reason: ${error.reason}\n  fix:    ${e.fix}\n`,
      );
    } else {
      process.stderr.write(`error: ${error instanceof Error ? error.message : String(error)}\n`);
    }
    process.exitCode = 1;
  });
