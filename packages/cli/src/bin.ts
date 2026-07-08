#!/usr/bin/env node
/**
 * CLI entrypoint: a thin argv parser (Node's built-in util.parseArgs) over the command
 * functions in commands.ts. Errors are printed clearly and set a non-zero exit code.
 */

import { parseArgs } from "node:util";
import { explainDenial, VerificationError } from "@roguezero/core";
import {
  createCommand,
  inspectAuditCommand,
  inspectJwtCommand,
  issueCapabilityCommand,
  issueProfileCommand,
  parseToolSpec,
  revokeCommand,
  verifyCommand,
} from "./commands.js";

const HELP = `roguezero — verifiable agent identity & authorization

Usage:
  roguezero create --out <file>
  roguezero issue profile    --issuer <keystore> --subject <did> --controller <did> --name <name> [--description <text>] [--expires <sec>] [--out <file>]
  roguezero issue capability --issuer <keystore> --subject <did> --audience <aud> --tool <name=scope1,scope2> [--tool ...] [--expires <sec>] [--out <file>]
  roguezero verify  --jwt <file>
  roguezero revoke  --list <file> (--id <credentialId> | --jwt <file>)
  roguezero inspect (--jwt <file> | --audit <file>)
`;

function req(value: string | undefined, flag: string): string {
  if (!value) throw new Error(`missing required --${flag}`);
  return value;
}

async function run(argv: string[]): Promise<number> {
  const [command, ...rest] = argv;

  switch (command) {
    case "create": {
      const { values } = parseArgs({ args: rest, options: { out: { type: "string" } } });
      const keystore = await createCommand({ outPath: values.out });
      process.stdout.write(`${keystore.did}\n`);
      if (values.out) process.stdout.write(`saved keystore -> ${values.out}\n`);
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
        process.stdout.write(values.out ? `saved AgentProfile -> ${values.out}\n` : `${jwt}\n`);
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
        process.stdout.write(values.out ? `saved AgentCapability -> ${values.out}\n` : `${jwt}\n`);
        return 0;
      }
      throw new Error(`unknown issue type "${kind ?? ""}"; expected profile|capability`);
    }

    case "verify": {
      const { values } = parseArgs({ args: rest, options: { jwt: { type: "string" } } });
      const result = await verifyCommand({ jwtPath: req(values.jwt, "jwt") });
      process.stdout.write(`OK  ${result.type}\n`);
      process.stdout.write(`  issuer:  ${result.issuer}\n`);
      process.stdout.write(`  subject: ${result.subject.id}\n`);
      if (result.expiresAt) {
        process.stdout.write(`  expires: ${new Date(result.expiresAt * 1000).toISOString()}\n`);
      }
      return 0;
    }

    case "revoke": {
      const { values } = parseArgs({
        args: rest,
        options: { list: { type: "string" }, id: { type: "string" }, jwt: { type: "string" } },
      });
      const { revokedId } = await revokeCommand({
        listPath: req(values.list, "list"),
        id: values.id,
        jwtPath: values.jwt,
      });
      process.stdout.write(`revoked ${revokedId}\n`);
      return 0;
    }

    case "inspect": {
      const { values } = parseArgs({
        args: rest,
        options: { jwt: { type: "string" }, audit: { type: "string" } },
      });
      if (values.audit) {
        process.stdout.write(`${await inspectAuditCommand({ auditPath: values.audit })}\n`);
        return 0;
      }
      if (values.jwt) {
        process.stdout.write(`${await inspectJwtCommand({ jwtPath: values.jwt })}\n`);
        return 0;
      }
      throw new Error("inspect requires --jwt or --audit");
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
