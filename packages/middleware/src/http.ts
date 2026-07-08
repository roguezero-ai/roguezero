/**
 * HTTP middleware (Hono): the same verify → policy → audit pipeline as the MCP wrapper, for
 * plain HTTP tool endpoints. Thin transport glue over `@roguezero/core`'s authorizeToolCall.
 *
 * Transport: the agent obtains a one-time challenge from the challenge route, then sends the
 * holder-signed presentation in the `x-roguezero-presentation` header on the protected
 * request. Denials return 403 with the precise reason and correlation id; on allow, the
 * verified request is stashed on the context for the handler.
 */

import type { Context, MiddlewareHandler } from "hono";
import { authorizeToolCall, explainDenial } from "@roguezero/core";
import type { AuthorizedContext, RogueZeroGuardOptions } from "./shared.js";

/** Header carrying the holder-signed presentation on protected requests. */
export const PRESENTATION_HEADER = "x-roguezero-presentation";

/** Hono env exposing the authorized context to downstream handlers via `c.get("rogueZero")`. */
export interface RogueZeroHonoEnv {
  Variables: { rogueZero: AuthorizedContext };
}

export function createHttpGuard(options: RogueZeroGuardOptions) {
  return {
    /** Route handler that issues a one-time challenge bound to this endpoint's audience. */
    async issueChallenge(c: Context): Promise<Response> {
      const challenge = await options.nonceStore.issue(options.audience);
      return c.json(challenge);
    },

    /** Middleware protecting a route for a given tool: verify → policy → audit, else 403. */
    protect(tool: string): MiddlewareHandler<RogueZeroHonoEnv> {
      return async (c, next) => {
        const presentation = c.req.header(PRESENTATION_HEADER) ?? "";
        const result = await authorizeToolCall({
          presentation,
          tool,
          audience: options.audience,
          resolver: options.resolver,
          trustedIssuers: options.trustedIssuers,
          nonceStore: options.nonceStore,
          policy: options.policy,
          auditSink: options.auditSink,
          isRevoked: options.isRevoked,
        });

        if (result.decision !== "allow" || !result.request) {
          const e = explainDenial(result.reason);
          return c.json(
            {
              error: "forbidden",
              reason: result.reason,
              summary: e.summary,
              fix: e.fix,
              correlationId: result.correlationId,
            },
            403,
          );
        }

        c.set("rogueZero", { authorized: result.request, correlationId: result.correlationId });
        await next();
      };
    },
  };
}
