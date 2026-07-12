/**
 * `createRuntimeServer` — the runtime's HTTP entrypoint. A framework-free `node:http` server that
 * exposes registered tools to an agent and runs the full spine (`handleToolCall`) on every call:
 *
 *   GET  /challenge → { nonce }           a single-use nonce to bind a presentation to
 *   GET  /tools     → { tools: [...] }     the tool ids this runtime serves
 *   POST /call      → { decision, response | reason }   authenticate → policy → revocation →
 *                                          resolve → decrypt → inject → dispatch → audit
 *
 * The agent never holds a credential; the runtime injects it server-side. Denials are 403,
 * execution failures 502. This is thin transport glue over `handleToolCall` — an embedder can skip
 * it and call `handleToolCall` from their own server.
 */

import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import {
  createRateLimiter,
  handleToolCall,
  type RateLimiter,
  type RuntimeToolCallOptions,
} from "@roguezero/core";

/** Everything the runtime needs, minus the per-request fields (tool/args/presentation). */
export type RuntimeServerOptions = Omit<
  RuntimeToolCallOptions,
  "presentation" | "tool" | "args" | "correlationId"
> & {
  /**
   * Throttle for the unauthenticated `GET /challenge` surface (nonce minting), keyed per client.
   * Omit for the secure default (20-burst, 5/sec sustained). Pass your own `RateLimiter` to tune
   * or share it, or `false` to disable — only sane behind an external gateway that already throttles.
   */
  challengeRateLimiter?: RateLimiter | false;
};

const MAX_BODY_BYTES = 64 * 1024; // a presentation is a few KB; cap hostile bodies

/** Secure-by-default throttle: a short honest burst, then a modest sustained rate per client. */
const DEFAULT_CHALLENGE_RATE = { capacity: 20, refillPerSecond: 5 };

/**
 * Identify the client for rate-limiting. We key on the **socket** remote address only — never a
 * caller-supplied `X-Forwarded-For`, which is trivially spoofed and would let an attacker mint an
 * unlimited number of throttle identities and bypass the limit entirely. A self-hoster behind a
 * trusted proxy should terminate/limit there, or pass a `challengeRateLimiter` that reads a header
 * they control. Unknown address falls back to a single shared bucket (fail closed, not open).
 */
function clientKey(req: IncomingMessage): string {
  return req.socket.remoteAddress ?? "unknown";
}

interface CallBody {
  tool?: string;
  args?: Record<string, unknown>;
  presentation?: string;
}

function json(res: ServerResponse, status: number, obj: unknown): void {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(obj));
}

async function readBody(req: IncomingMessage): Promise<CallBody> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const c of req) {
    size += (c as Buffer).length;
    if (size > MAX_BODY_BYTES) throw new Error("request body too large");
    chunks.push(c as Buffer);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8")) as CallBody;
}

export function createRuntimeServer(options: RuntimeServerOptions): Server {
  const challengeLimiter =
    options.challengeRateLimiter === false
      ? undefined
      : (options.challengeRateLimiter ?? createRateLimiter(DEFAULT_CHALLENGE_RATE));

  const handle = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    try {
      if (req.method === "GET" && req.url === "/challenge") {
        if (challengeLimiter) {
          const verdict = challengeLimiter.check(clientKey(req));
          if (!verdict.allowed) {
            res.setHeader("retry-after", String(verdict.retryAfterSeconds));
            return json(res, 429, { error: "too many challenge requests" });
          }
        }
        const challenge = await options.nonceStore.issue(options.audience);
        return json(res, 200, { nonce: challenge.nonce });
      }
      if (req.method === "GET" && req.url === "/tools") {
        return json(res, 200, { tools: [...options.registry.byId.keys()] });
      }
      if (req.method === "POST" && req.url === "/call") {
        const body = await readBody(req);
        if (!body.tool || !body.presentation) {
          return json(res, 400, { error: "body must include 'tool' and 'presentation'" });
        }
        const result = await handleToolCall({
          ...options,
          tool: body.tool,
          args: body.args ?? {},
          presentation: body.presentation,
        });
        if (result.ok)
          return json(res, 200, { decision: result.decision, response: result.response });
        return json(res, result.decision === "deny" ? 403 : 502, {
          decision: result.decision,
          reason: result.reason,
          error: result.error,
        });
      }
      json(res, 404, { error: "not found" });
    } catch (e) {
      json(res, 500, { error: e instanceof Error ? e.message : String(e) });
    }
  };

  return createServer((req, res) => {
    void handle(req, res);
  });
}
