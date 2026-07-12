/**
 * Tool registry (ADR 0005 D1) — the SSRF-containment layer. An agent names a **tool** and supplies
 * typed **parameters**; it never supplies a URL, host, scheme, or method. The registry pins the
 * target and turns (toolId, args) into a validated `RequestPlan`, or throws. It holds no vault and
 * makes no network call — pure, so every threat in `docs/RUNTIME-THREATS.md` it owns is a unit test.
 *
 * What it guarantees (the rest — DNS rebinding, redirect-following, private-IP dial — is the
 * injection proxy's dispatch layer, since it needs the network):
 *   - agent input never reaches host/scheme/authority (T-INJ-1); the built URL's host is asserted
 *     to equal the pinned host;
 *   - path params can't traverse (`.`/`..`/`/`/`\` rejected, then percent-encoded) (T-INJ-5);
 *   - no param may contain control chars / CRLF (T-INJ-6);
 *   - the method is fixed by the tool, not the agent (T-INJ-9);
 *   - the credential goes only in a header/bearer/basic slot, never a query param (T-INJ-11);
 *   - `http` is refused unless the tool is explicitly `internal` (T-INJ-12);
 *   - agents can't set the `authorization` (or the credential's) header.
 *
 * The `RequestPlan` carries the credential **ref + placement**, not the secret — the proxy decrypts
 * from the vault and injects. The registry never sees a credential value.
 */

import { z } from "zod";

export type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";

const HOSTNAME = /^[a-zA-Z0-9.-]+$/; // hostname or IPv4 literal; no scheme/port/userinfo/path

/** True if the string contains any C0 control char or DEL — the header/path-injection defense (CRLF included). */
function hasControlChar(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c <= 0x1f || c === 0x7f) return true;
  }
  return false;
}

const httpMethod = z.enum(["GET", "POST", "PUT", "PATCH", "DELETE"]);

const toolParamSchema = z
  .object({
    name: z.string().min(1),
    in: z.enum(["path", "query", "header", "body"]),
    type: z.enum(["string", "number", "enum"]).default("string"),
    enum: z.array(z.string()).optional(),
    required: z.boolean().default(false),
    pattern: z.string().optional(),
    /** For `in: "header"`, the header name to set (defaults to `name`). */
    header: z.string().optional(),
  })
  .strict();

const credentialInjectionSchema = z
  .object({
    ref: z.string().min(1),
    // No `query` — a credential in a URL leaks into downstream/proxy logs (T-INJ-11).
    placement: z.enum(["bearer", "basic", "header"]),
    header: z.string().optional(),
  })
  .strict()
  .refine((c) => c.placement !== "header" || !!c.header, {
    message: "placement 'header' requires a header name",
  });

/** Any JSON value — the shape a `bodyTemplate` may take (it comes from a parsed JSON registry). */
type JsonValue = string | number | boolean | null | JsonValue[] | { [k: string]: JsonValue };
const jsonValueSchema: z.ZodType<JsonValue> = z.lazy(() =>
  z.union([
    z.string(),
    z.number(),
    z.boolean(),
    z.null(),
    z.array(jsonValueSchema),
    z.record(jsonValueSchema),
  ]),
);

const toolDefinitionSchema = z
  .object({
    id: z.string().min(1),
    method: httpMethod,
    scheme: z.enum(["https", "http"]),
    host: z.string().regex(HOSTNAME, "host must be a bare hostname or IP (no scheme/port/path)"),
    port: z.number().int().min(1).max(65535).optional(),
    /** Path template beginning with `/`, with `{name}` slots for `in: "path"` params. */
    path: z.string().startsWith("/"),
    /** Static query pairs (not agent-controlled). */
    query: z.record(z.string()).optional(),
    /**
     * A nested JSON request body with `{name}` placeholders filled by `in: "body"` params — for
     * APIs whose payload isn't a flat object (OpenAI chat, GraphQL, SendGrid). Operator-authored;
     * agent values only ever land in placeholder slots, and are typed/validated like any param, so
     * they cannot alter the body's structure. Omit for the flat-object default.
     */
    bodyTemplate: jsonValueSchema.optional(),
    /**
     * Static request headers set by the operator, not the agent — e.g. `Accept`, `User-Agent`, an
     * API-version header a real API demands. Never the credential/`authorization` header (that is
     * injected), and never agent-controlled; validated for that at parse time.
     */
    headers: z.record(z.string()).optional(),
    params: z.array(toolParamSchema).optional(),
    credential: credentialInjectionSchema,
    /** Allow a private/internal target. Off by default — `http` and private IPs need this. */
    internal: z.boolean().default(false),
  })
  .strict()
  .refine((t) => t.scheme !== "http" || t.internal, {
    message: "scheme 'http' is only allowed for an internal tool",
  });

export const toolRegistrySchema = z
  .object({ tools: z.array(toolDefinitionSchema) })
  .strict()
  .refine((r) => new Set(r.tools.map((t) => t.id)).size === r.tools.length, {
    message: "duplicate tool id",
  });

export type ToolParam = z.infer<typeof toolParamSchema>;
export type CredentialInjection = z.infer<typeof credentialInjectionSchema>;
export type ToolDefinition = z.infer<typeof toolDefinitionSchema>;

/** A validated, pinned request. The credential is referenced, not present — the proxy injects it. */
export interface RequestPlan {
  method: HttpMethod;
  url: string;
  headers: Record<string, string>;
  body?: string;
  credential: CredentialInjection;
  internal: boolean;
}

/** A parsed, index-able registry. */
export interface ToolRegistry {
  byId: Map<string, ToolDefinition>;
}

/** Parse + validate a registry config (a trust boundary), rejecting agent-settable auth headers. */
export function parseToolRegistry(raw: unknown): ToolRegistry {
  const parsed = toolRegistrySchema.parse(raw);
  const byId = new Map<string, ToolDefinition>();
  for (const tool of parsed.tools) {
    const reserved = new Set(
      ["authorization", tool.credential.header?.toLowerCase()].filter(Boolean) as string[],
    );
    for (const p of tool.params ?? []) {
      if (p.in === "header") {
        const h = (p.header ?? p.name).toLowerCase();
        if (reserved.has(h)) {
          throw new Error(
            `tool ${tool.id}: header param '${h}' collides with the credential header`,
          );
        }
      }
    }
    // Static headers may not impersonate the credential/authorization header, nor smuggle CRLF.
    for (const [key, value] of Object.entries(tool.headers ?? {})) {
      const lk = key.toLowerCase();
      if (reserved.has(lk)) {
        throw new Error(
          `tool ${tool.id}: static header '${lk}' collides with the credential header`,
        );
      }
      if (hasControlChar(key) || hasControlChar(value)) {
        throw new Error(`tool ${tool.id}: static header '${key}' contains control characters`);
      }
    }
    // A body template and its `in: "body"` params must correspond exactly — catches typos that would
    // otherwise silently send an empty slot or drop a value.
    if (tool.bodyTemplate !== undefined) {
      const bodyParams = new Set(
        (tool.params ?? []).filter((p) => p.in === "body").map((p) => p.name),
      );
      const placeholders = collectPlaceholders(tool.bodyTemplate);
      for (const ph of placeholders) {
        if (!bodyParams.has(ph)) {
          throw new Error(
            `tool ${tool.id}: bodyTemplate references undeclared body param '{${ph}}'`,
          );
        }
      }
      for (const bp of bodyParams) {
        if (!placeholders.has(bp)) {
          throw new Error(`tool ${tool.id}: body param '${bp}' is not used in bodyTemplate`);
        }
      }
    }
    byId.set(tool.id, tool);
  }
  return { byId };
}

function validateScalar(param: ToolParam, raw: unknown): string {
  const v = String(raw);
  if (hasControlChar(v)) throw new Error(`param '${param.name}' contains control characters`);
  if (param.type === "number" && !/^-?\d+(\.\d+)?$/.test(v)) {
    throw new Error(`param '${param.name}' must be a number`);
  }
  if (param.type === "enum" && !(param.enum ?? []).includes(v)) {
    throw new Error(`param '${param.name}' must be one of ${JSON.stringify(param.enum ?? [])}`);
  }
  if (param.pattern && !new RegExp(`^(?:${param.pattern})$`).test(v)) {
    throw new Error(`param '${param.name}' does not match /${param.pattern}/`);
  }
  return v;
}

/** A lone placeholder for an absent optional param → its object key / array element is dropped. */
const OMIT = Symbol("omit");
const PLACEHOLDER = /\{([^{}]+)\}/g;

/** Collect the `{name}` placeholders referenced anywhere in a body template. */
function collectPlaceholders(node: unknown, out: Set<string> = new Set()): Set<string> {
  if (typeof node === "string") {
    for (const m of node.matchAll(PLACEHOLDER)) out.add(m[1]!);
  } else if (Array.isArray(node)) {
    for (const el of node) collectPlaceholders(el, out);
  } else if (node && typeof node === "object") {
    for (const v of Object.values(node)) collectPlaceholders(v, out);
  }
  return out;
}

/**
 * Fill a body template with typed param values. A string that is *exactly* one placeholder becomes
 * the param's typed value (a number stays a number); a placeholder embedded in a larger string is
 * string-interpolated. An absent optional param drops its object key / array element. Agent values
 * only ever occupy leaf slots, so they can never reshape the JSON around them.
 */
function fillTemplate(node: unknown, values: Map<string, string | number>): unknown {
  if (typeof node === "string") {
    const lone = node.match(/^\{([^{}]+)\}$/);
    if (lone) {
      const name = lone[1]!;
      return values.has(name) ? values.get(name)! : OMIT;
    }
    return node.replace(PLACEHOLDER, (_, name: string) =>
      values.has(name) ? String(values.get(name)) : "",
    );
  }
  if (Array.isArray(node)) {
    return node.map((el) => fillTemplate(el, values)).filter((v) => v !== OMIT);
  }
  if (node && typeof node === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(node)) {
      const filled = fillTemplate(v, values);
      if (filled !== OMIT) out[k] = filled;
    }
    return out;
  }
  return node;
}

/** Turn a tool call into a validated, pinned request — or throw. Never touches host/scheme/method. */
export function resolveRequest(
  registry: ToolRegistry,
  toolId: string,
  args: Record<string, unknown> = {},
): RequestPlan {
  const tool = registry.byId.get(toolId);
  if (!tool) throw new Error(`unknown tool '${toolId}'`);

  const params = tool.params ?? [];
  const byName = new Map(params.map((p) => [p.name, p]));

  // Reject any arg the tool did not declare (an agent can't smuggle in method/host/etc.).
  for (const key of Object.keys(args)) {
    if (!byName.has(key)) throw new Error(`tool '${toolId}' has no parameter '${key}'`);
  }
  for (const p of params) {
    if (p.required && (args[p.name] === undefined || args[p.name] === null)) {
      throw new Error(`tool '${toolId}' requires parameter '${p.name}'`);
    }
  }

  // Seed with the operator's static headers (lowercased); agent params and the injected credential
  // layer on top. The credential header always wins — it is injected last, in the proxy.
  const headers: Record<string, string> = {};
  for (const [k, v] of Object.entries(tool.headers ?? {})) headers[k.toLowerCase()] = v;
  const queryPairs: [string, string][] = Object.entries(tool.query ?? {});
  const bodyValues = new Map<string, string | number>();
  let path = tool.path;

  for (const p of params) {
    const raw = args[p.name];
    if (raw === undefined || raw === null) continue; // optional & absent
    const value = validateScalar(p, raw);
    switch (p.in) {
      case "path": {
        if (value === "." || value === ".." || /[/\\%]/.test(value)) {
          throw new Error(`path param '${p.name}' contains an illegal path character`);
        }
        path = path.replaceAll(`{${p.name}}`, encodeURIComponent(value));
        break;
      }
      case "query":
        queryPairs.push([p.name, value]);
        break;
      case "header":
        headers[p.header ?? p.name] = value; // control chars already rejected (no CRLF)
        break;
      case "body":
        bodyValues.set(p.name, p.type === "number" ? Number(value) : value);
        break;
    }
  }

  if (/\{[^}]+\}/.test(path)) throw new Error(`unfilled path slot in '${path}'`);
  if (path.includes("..")) throw new Error(`resolved path traverses: '${path}'`);

  const authority = `${tool.host}${tool.port ? `:${tool.port}` : ""}`;
  const query = queryPairs
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
    .join("&");
  const url = `${tool.scheme}://${authority}${path}${query ? `?${query}` : ""}`;

  // Belt-and-suspenders: the built URL's host/scheme must equal the pinned ones. Catches any
  // template or encoding trick that tried to escape the authority.
  const parsed = new URL(url);
  if (parsed.hostname.toLowerCase() !== tool.host.toLowerCase()) {
    throw new Error(`refusing request: resolved host ${parsed.hostname} != pinned ${tool.host}`);
  }
  if (parsed.protocol !== `${tool.scheme}:`) {
    throw new Error(`refusing request: resolved scheme ${parsed.protocol} != ${tool.scheme}`);
  }

  const plan: RequestPlan = {
    method: tool.method,
    url,
    headers,
    credential: tool.credential,
    internal: tool.internal,
  };
  // A body template (nested/GraphQL payloads) fills placeholders; otherwise the flat-object default.
  if (tool.bodyTemplate !== undefined) {
    plan.body = JSON.stringify(fillTemplate(tool.bodyTemplate, bodyValues));
    plan.headers["content-type"] = "application/json";
  } else if (bodyValues.size > 0) {
    plan.body = JSON.stringify(Object.fromEntries(bodyValues));
    plan.headers["content-type"] = "application/json";
  }
  return plan;
}
