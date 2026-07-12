import { describe, expect, it } from "vitest";
import { parseToolRegistry, resolveRequest, type ToolRegistry } from "./registry.js";

/** A GitHub-style registry: pinned host, one path param, one query param, bearer credential. */
function ghRegistry(): ToolRegistry {
  return parseToolRegistry({
    tools: [
      {
        id: "gh-issues",
        method: "GET",
        scheme: "https",
        host: "api.github.com",
        path: "/repos/{owner}/{repo}/issues",
        query: { per_page: "20" },
        params: [
          { name: "owner", in: "path", required: true },
          { name: "repo", in: "path", required: true },
          { name: "state", in: "query", type: "enum", enum: ["open", "closed"] },
        ],
        credential: { ref: "github", placement: "bearer" },
      },
    ],
  });
}

describe("registry — valid resolution", () => {
  it("builds a pinned request from tool + params; the credential is referenced, not present", () => {
    const plan = resolveRequest(ghRegistry(), "gh-issues", {
      owner: "acme",
      repo: "app",
      state: "open",
    });
    expect(plan.method).toBe("GET");
    expect(plan.url).toBe("https://api.github.com/repos/acme/app/issues?per_page=20&state=open");
    expect(plan.credential).toEqual({ ref: "github", placement: "bearer" });
    // The registry never sees the secret — no auth header is set here.
    expect(Object.keys(plan.headers).map((h) => h.toLowerCase())).not.toContain("authorization");
  });

  it("percent-encodes path params (no structure injection)", () => {
    const plan = resolveRequest(ghRegistry(), "gh-issues", { owner: "a b", repo: "x&y" });
    expect(plan.url).toBe("https://api.github.com/repos/a%20b/x%26y/issues?per_page=20");
    expect(new URL(plan.url).hostname).toBe("api.github.com");
  });

  it("assembles a JSON body from body params", () => {
    const reg = parseToolRegistry({
      tools: [
        {
          id: "create-issue",
          method: "POST",
          scheme: "https",
          host: "api.github.com",
          path: "/repos/o/r/issues",
          params: [{ name: "title", in: "body", required: true }],
          credential: { ref: "github", placement: "bearer" },
        },
      ],
    });
    const plan = resolveRequest(reg, "create-issue", { title: "bug" });
    expect(plan.body).toBe(JSON.stringify({ title: "bug" }));
    expect(plan.headers["content-type"]).toBe("application/json");
  });
});

describe("registry — fails closed (RUNTIME-THREATS)", () => {
  it("T-INJ-1: agent input never reaches the host; undeclared args are refused", () => {
    // No arg maps to host/scheme/method; an attempt to add one is rejected.
    expect(() =>
      resolveRequest(ghRegistry(), "gh-issues", { owner: "a", repo: "b", host: "evil.com" }),
    ).toThrow(/no parameter 'host'/);
    // Even a hostile path-param value stays inside the path — host is asserted pinned.
    const plan = resolveRequest(ghRegistry(), "gh-issues", { owner: "x", repo: "y" });
    expect(new URL(plan.url).hostname).toBe("api.github.com");
  });

  it("T-INJ-5: path params can't traverse", () => {
    expect(() => resolveRequest(ghRegistry(), "gh-issues", { owner: "..", repo: "b" })).toThrow(
      /illegal path/,
    );
    expect(() => resolveRequest(ghRegistry(), "gh-issues", { owner: "a/b", repo: "c" })).toThrow(
      /illegal path/,
    );
  });

  it("T-INJ-6: control chars / CRLF in any param are rejected", () => {
    expect(() => resolveRequest(ghRegistry(), "gh-issues", { owner: "a\r\nb", repo: "c" })).toThrow(
      /control characters/,
    );
  });

  it("T-INJ-9: the method is fixed — no arg can change it", () => {
    expect(() =>
      resolveRequest(ghRegistry(), "gh-issues", { owner: "a", repo: "b", method: "DELETE" }),
    ).toThrow(/no parameter 'method'/);
    expect(resolveRequest(ghRegistry(), "gh-issues", { owner: "a", repo: "b" }).method).toBe("GET");
  });

  it("T-INJ-11: a credential may not be placed in a query param", () => {
    expect(() =>
      parseToolRegistry({
        tools: [
          {
            id: "t",
            method: "GET",
            scheme: "https",
            host: "api.example.com",
            path: "/x",
            credential: { ref: "k", placement: "query" },
          },
        ],
      }),
    ).toThrow();
  });

  it("T-INJ-12: http is refused unless the tool is explicitly internal", () => {
    const cfg = (internal: boolean) => ({
      tools: [
        {
          id: "t",
          method: "GET",
          scheme: "http",
          host: "10.0.0.5",
          path: "/x",
          internal,
          credential: { ref: "k", placement: "bearer" },
        },
      ],
    });
    expect(() => parseToolRegistry(cfg(false))).toThrow();
    expect(() => parseToolRegistry(cfg(true))).not.toThrow();
  });

  it("rejects a host that smuggles a scheme, port, path, or userinfo", () => {
    for (const host of ["evil.com/x", "a@b.com", "https://x", "host:8080", "a b"]) {
      expect(() =>
        parseToolRegistry({
          tools: [
            {
              id: "t",
              method: "GET",
              scheme: "https",
              host,
              path: "/x",
              credential: { ref: "k", placement: "bearer" },
            },
          ],
        }),
      ).toThrow();
    }
  });

  it("rejects agent-settable auth headers and duplicate tool ids", () => {
    expect(() =>
      parseToolRegistry({
        tools: [
          {
            id: "t",
            method: "GET",
            scheme: "https",
            host: "api.example.com",
            path: "/x",
            params: [{ name: "auth", in: "header", header: "Authorization" }],
            credential: { ref: "k", placement: "bearer" },
          },
        ],
      }),
    ).toThrow(/collides with the credential header/);

    expect(() =>
      parseToolRegistry({
        tools: [
          {
            id: "dup",
            method: "GET",
            scheme: "https",
            host: "a.com",
            path: "/x",
            credential: { ref: "k", placement: "bearer" },
          },
          {
            id: "dup",
            method: "GET",
            scheme: "https",
            host: "a.com",
            path: "/y",
            credential: { ref: "k", placement: "bearer" },
          },
        ],
      }),
    ).toThrow(/duplicate tool id/);
  });

  it("enforces enum, number, and required params, and unknown tools", () => {
    expect(() =>
      resolveRequest(ghRegistry(), "gh-issues", { owner: "a", repo: "b", state: "bogus" }),
    ).toThrow(/must be one of/);
    expect(() => resolveRequest(ghRegistry(), "gh-issues", { repo: "b" })).toThrow(
      /requires parameter 'owner'/,
    );
    expect(() => resolveRequest(ghRegistry(), "nope", {})).toThrow(/unknown tool/);
  });
});

describe("registry — static operator headers", () => {
  const withHeaders = (headers: Record<string, string>): ToolRegistry =>
    parseToolRegistry({
      tools: [
        {
          id: "t",
          method: "GET",
          scheme: "https",
          host: "api.example.com",
          path: "/x",
          headers,
          credential: { ref: "k", placement: "bearer" },
        },
      ],
    });

  it("sets the operator's static headers on the built request (lowercased)", () => {
    const plan = resolveRequest(
      withHeaders({ "User-Agent": "roguezero", Accept: "application/vnd.github+json" }),
      "t",
    );
    expect(plan.headers["user-agent"]).toBe("roguezero");
    expect(plan.headers["accept"]).toBe("application/vnd.github+json");
  });

  it("refuses a static header that impersonates the credential/authorization header", () => {
    expect(() => withHeaders({ Authorization: "Bearer sneaky" })).toThrow(/collides/);
    expect(() =>
      parseToolRegistry({
        tools: [
          {
            id: "t",
            method: "GET",
            scheme: "https",
            host: "api.example.com",
            path: "/x",
            headers: { "X-Api-Key": "static" },
            credential: { ref: "k", placement: "header", header: "X-Api-Key" },
          },
        ],
      }),
    ).toThrow(/collides/);
  });

  it("refuses a static header carrying control characters (CRLF injection)", () => {
    expect(() => withHeaders({ "X-Evil": "a\r\nInjected: 1" })).toThrow(/control characters/);
  });
});

describe("registry — nested body templates", () => {
  const openaiRegistry = (): ToolRegistry =>
    parseToolRegistry({
      tools: [
        {
          id: "chat",
          method: "POST",
          scheme: "https",
          host: "api.openai.com",
          path: "/v1/chat/completions",
          bodyTemplate: {
            model: "{model}",
            messages: [{ role: "user", content: "{prompt}" }],
            max_tokens: 1024,
            stream: "{stream}",
          },
          params: [
            { name: "model", in: "body", required: true },
            { name: "prompt", in: "body", required: true },
            { name: "stream", in: "body" },
          ],
          credential: { ref: "openai", placement: "bearer" },
        },
      ],
    });

  it("fills placeholders into a nested body and sets JSON content-type", () => {
    const plan = resolveRequest(openaiRegistry(), "chat", {
      model: "gpt-4o",
      prompt: "hello there",
    });
    expect(plan.headers["content-type"]).toBe("application/json");
    expect(JSON.parse(plan.body!)).toEqual({
      model: "gpt-4o",
      messages: [{ role: "user", content: "hello there" }],
      max_tokens: 1024,
      // `stream` was optional and absent → its object key is dropped, not sent empty.
    });
  });

  it("keeps a numeric param a JSON number, not a quoted string", () => {
    const registry = parseToolRegistry({
      tools: [
        {
          id: "t",
          method: "POST",
          scheme: "https",
          host: "api.example.com",
          path: "/x",
          bodyTemplate: { limit: "{n}", nested: { value: "{n}" } },
          params: [{ name: "n", in: "body", type: "number" }],
          credential: { ref: "k", placement: "bearer" },
        },
      ],
    });
    const body = JSON.parse(resolveRequest(registry, "t", { n: 5 }).body!);
    expect(body).toEqual({ limit: 5, nested: { value: 5 } });
    expect(typeof body.limit).toBe("number");
  });

  it("string-interpolates a placeholder embedded in a larger string", () => {
    const registry = parseToolRegistry({
      tools: [
        {
          id: "t",
          method: "POST",
          scheme: "https",
          host: "api.example.com",
          path: "/x",
          bodyTemplate: { greeting: "Hello, {who}!" },
          params: [{ name: "who", in: "body", required: true }],
          credential: { ref: "k", placement: "bearer" },
        },
      ],
    });
    expect(JSON.parse(resolveRequest(registry, "t", { who: "world" }).body!)).toEqual({
      greeting: "Hello, world!",
    });
  });

  it("agent values can't reshape the JSON — a brace-laden value stays a leaf string", () => {
    const plan = resolveRequest(openaiRegistry(), "chat", {
      model: "gpt-4o",
      prompt: '{"role":"system"}',
    });
    const body = JSON.parse(plan.body!) as { messages: { role: string; content: string }[] };
    // The injected value is a plain string leaf, not parsed structure.
    expect(body.messages[0]!.content).toBe('{"role":"system"}');
    expect(body.messages[0]!.role).toBe("user");
  });

  it("rejects a template placeholder with no matching body param, and vice versa", () => {
    const base = {
      id: "t",
      method: "POST",
      scheme: "https",
      host: "api.example.com",
      path: "/x",
      credential: { ref: "k", placement: "bearer" },
    };
    expect(() =>
      parseToolRegistry({
        tools: [{ ...base, bodyTemplate: { a: "{ghost}" }, params: [] }],
      }),
    ).toThrow(/undeclared body param/);
    expect(() =>
      parseToolRegistry({
        tools: [
          { ...base, bodyTemplate: { a: "literal" }, params: [{ name: "unused", in: "body" }] },
        ],
      }),
    ).toThrow(/not used in bodyTemplate/);
  });
});
