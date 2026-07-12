import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createServer, type Server } from "node:http";
import { type AddressInfo } from "node:net";
import { dispatchToolCall, injectCredential, isBlockedAddress } from "./proxy.js";
import type { CredentialInjection, RequestPlan } from "./registry.js";

const bytes = (s: string) => new TextEncoder().encode(s);

describe("isBlockedAddress", () => {
  it("blocks loopback, private, link-local/metadata, CGNAT, ULA, and mapped", () => {
    for (const ip of [
      "127.0.0.1",
      "10.0.0.1",
      "172.16.0.1",
      "192.168.1.1",
      "169.254.169.254", // cloud metadata
      "100.64.0.1", // CGNAT
      "0.0.0.0",
      "::1",
      "fe80::1",
      "fc00::1",
      "::ffff:127.0.0.1",
      "not-an-ip",
    ]) {
      expect(isBlockedAddress(ip), ip).toBe(true);
    }
  });

  it("allows public addresses", () => {
    for (const ip of ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111"]) {
      expect(isBlockedAddress(ip), ip).toBe(false);
    }
  });
});

describe("injectCredential", () => {
  const cred: CredentialInjection = { ref: "k", placement: "bearer" };
  it("sets bearer / basic / custom header, never a query param", () => {
    const bearer: Record<string, string> = {};
    injectCredential(bearer, cred, bytes("tok"));
    expect(bearer.authorization).toBe("Bearer tok");

    const basic: Record<string, string> = {};
    injectCredential(basic, { ref: "k", placement: "basic" }, bytes("user:pass"));
    expect(basic.authorization).toBe(`Basic ${Buffer.from("user:pass").toString("base64")}`);

    const custom: Record<string, string> = {};
    injectCredential(custom, { ref: "k", placement: "header", header: "X-API-Key" }, bytes("abc"));
    expect(custom["X-API-Key"]).toBe("abc");
  });
});

describe("dispatchToolCall", () => {
  let server: Server;
  let port = 0;
  let secretHit = false;

  beforeAll(async () => {
    server = createServer((req, res) => {
      if (req.url === "/echo") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(
          JSON.stringify({ auth: req.headers.authorization ?? null, host: req.headers.host }),
        );
      } else if (req.url === "/redirect") {
        res.writeHead(302, { location: "/secret" });
        res.end("go away");
      } else if (req.url === "/secret") {
        secretHit = true;
        res.writeHead(200);
        res.end("SECRET");
      } else {
        res.writeHead(404);
        res.end();
      }
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    port = (server.address() as AddressInfo).port;
  });
  afterAll(() => new Promise<void>((r) => server.close(() => r())));

  const plan = (path: string, internal: boolean, host = "127.0.0.1"): RequestPlan => ({
    method: "GET",
    url: `http://${host}:${port}${path}`,
    headers: {},
    credential: { ref: "k", placement: "bearer" },
    internal,
  });

  it("injects the credential and reaches an internal target", async () => {
    const res = await dispatchToolCall(plan("/echo", true), { credential: bytes("secret-token") });
    expect(res.status).toBe(200);
    expect(JSON.parse(res.body).auth).toBe("Bearer secret-token");
  });

  it("refuses a non-public address unless the tool is internal (direct IP)", async () => {
    await expect(
      dispatchToolCall(plan("/echo", false), { credential: bytes("x") }),
    ).rejects.toThrow(/non-public/);
  });

  it("refuses a hostname that resolves to loopback (SSRF via DNS)", async () => {
    await expect(
      dispatchToolCall(plan("/echo", false, "localhost"), { credential: bytes("x") }),
    ).rejects.toThrow(/non-public/);
  });

  it("does not follow redirects (a 3xx never re-sends the credential)", async () => {
    secretHit = false;
    const res = await dispatchToolCall(plan("/redirect", true), { credential: bytes("x") });
    expect(res.status).toBe(302);
    expect(res.body).not.toContain("SECRET");
    expect(secretHit).toBe(false);
  });
});
