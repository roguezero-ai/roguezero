/**
 * Generic HTTP injection proxy (ADR 0005 D1 dispatch layer). Takes a `RequestPlan` (already
 * SSRF-contained by the registry) plus the decrypted credential bytes, and performs the network
 * call under the controls the registry couldn't (they need DNS/sockets):
 *
 *   - **resolve once, validate the IP, connect to that exact IP** — so a hostname that resolves to a
 *     private/metadata address is refused (T-INJ-4), and there is no second resolution for a rebind
 *     to slip through (T-INJ-2). SNI + Host are preserved to the original hostname.
 *   - **never follow redirects** — a 3xx is returned as-is, so a `302 → 169.254.169.254` can't
 *     re-send the credential to an attacker's target (T-INJ-3).
 *   - **caps** on response size and time (T-INJ-13).
 *
 * The credential is injected here and nowhere else; it is never logged. It does become a JS string
 * at the Node HTTP layer (headers are strings) — an unavoidable, short-lived copy; the caller zeroes
 * the source bytes after dispatch (ADR 0005 D3). Decrypt-then-dispatch is the *last* step of the
 * request path, after auth + policy + revocation (D0) — that ordering lives in the spine, not here.
 */

import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { lookup as dnsLookup } from "node:dns/promises";
import { isIP } from "node:net";
import type { CredentialInjection, RequestPlan } from "./registry.js";

const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_MAX_BYTES = 10 * 1024 * 1024;

function isBlockedV4(ip: string): boolean {
  const o = ip.split(".").map((x) => Number(x));
  if (o.length !== 4 || o.some((x) => !Number.isInteger(x) || x < 0 || x > 255)) return true;
  const [a, b] = o as [number, number, number, number];
  if (a === 0 || a === 10 || a === 127) return true; // unspecified, private, loopback
  if (a === 169 && b === 254) return true; // link-local + cloud metadata (169.254.169.254)
  if (a === 172 && b >= 16 && b <= 31) return true; // private
  if (a === 192 && b === 168) return true; // private
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
  if (a === 198 && (b === 18 || b === 19)) return true; // benchmarking
  if (a === 255) return true; // broadcast
  return false;
}

/** True if `ip` is loopback/private/link-local/metadata/ULA — anything we won't dial unless internal. */
export function isBlockedAddress(ip: string): boolean {
  const fam = isIP(ip);
  if (fam === 4) return isBlockedV4(ip);
  if (fam === 6) {
    const low = ip.toLowerCase();
    if (low === "::1" || low === "::") return true; // loopback, unspecified
    if (low.startsWith("fe80") || low.startsWith("fc") || low.startsWith("fd")) return true; // link-local, ULA
    const mapped = low.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/); // IPv4-mapped
    if (mapped?.[1]) return isBlockedV4(mapped[1]);
    return false;
  }
  return true; // not a valid IP literal → refuse (fail closed)
}

/** Inject the credential into request headers per its placement. Never a query param (T-INJ-11). */
export function injectCredential(
  headers: Record<string, string>,
  injection: CredentialInjection,
  credential: Uint8Array,
): void {
  // Unavoidably a string at Node's HTTP layer; kept short-lived and never logged. The caller zeroes
  // the source `credential` bytes after the request.
  const value = new TextDecoder().decode(credential);
  if (injection.placement === "bearer") {
    headers.authorization = `Bearer ${value}`;
  } else if (injection.placement === "basic") {
    headers.authorization = `Basic ${Buffer.from(value, "utf8").toString("base64")}`;
  } else if (injection.placement === "header" && injection.header) {
    headers[injection.header] = value;
  }
}

export interface DispatchOptions {
  /** The decrypted credential to inject. Omit to send unauthenticated (rare). */
  credential?: Uint8Array;
  timeoutMs?: number;
  maxBytes?: number;
}

export interface DispatchResult {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: string;
}

/**
 * Execute a validated `RequestPlan`, injecting the credential and enforcing the dispatch-layer SSRF
 * controls. Throws (fail closed) on a blocked address, timeout, oversize body, or transport error.
 */
export async function dispatchToolCall(
  plan: RequestPlan,
  opts: DispatchOptions = {},
): Promise<DispatchResult> {
  const url = new URL(plan.url);
  const isHttps = url.protocol === "https:";

  // Resolve once; refuse a non-public address unless the tool is explicitly internal.
  const { address, family } = await dnsLookup(url.hostname);
  if (!plan.internal && isBlockedAddress(address)) {
    throw new Error(
      `refusing to connect: ${url.hostname} resolves to non-public address ${address}`,
    );
  }

  const headers: Record<string, string> = { ...plan.headers, host: url.host };
  if (opts.credential) injectCredential(headers, plan.credential, opts.credential);

  const options = {
    host: address, // connect to the validated IP — pins it, no rebind window
    port: url.port ? Number(url.port) : isHttps ? 443 : 80,
    method: plan.method,
    path: `${url.pathname}${url.search}`,
    headers,
    family,
    servername: isHttps ? url.hostname : undefined, // SNI + cert validated against the real host
  };

  return await new Promise<DispatchResult>((resolve, reject) => {
    const maxBytes = opts.maxBytes ?? DEFAULT_MAX_BYTES;
    // Raw request — does NOT follow redirects (a 3xx comes back as-is, T-INJ-3).
    const req = (isHttps ? httpsRequest : httpRequest)(options, (res) => {
      const chunks: Buffer[] = [];
      let size = 0;
      res.on("data", (c: Buffer) => {
        size += c.length;
        if (size > maxBytes) {
          req.destroy(new Error("downstream response exceeded max size"));
          return;
        }
        chunks.push(c);
      });
      res.on("end", () => {
        resolve({
          status: res.statusCode ?? 0,
          headers: res.headers,
          body: Buffer.concat(chunks).toString("utf8"),
        });
      });
    });
    req.setTimeout(opts.timeoutMs ?? DEFAULT_TIMEOUT_MS, () => {
      req.destroy(new Error("downstream request timed out"));
    });
    req.on("error", reject);
    if (plan.body !== undefined) req.write(plan.body);
    req.end();
  });
}
