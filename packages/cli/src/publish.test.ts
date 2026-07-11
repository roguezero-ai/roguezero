import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createResolver,
  createSignedFileRevocationChecker,
  nextSequence,
  revokeCredential,
} from "@roguezero/core";
import { createCommand } from "./commands.js";
import { publishRevocationsCommand } from "./publish.js";

let dir = "";
async function workspace(): Promise<{ list: string; out: string; key: string; did: string }> {
  dir = await mkdtemp(join(tmpdir(), "rz-publish-"));
  const key = join(dir, "controller.key.json");
  const controller = await createCommand({ outPath: key });
  const list = join(dir, "revocations.json");
  await writeFile(list, JSON.stringify({ revoked: [] }), "utf8");
  return { list, out: join(dir, "revocations.jwt"), key, did: controller.did };
}

afterEach(async () => {
  if (dir) await rm(dir, { recursive: true, force: true });
  dir = "";
});

describe("nextSequence", () => {
  it("is floored at the wall clock, so losing the counter cannot roll the list back", () => {
    const now = 1_800_000_000;
    // No stored counter at all — still lands above any seq published before `now`.
    expect(nextSequence(undefined, now)).toBe(now);
    // A stored counter only breaks ties inside the same second.
    expect(nextSequence(now, now)).toBe(now + 1);
    expect(nextSequence(now + 5, now)).toBe(now + 6);
    // An older counter never drags the sequence backwards.
    expect(nextSequence(1, now)).toBe(now);
  });

  it("refuses a planted far-future sequence rather than chasing it", () => {
    const now = 1_800_000_000;
    expect(() => nextSequence(now + 400 * 24 * 3600, now)).toThrow(/year ahead/);
  });
});

describe("revocations publish", () => {
  it("signs the local list so a verifier anywhere denies the revoked credential", async () => {
    const ws = await workspace();
    await revokeCredential(ws.list, "urn:uuid:dead");

    const result = await publishRevocationsCommand({
      listPath: ws.list,
      signWithPath: ws.key,
      outPath: ws.out,
    });
    expect(result.issuer).toBe(ws.did);
    expect(result.published.map((e) => e.id)).toEqual(["urn:uuid:dead"]);

    // A guard that only trusts this publisher now honours the kill switch.
    const checker = createSignedFileRevocationChecker(ws.out, {
      resolver: createResolver(),
      trustedIssuers: [ws.did],
    });
    expect(await checker({ id: "urn:uuid:dead", issuer: ws.did })).toBe(true);
    expect(await checker({ id: "urn:uuid:live", issuer: ws.did })).toBe(false);
  });

  it("bumps the sequence on every publish, and a verifier refuses the older list", async () => {
    const ws = await workspace();
    const first = await publishRevocationsCommand({
      listPath: ws.list,
      signWithPath: ws.key,
      outPath: ws.out,
    });
    const firstJwt = await readFile(ws.out, "utf8");

    await revokeCredential(ws.list, "urn:uuid:dead");
    const second = await publishRevocationsCommand({
      listPath: ws.list,
      signWithPath: ws.key,
      outPath: ws.out,
    });
    expect(second.seq).toBeGreaterThan(first.seq);

    // The verifier sees the new list, then is served the old one — a rollback that would
    // resurrect the revoked credential. It must refuse.
    const checker = createSignedFileRevocationChecker(ws.out, {
      resolver: createResolver(),
      trustedIssuers: [ws.did],
    });
    expect(await checker({ id: "urn:uuid:dead", issuer: ws.did })).toBe(true);

    await writeFile(ws.out, firstJwt, "utf8");
    await expect(checker({ id: "urn:uuid:dead", issuer: ws.did })).rejects.toThrow(
      /older than seq/,
    );
  });

  it("prunes entries whose credential has already expired, bounding list growth", async () => {
    const ws = await workspace();
    const now = Math.floor(Date.now() / 1000);
    await revokeCredential(ws.list, "urn:uuid:gone", { expiresAt: now - 10 });
    await revokeCredential(ws.list, "urn:uuid:live", { expiresAt: now + 3600 });
    await revokeCredential(ws.list, "urn:uuid:forever");

    const result = await publishRevocationsCommand({
      listPath: ws.list,
      signWithPath: ws.key,
      outPath: ws.out,
    });
    expect(result.published.map((e) => e.id).sort()).toEqual(["urn:uuid:forever", "urn:uuid:live"]);
    expect(result.pruned.map((e) => e.id)).toEqual(["urn:uuid:gone"]);

    // Pruning is a publish-time decision; the operator's own list is left intact.
    const raw = JSON.parse(await readFile(ws.list, "utf8")) as { revoked: unknown[] };
    expect(raw.revoked).toHaveLength(3);
  });

  it("records the credential's expiry when revoking from a JWT, so it can be pruned later", async () => {
    const ws = await workspace();
    await revokeCredential(ws.list, "urn:uuid:x", { expiresAt: 1_900_000_000 });
    const raw = JSON.parse(await readFile(ws.list, "utf8")) as {
      revoked: Array<{ id: string; expiresAt: number }>;
    };
    expect(raw.revoked[0]).toEqual({ id: "urn:uuid:x", expiresAt: 1_900_000_000 });
  });
});
