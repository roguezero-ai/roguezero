import { describe, expect, it } from "vitest";
import { verifyAgentProfileCredential } from "./credentials.js";
import { VerificationError } from "./errors.js";
import { createDidKey } from "./identity.js";
import { createResolver } from "./resolver.js";

const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");

describe("security — algorithm confusion (pre-public hardening, H5)", () => {
  it("rejects an unsigned alg:none token", async () => {
    const agent = createDidKey();
    const now = Math.floor(Date.now() / 1000);
    const header = b64({ alg: "none", typ: "JWT" });
    const payload = b64({
      iss: agent.did,
      sub: agent.did,
      nbf: now,
      exp: now + 600,
      vc: {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        type: ["VerifiableCredential", "AgentProfile"],
        credentialSubject: { id: agent.did, controller: agent.did, name: "Forged" },
      },
    });
    const unsigned = `${header}.${payload}.`; // empty signature
    await expect(verifyAgentProfileCredential(unsigned, createResolver())).rejects.toBeInstanceOf(
      VerificationError,
    );
  });

  it("rejects a token claiming a non-EdDSA algorithm", async () => {
    const agent = createDidKey();
    const header = b64({ alg: "HS256", typ: "JWT" });
    const payload = b64({ iss: agent.did, sub: agent.did });
    const forged = `${header}.${payload}.AAAA`;
    await expect(verifyAgentProfileCredential(forged, createResolver())).rejects.toBeInstanceOf(
      VerificationError,
    );
  });
});
