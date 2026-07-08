/**
 * Keystore: how the CLI persists an identity's keys on disk. A keystore is a JSON file with
 * the DID, its public key (multibase), and the Ed25519 private key (base64url). Private keys
 * live only in these files (git-ignored via `keys/` / `*.key.json`); they are never printed,
 * logged, or embedded in credentials or audit events.
 */

import { readFile, writeFile } from "node:fs/promises";
import { createDidKey, type AgentKeyPair, type CredentialSigner, type Did } from "@roguezero/core";

export interface Keystore {
  did: Did;
  publicKeyMultibase: string;
  /** Ed25519 private key seed, base64url. */
  privateKey: string;
}

export function keystoreFromKeyPair(keyPair: AgentKeyPair): Keystore {
  return {
    did: keyPair.did,
    publicKeyMultibase: keyPair.publicKeyMultibase,
    privateKey: Buffer.from(keyPair.privateKey).toString("base64url"),
  };
}

/** Generate a new did:key identity and its keystore. */
export function createKeystore(): Keystore {
  return keystoreFromKeyPair(createDidKey());
}

export async function saveKeystore(path: string, keystore: Keystore): Promise<void> {
  await writeFile(path, `${JSON.stringify(keystore, null, 2)}\n`, {
    encoding: "utf8",
    mode: 0o600,
  });
}

export async function loadKeystore(path: string): Promise<Keystore> {
  return JSON.parse(await readFile(path, "utf8")) as Keystore;
}

/** Load a keystore as a credential signer (DID + raw private key). */
export async function loadSigner(path: string): Promise<CredentialSigner> {
  const keystore = await loadKeystore(path);
  return {
    did: keystore.did,
    privateKey: new Uint8Array(Buffer.from(keystore.privateKey, "base64url")),
  };
}
