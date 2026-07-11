/**
 * Per-call overhead benchmark for the RogueZero request path.
 *
 * Measures the compute cost RogueZero adds to a single protected tool call, broken into the
 * two hops that make up the challenge round-trip:
 *   - mint  (agent side): obtain a nonce + build a fresh holder-signed presentation
 *   - verify (server side): run the full fail-closed pipeline (VP sig → nonce → 2 VC verifies
 *            → structure → issuer trust → binding → audience → revocation)
 *
 * DID resolution is in-memory here (did:key agent + local did:web issuer), so the numbers are
 * pure crypto/parse compute — they EXCLUDE network round-trip time and any over-the-wire DID
 * resolution. That is the honest thing to publish: "RogueZero adds ~X ms of CPU per call; the
 * challenge hop adds one network round-trip on top, which your transport already dominates."
 *
 * Run: node scripts/bench-overhead.mjs [iterations]
 */

import {
  createDidKey,
  generateEd25519KeyPair,
  didWebFromHost,
  createDidWebDocument,
  createResolver,
  issueAgentProfileCredential,
  issueAgentCapabilityCredential,
  createInMemoryNonceStore,
  createPresentation,
  verifyRequest,
} from "../packages/core/dist/index.js";

const AUDIENCE = "mcp://reports.acme.example";
const ITERATIONS = Number(process.argv[2] ?? 500);
const WARMUP = 50;

// --- fixed setup: credentials are long-lived, so issuance is NOT per-call cost ---
const { publicKey: orgPub, privateKey: orgPriv } = generateEd25519KeyPair();
const orgDid = didWebFromHost("acme.example");
const resolver = createResolver({
  localDidWebDocuments: { [orgDid]: createDidWebDocument(orgDid, orgPub) },
});
const org = { did: orgDid, privateKey: orgPriv };
const agent = createDidKey();
const agentSigner = { did: agent.did, privateKey: agent.privateKey };

const profileVc = await issueAgentProfileCredential(org, {
  id: agent.did,
  controller: orgDid,
  name: "Reporter",
});
const capabilityVc = await issueAgentCapabilityCredential(org, {
  id: agent.did,
  tools: [{ name: "read_report", scopes: ["reports:read"] }],
  audience: AUDIENCE,
});

const nonceStore = createInMemoryNonceStore();

/** One full call: issue nonce + mint presentation (agent) then verify (server). Returns [mintMs, verifyMs]. */
async function oneCall() {
  const t0 = performance.now();
  const challenge = await nonceStore.issue(AUDIENCE);
  const presentation = await createPresentation(
    agentSigner,
    { profileVc, capabilityVc },
    { challenge: challenge.nonce, audience: AUDIENCE },
  );
  const t1 = performance.now();
  await verifyRequest({
    presentation,
    audience: AUDIENCE,
    resolver,
    trustedIssuers: [orgDid],
    nonceStore,
  });
  const t2 = performance.now();
  return [t1 - t0, t2 - t1];
}

function stats(xs) {
  const s = [...xs].sort((a, b) => a - b);
  const at = (p) => s[Math.min(s.length - 1, Math.floor((p / 100) * s.length))];
  const mean = s.reduce((a, b) => a + b, 0) / s.length;
  return { mean, p50: at(50), p95: at(95), p99: at(99), min: s[0], max: s[s.length - 1] };
}

const fmt = (n) => `${n.toFixed(3)} ms`;
function row(label, st) {
  return `${label.padEnd(22)} mean ${fmt(st.mean).padStart(9)}   p50 ${fmt(st.p50).padStart(9)}   p95 ${fmt(st.p95).padStart(9)}   p99 ${fmt(st.p99).padStart(9)}`;
}

for (let i = 0; i < WARMUP; i++) await oneCall();

const mint = [];
const verify = [];
const total = [];
for (let i = 0; i < ITERATIONS; i++) {
  const [m, v] = await oneCall();
  mint.push(m);
  verify.push(v);
  total.push(m + v);
}

console.log(`\nRogueZero per-call overhead — ${ITERATIONS} iterations, Node ${process.version}`);
console.log(`(in-memory DID resolution; compute only, excludes network RTT)\n`);
console.log(row("mint (agent side)", stats(mint)));
console.log(row("verify (server side)", stats(verify)));
console.log(row("TOTAL added compute", stats(total)));
console.log("");
