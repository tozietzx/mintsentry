// Tests for MintSentry. Run with: npm test
//
// Uses a stubbed RPC (no network) so the verdict paths are deterministic:
//   FREE    — Meow Cards, pool open, quota unused
//   PAID    — BAGENT, 10 USDT/share
//   BLOCKED — BAO, free pool sold out (snapshot) / UFO, permit-gated
//   RISKY   — an unknown contract, and a supplied truncated selector
// Plus: a real Groth16 proof for every verdict, each verified locally
// with snarkjs, and the fail-closed property (the circuit refuses a
// wrong decision). The live-RPC path is exercised separately by the
// server's self-test and by a manual /verify call.
//
// Note: snarkjs leaves the Node event loop alive after use, so this file
// calls process.exit() explicitly at the end.

const assert = require("node:assert/strict");
const path = require("node:path");

const { verify, selectorOf } = require("./mintsentry/check");
const {
  generateProof,
  loadVerificationKey,
  verifyProof,
} = require("./mintsentry/prove");
const { REGISTERED_VK_HASH } = require("./lib/field");
const hmac = require("./lib/hmac");

const WASM_PATH = path.join(__dirname, "circuits", "gatekeeper.wasm");
const ZKEY_PATH = path.join(__dirname, "circuits", "gatekeeper_final.zkey");

const MEOW = "0xb8164afefc53910d7a74cece15a60a9e0c86089e";
const BAO = "0x5c221475239decFb241Cb3337257E76fdfAE8945";
const BAGENT = "0x9CA1A3eeA74829aA5011c56386b226DB472D0F4f";
const WALLET = "0x3e8bf222ee06e8820af628940ead047b492aa685";

let passed = 0;
function check(name, fn) {
  fn();
  passed += 1;
  console.log(`  ok - ${name}`);
}
async function checkAsync(name, fn) {
  await fn();
  passed += 1;
  console.log(`  ok - ${name}`);
}

// Stub RPC: answers the views Meow Cards and BAO actually expose, and
// reverts everything else (exactly like the live chain does).
function stubRpc() {
  const uint = (n) => "0x" + BigInt(n).toString(16).padStart(64, "0");
  return {
    async ethCall(to, data) {
      const t = to.toLowerCase();
      const sel = data.slice(0, 10).toLowerCase();
      if (t === MEOW.toLowerCase()) {
        if (sel === selectorOf("totalSupply()")) return uint(1564);
        if (sel === selectorOf("totalMinted()")) return uint(1564);
        if (sel === selectorOf("mintedByWallet(address)")) return uint(0);
        if (sel === selectorOf("balanceOf(address)")) return uint(0);
        return null; // revert: view does not exist (freeRemaining, freeUsed, ...)
      }
      if (t === BAO.toLowerCase()) {
        return null; // BAO exposes none of the probed views
      }
      return null;
    },
    async blockNumber() {
      return 133610458n;
    },
    async gasPrice() {
      return 50000000n;
    },
    async estimateGas(to, data) {
      if (to.toLowerCase() === MEOW.toLowerCase()) return 150000n;
      return null; // would revert
    },
  };
}

async function proveAndVerify(result) {
  const vk = await loadVerificationKey(ZKEY_PATH);
  const decision = result.verdict === "FREE" ? "FREE" : "REJECT";
  const { proof, publicSignals } = await generateProof(result.circuitFields, decision, {
    wasmPath: WASM_PATH,
    zkeyPath: ZKEY_PATH,
    taskIdMode: "keccak",
  });
  assert.equal(publicSignals.length, 13);
  assert.equal(await verifyProof(publicSignals, proof, vk), true);
  return { proof, publicSignals };
}

async function main() {
  const rpc = stubRpc();

  console.log("== selectors: computed, never copied ==");
  check("mint(uint256,uint256) is 0x1b2ef1ca (the BAO selector)", () => {
    assert.equal(selectorOf("mint(uint256,uint256)"), "0x1b2ef1ca");
  });
  check("mint(uint256,uint256) is 0x1b2ef1ca (the BAO selector — and Meow's)", () => {
    assert.equal(selectorOf("mint(uint256,uint256)"), "0x1b2ef1ca");
  });
  check("the bundled registry corrects meow's fn to mint(uint256,uint256): agentTokenId is a uint256, not bytes32 (the official skill.md states selector 0x1b2ef1ca)", () => {
    const known = require("./mintsentry/known");
    const meow = known.findByContract(MEOW);
    assert.equal(meow.entry.fn, "mint(uint256,uint256)");
    assert.equal(meow.entry.selector, "0x1b2ef1ca");
    assert.equal(meow.entry.recordedSelector, "0x1b2ef1ca");
    // Computing from the WRONG type gives a wrong selector — that is why
    // the checker also cross-checks against the official stated selector.
    assert.equal(selectorOf("mint(uint256,bytes32)"), "0x1801fbe5");
  });
  check("mint() is 0x1249c58b, mintFree() is 0x8ab53447, openFree() is 0x1644fa8e", () => {
    assert.equal(selectorOf("mint()"), "0x1249c58b");
    assert.equal(selectorOf("mintFree()"), "0x8ab53447");
    assert.equal(selectorOf("openFree()"), "0x1644fa8e");
  });

  console.log("== verdict: FREE ==");
  const freeRes = await verify({ contract: MEOW, wallet: WALLET }, rpc);
  check("Meow Cards verifies FREE", () => {
    assert.equal(freeRes.verdict, "FREE");
    assert.equal(freeRes.reasonCode, "FREE");
    assert.equal(freeRes.project, "meow-cards");
    assert.equal(freeRes.selector, "0x1b2ef1ca");
  });
  check("FREE result lists all seven checks, all passing", () => {
    assert.equal(freeRes.checks.length, 7);
    for (const c of freeRes.checks) assert.equal(c.pass, true, c.code);
    assert.equal(freeRes.gasEstimateWei, (150000n * 50000000n).toString());
  });
  check("FREE result carries a live pool reading (1564/10000)", () => {
    assert.equal(freeRes.liveRemaining, (10000 - 1564).toString());
  });
  await checkAsync("FREE proof generates and verifies locally", async () => {
    const { publicSignals } = await proveAndVerify(freeRes);
    // public signals: [binding, registeredVk, proofVk, minimum,
    // publicBalance, expiry, current, recipient, conditionRecipient,
    // amount, maxTransfer, decision, taskId]
    assert.equal(publicSignals[1], BigInt(MEOW).toString());
    assert.equal(publicSignals[2], BigInt(MEOW).toString());
    assert.equal(publicSignals[3], "1");
    assert.equal(publicSignals[4], (10000 - 1564).toString());
    assert.equal(publicSignals[9], "0");
    assert.equal(publicSignals[10], "0");
    assert.equal(publicSignals[11], "1");
  });

  console.log("== verdict: PAID ==");
  const paidRes = await verify({ contract: BAGENT }, rpc);
  check("BAGENT verifies PAID", () => {
    assert.equal(paidRes.verdict, "PAID");
    assert.equal(paidRes.reasonCode, "COST");
    assert.equal(paidRes.project, "bagent");
    assert.equal(paidRes.cost.human, "10 USDT/share");
  });
  check("PAID still lists the failing value_free check (and the approval consequence)", () => {
    const byCode = {};
    for (const c of paidRes.checks) byCode[c.code] = c;
    assert.equal(byCode.value_free.pass, false);
    assert.equal(byCode.no_hidden_approval.pass, false);
    assert.equal(byCode.source_match.pass, true);
  });
  await checkAsync("PAID proof generates and verifies locally (decision 0)", async () => {
    const { publicSignals } = await proveAndVerify(paidRes);
    assert.equal(publicSignals[9], "10000000"); // 10 USDT, smallest unit
    assert.equal(publicSignals[10], "0");
    assert.equal(publicSignals[11], "0");
  });

  console.log("== verdict: BLOCKED ==");
  const blockedRes = await verify({ contract: BAO }, rpc);
  check("BAO verifies BLOCKED (sold out, snapshot)", () => {
    assert.equal(blockedRes.verdict, "BLOCKED");
    assert.equal(blockedRes.reasonCode, "SOLD_OUT");
    assert.equal(blockedRes.project, "bao");
  });
  check("BAO pool check is snapshot-sourced (no live supply view answers)", () => {
    const pool = blockedRes.checks.find((c) => c.code === "pool_open");
    assert.equal(pool.pass, false);
    assert.equal(pool.source, "snapshot");
  });
  await checkAsync("BLOCKED proof generates and verifies locally", async () => {
    const { publicSignals } = await proveAndVerify(blockedRes);
    assert.equal(publicSignals[4], "0"); // remaining 0
    assert.equal(publicSignals[11], "0");
  });

  const ufoRes = await verify({ url: "https://ufo-bsc.netlify.app/" }, rpc);
  check("UFO (URL lookup) verifies BLOCKED (permit-gated)", () => {
    assert.equal(ufoRes.verdict, "BLOCKED");
    assert.equal(ufoRes.reasonCode, "PERMIT_GATE");
    assert.equal(ufoRes.project, "ufo");
  });
  await checkAsync("UFO BLOCKED proof generates and verifies locally", async () => {
    await proveAndVerify(ufoRes);
  });

  console.log("== verdict: RISKY ==");
  const unknownRes = await verify({ contract: "0x1111111111111111111111111111111111111111" }, rpc);
  check("an unknown contract verifies RISKY", () => {
    assert.equal(unknownRes.verdict, "RISKY");
    assert.equal(unknownRes.reasonCode, "CONTRACT_UNKNOWN");
  });
  await checkAsync("RISKY (unknown contract) proof generates and verifies locally", async () => {
    const { publicSignals } = await proveAndVerify(unknownRes);
    assert.equal(publicSignals[1], "0"); // no registered contract
    assert.notEqual(publicSignals[1], publicSignals[2]);
    assert.equal(publicSignals[11], "0");
  });

  const trapRes = await verify({ contract: MEOW, selector: "0xb2ef1ca0" }, rpc);
  check("a supplied truncated selector (the BAO trap) verifies RISKY", () => {
    assert.equal(trapRes.verdict, "RISKY");
    assert.equal(trapRes.reasonCode, "SELECTOR_MISMATCH");
    const sel = trapRes.checks.find((c) => c.code === "selector_verified");
    assert.equal(sel.pass, false);
  });
  await checkAsync("RISKY (selector trap) proof generates and verifies locally", async () => {
    await proveAndVerify(trapRes);
  });

  console.log("== proofs: fail-closed ==");
  await checkAsync("the circuit refuses a FREE verdict proven as REJECT", async () => {
    await assert.rejects(
      generateProof(freeRes.circuitFields, "REJECT", {
        wasmPath: WASM_PATH,
        zkeyPath: ZKEY_PATH,
        taskIdMode: "keccak",
      })
    );
  });
  await checkAsync("the circuit refuses a PAID verdict proven as FREE", async () => {
    await assert.rejects(
      generateProof(paidRes.circuitFields, "FREE", {
        wasmPath: WASM_PATH,
        zkeyPath: ZKEY_PATH,
        taskIdMode: "keccak",
      })
    );
  });

  console.log("== hmac: sign and verify ==");
  check("sign/verify round-trips (hex format)", () => {
    const secret = "test-secret";
    const body = Buffer.from('{"a":1}', "utf8");
    const sig = hmac.sign(secret, body, "hex");
    assert.equal(hmac.verify(secret, body, sig), true);
    assert.equal(hmac.verify(secret, body, sig + "0"), false);
  });
  check("sign/verify round-trips (sha256= format)", () => {
    const secret = "test-secret";
    const body = Buffer.from("hello", "utf8");
    const sig = hmac.sign(secret, body, "sha256=");
    assert.ok(sig.startsWith("sha256="));
    assert.equal(hmac.verify(secret, body, sig), true);
  });

  console.log("== misc ==");
  check("verify() throws when neither contract nor URL is given", async () => {
    await assert.rejects(verify({}, rpc), /give a contract address or a mint URL/);
  });
  check("the bundled registry has the four preset projects", () => {
    const known = require("./mintsentry/known");
    assert.ok(known.findByContract(MEOW));
    assert.ok(known.findByContract(BAGENT));
    assert.ok(known.findByContract(BAO));
    assert.ok(known.findByUrl("https://ufo-bsc.netlify.app/"));
  });
  check("VK hash is the official Gatekeeper one", () => {
    assert.equal(REGISTERED_VK_HASH, "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0");
  });

  console.log(`\nALL TESTS PASSED (${passed} checks)`);
  process.exit(0);
}

main().catch((err) => {
  console.error("\nTEST FAILURE:", err);
  process.exit(1);
});
