// MintSentry — a verifiable free-mint checker for zkVerify Agent Games
// Season 01, Wildcard track (handle: aspjawir).
//
// Answers: "Is this mint really free, really the official contract, and
// really still open?" It NEVER signs or sends anything; it only judges.
//
//   GET  /          -> interactive dashboard (paste a mint URL or contract)
//   POST /verify    -> { url?, contract?, function?, selector?, wallet? }
//                      -> { verdict, reasonCode, checks, gas..., zk_proof }
//   POST /agent     -> same as /verify, but the request must carry a valid
//                      x-agent-games-signature (when a secret is set) and
//                      the response is signed, following the platform's
//                      transport convention (same as the Gatekeeper agent).
//   GET  /health    -> { ok, agent, hmacConfigured, selfTest }
//   POST (any path) with body.type === "agent-games.preflight.v1"
//                      -> { ok: true, protocolVersion: "v1" }
//
// The Groth16 proof attests that the verdict follows the checks given the
// inputs. It does NOT prove the external source itself is truthful —
// "A proof can verify perfectly and still authorize the wrong action."
// See README.md for the full honesty note and the circuit mapping.
//
// Environment:
//   PORT (8080)  HOST (0.0.0.0)
//   AGENT_GAMES_HMAC_SECRET    (no default — required in production)
//   AGENT_GAMES_HMAC_FORMAT    "hex" (default) or "sha256="
//
// Circuit artifacts (gatekeeper.wasm, gatekeeper_final.zkey) are downloaded
// at boot if missing; a failed download exits non-zero. They are never
// committed to git.

const http = require("node:http");
const path = require("node:path");

const hmac = require("./lib/hmac");
const { REGISTERED_VK_HASH } = require("./lib/field");
const { verify } = require("./mintsentry/check");
const {
  generateProof,
  loadVerificationKey,
  verifyProof,
} = require("./mintsentry/prove");
const rpcLib = require("./lib/rpc");
const { fetchCircuits, CIRCUITS_DIR } = require("./scripts/fetch-circuits");

const PORT = Number(process.env.PORT || 8080);
const HOST = process.env.HOST || "0.0.0.0";
const HMAC_SECRET = process.env.AGENT_GAMES_HMAC_SECRET || "";
const HMAC_FORMAT = process.env.AGENT_GAMES_HMAC_FORMAT || "hex";

const WASM_PATH = path.join(CIRCUITS_DIR, "gatekeeper.wasm");
const ZKEY_PATH = path.join(CIRCUITS_DIR, "gatekeeper_final.zkey");

const MAX_BODY_BYTES = 1024 * 1024;
const PREFLIGHT_TYPE = "agent-games.preflight.v1";
const VK_HASH = REGISTERED_VK_HASH;

let selfTestState = "pending";
let verificationKey = null;

function log(...args) {
  console.log(new Date().toISOString(), ...args);
}

function sendJson(res, statusCode, obj) {
  const body = Buffer.from(JSON.stringify(obj), "utf8");
  const headers = { "content-type": "application/json" };
  if (HMAC_SECRET) {
    headers[hmac.SIGNATURE_HEADER] = hmac.sign(HMAC_SECRET, body, HMAC_FORMAT);
  }
  res.writeHead(statusCode, headers);
  res.end(body);
}

function sendHtml(res, html) {
  const body = Buffer.from(html, "utf8");
  res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
  res.end(body);
}

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    let tooLarge = false;
    req.on("data", (chunk) => {
      total += chunk.length;
      if (total > MAX_BODY_BYTES) {
        tooLarge = true;
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      if (tooLarge) reject(new Error("body too large"));
      else resolve(Buffer.concat(chunks));
    });
    req.on("error", reject);
  });
}

// Run one verification and attach a locally-verified Groth16 proof.
// Never throws: a proof failure is reported in the response, not a crash.
async function handleVerify(input) {
  const result = await verify(input, rpcLib);
  const decision = result.verdict === "FREE" ? "FREE" : "REJECT";
  let zkProof = null;
  try {
    const { proof, publicSignals } = await generateProof(
      result.circuitFields,
      decision,
      { wasmPath: WASM_PATH, zkeyPath: ZKEY_PATH, taskIdMode: "keccak" }
    );
    const verifiedLocally = verificationKey
      ? await verifyProof(publicSignals, proof, verificationKey)
      : false;
    zkProof = {
      protocol: "groth16",
      curve: "bn128",
      zkverify_vk_hash: VK_HASH,
      verified_locally: verifiedLocally,
      public_signals: publicSignals,
      proof,
    };
  } catch (err) {
    log(`[verify] proof FAILED for ${result.contract || result.project}: ${err.message}`);
    zkProof = { protocol: "groth16", curve: "bn128", zkverify_vk_hash: VK_HASH, verified_locally: false, error: "proof generation failed" };
  }
  const { circuitFields, ...rest } = result;
  return { ...rest, zk_proof: zkProof };
}

// Startup self-test: verify a known-good mint end to end, prove the
// verdict, verify the proof locally, and confirm the circuit refuses a
// wrong decision. Sets selfTestState to "PASS" or "FAIL (<reason>)".
async function runSelfTest() {
  try {
    verificationKey = await loadVerificationKey(ZKEY_PATH);
    const result = await verify(
      { contract: "0xb8164afefc53910d7a74cece15a60a9e0c86089e" },
      rpcLib
    );
    // Meow Cards is a known-good free mint: it must come back FREE (pool
    // open) or BLOCKED (pool sold out since the snapshot) — never RISKY
    // or PAID, which would mean the checker itself is broken.
    if (result.verdict !== "FREE" && result.verdict !== "BLOCKED") {
      throw new Error(`self-test verdict was ${result.verdict} (${result.reasonCode}), expected FREE or BLOCKED`);
    }
    const decision = result.verdict === "FREE" ? "FREE" : "REJECT";
    const { proof, publicSignals } = await generateProof(result.circuitFields, decision, {
      wasmPath: WASM_PATH,
      zkeyPath: ZKEY_PATH,
      taskIdMode: "keccak",
    });
    if (!(await verifyProof(publicSignals, proof, verificationKey))) {
      throw new Error("self-test proof did not verify locally");
    }
    // Fail-closed: the same fields proven with the opposite decision must
    // be refused by the circuit.
    let refused = false;
    try {
      await generateProof(result.circuitFields, decision === "FREE" ? "REJECT" : "FREE", {
        wasmPath: WASM_PATH,
        zkeyPath: ZKEY_PATH,
        taskIdMode: "keccak",
      });
    } catch {
      refused = true;
    }
    if (!refused) throw new Error("circuit accepted a wrong decision (not fail-closed)");
    selfTestState = "PASS";
    log(`[self-test] PASS (verdict ${result.verdict})`);
  } catch (err) {
    selfTestState = `FAIL (${err.message})`;
    log(`[self-test] ${selfTestState}`);
  }
}

const DASHBOARD = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>MintSentry — is this mint really free?</title>
<style>
body{font-family:system-ui,-apple-system,sans-serif;max-width:760px;margin:0 auto;padding:24px;color:#1a1a1a;background:#fafafa}
h1{font-size:28px;margin:0 0 4px}.sub{color:#555;margin:0 0 20px}
.card{background:#fff;border:1px solid #ddd;border-radius:10px;padding:16px;margin:14px 0}
label{display:block;font-size:13px;color:#555;margin:10px 0 4px}
input[type=text]{width:100%;padding:10px;border:1px solid #ccc;border-radius:6px;font-size:15px;box-sizing:border-box}
button{padding:10px 16px;border:0;border-radius:6px;background:#111;color:#fff;font-size:15px;cursor:pointer;margin-top:14px}
button.preset{background:#eee;color:#111;margin:4px 4px 0 0;font-size:13px;padding:7px 10px}
.verdict{font-size:26px;font-weight:700;margin:6px 0}
.v-FREE{color:#0a7d2c}.v-PAID{color:#b26a00}.v-BLOCKED{color:#555}.v-RISKY{color:#c00}
.check{padding:6px 0;border-top:1px solid #eee;font-size:14px}
.check .ok{color:#0a7d2c;font-weight:700}.check .bad{color:#c00;font-weight:700}.check .unk{color:#b26a00;font-weight:700}
.check small{color:#777}
.mono{font-family:ui-monospace,Menlo,monospace;font-size:12px;word-break:break-all;background:#f4f4f4;padding:10px;border-radius:6px;white-space:pre-wrap}
.note{font-size:13px;color:#555;background:#fff8e1;border:1px solid #ffe08a;border-radius:8px;padding:12px}
.err{color:#c00}
</style></head><body>
<h1>MintSentry</h1>
<p class="sub">Is this mint really free, really the official contract, and really still open? Paste a mint link or a contract address. It only judges — it never signs or sends anything.</p>
<div class="card">
<label for="q">Mint URL or contract address (BSC)</label>
<input type="text" id="q" placeholder="https://meow-cards.pages.dev  or  0xb8164afe…">
<label for="w">Your wallet (optional — checks whether your free quota is used)</label>
<input type="text" id="w" placeholder="0x…">
<div>
<button class="preset" data-q="0xb8164afefc53910d7a74cece15a60a9e0c86089e">Known-good free mint (Meow Cards)</button>
<button class="preset" data-q="0x9CA1A3eeA74829aA5011c56386b226DB472D0F4f">Paid mint (BAGENT, 10 USDT/share)</button>
<button class="preset" data-q="0x5c221475239decFb241Cb3337257E76fdfAE8945">Sold-out mint (BAO)</button>
<button class="preset" data-q="https://ufo-bsc.netlify.app/">Permit-gated trap (UFO)</button>
</div>
<button id="go">Verify</button>
</div>
<div id="out"></div>
<div class="card note"><b>What the proof does — and does not — prove.</b> The Groth16 proof attests that the verdict follows the checks, given the inputs. It does <b>not</b> prove the external source itself is truthful. A proof can verify perfectly and still authorize the wrong action — that is why the per-check list above is the real evidence, and the proof is only a seal on it.</div>
<script>
var out = document.getElementById('out');
function esc(s){ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function render(r){
  if (r.error) { out.innerHTML = '<div class="card err">Error: ' + esc(r.error) + '</div>'; return; }
  var h = '<div class="card"><div>Verdict</div><div class="verdict v-' + r.verdict + '">' + r.verdict + '</div>';
  h += '<div>' + esc(r.reasonCode || '') + (r.project ? ' &middot; ' + esc(r.project) : '') + '</div>';
  if (r.contract) h += '<div style="margin-top:6px">Contract: <span class="mono">' + esc(r.contract) + '</span></div>';
  if (r.function) h += '<div>Function: <span class="mono">' + esc(r.function) + ' &nbsp; selector ' + esc(r.selector || '') + '</span></div>';
  if (r.cost && r.cost.human) h += '<div>Cost: ' + esc(r.cost.human) + '</div>';
  if (r.gasEstimateWei) h += '<div>Estimated gas cost: ' + esc(r.gasEstimateWei) + ' wei' + (r.gasUnits ? ' (' + esc(r.gasUnits) + ' gas)' : '') + '</div>';
  else if (r.gasPriceWei) h += '<div>Live gas price: ' + esc(r.gasPriceWei) + ' wei (mint estimate unavailable)</div>';
  h += '<h3>Checks</h3>';
  (r.checks || []).forEach(function(c){
    var cls = c.pass === true ? 'ok' : (c.pass === false ? 'bad' : 'unk');
    var mark = c.pass === true ? 'PASS' : (c.pass === false ? 'FAIL' : 'UNVERIFIED');
    h += '<div class="check"><span class="' + cls + '">' + mark + '</span> <b>' + esc(c.code) + '</b> — ' + esc(c.detail) + ' <small>(' + esc(c.source) + ')</small></div>';
  });
  if (r.zk_proof) {
    h += '<h3>Zero-knowledge proof</h3>';
    h += '<div>Groth16 / bn128 &middot; vk ' + esc((r.zk_proof.zkverify_vk_hash || '').slice(0, 18)) + '&hellip; &middot; verified locally by the server: <b>' + (r.zk_proof.verified_locally ? 'YES' : 'NO') + '</b></div>';
    if (r.zk_proof.public_signals) h += '<div class="mono">' + esc(JSON.stringify(r.zk_proof.public_signals)) + '</div>';
    if (r.zk_proof.proof) h += '<details><summary>proof</summary><div class="mono">' + esc(JSON.stringify(r.zk_proof.proof)) + '</div></details>';
    if (r.zk_proof.error) h += '<div class="err">' + esc(r.zk_proof.error) + '</div>';
  }
  h += '</div>';
  out.innerHTML = h;
}
document.getElementById('go').addEventListener('click', function(){
  var q = document.getElementById('q').value.trim();
  var w = document.getElementById('w').value.trim();
  if (!q) { out.innerHTML = '<div class="card err">Paste a mint URL or a contract address first.</div>'; return; }
  out.innerHTML = '<div class="card">Verifying&hellip; (live RPC + proof, usually a few seconds)</div>';
  var body = { wallet: w || undefined };
  if (/^0x[0-9a-fA-F]{40}$/.test(q)) body.contract = q; else body.url = q;
  fetch('/verify', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })
    .then(function(r){ return r.json(); })
    .then(render)
    .catch(function(e){ out.innerHTML = '<div class="card err">Request failed: ' + esc(e.message) + '</div>'; });
});
document.querySelectorAll('button.preset').forEach(function(b){
  b.addEventListener('click', function(){
    document.getElementById('q').value = b.getAttribute('data-q');
    document.getElementById('go').click();
  });
});
</script></body></html>`;

async function main() {
  try {
    await fetchCircuits();
  } catch (err) {
    console.error(`[boot] circuit download failed: ${err.message}`);
    process.exit(1);
  }

  if (!HMAC_SECRET) {
    log("[boot] WARNING: AGENT_GAMES_HMAC_SECRET is not set — responses will be unsigned and inbound HMAC checks are skipped");
  }

  const server = http.createServer((req, res) => {
    (async () => {
      const url = new URL(req.url, "http://localhost");
      const pathname = url.pathname;

      if (req.method === "GET" && pathname === "/health") {
        sendJson(res, 200, {
          ok: true,
          agent: "mintsentry",
          hmacConfigured: Boolean(HMAC_SECRET),
          selfTest: selfTestState,
        });
        return;
      }

      if (req.method === "GET" && (pathname === "/" || pathname === "/index.html")) {
        sendHtml(res, DASHBOARD);
        return;
      }

      if (req.method === "POST") {
        let rawBody;
        try {
          rawBody = await readRawBody(req);
        } catch (err) {
          sendJson(res, 400, { ok: false, error: err.message || "invalid body" });
          return;
        }

        // HMAC over the RAW bytes, before any JSON parsing (when a secret
        // is set). /verify is public; /agent requires the signature.
        const isAgent = pathname === "/agent";
        if (HMAC_SECRET && isAgent && !hmac.verify(HMAC_SECRET, rawBody, req.headers[hmac.SIGNATURE_HEADER])) {
          sendJson(res, 401, { ok: false, error: "bad signature" });
          return;
        }

        let body;
        try {
          body = JSON.parse(rawBody.toString("utf8"));
        } catch {
          sendJson(res, 400, { ok: false, error: "invalid json" });
          return;
        }

        if (body && body.type === PREFLIGHT_TYPE) {
          sendJson(res, 200, { ok: true, protocolVersion: "v1" });
          return;
        }

        if (pathname === "/verify" || pathname === "/agent") {
          if (!body.contract && !body.url) {
            sendJson(res, 400, { ok: false, error: "give a contract address or a mint URL" });
            return;
          }
          try {
            const out = await handleVerify(body);
            sendJson(res, 200, out);
          } catch (err) {
            log(`[${pathname}] handler error:`, err.message);
            sendJson(res, 500, { ok: false, error: "handler error" });
          }
          return;
        }

        sendJson(res, 404, { ok: false, error: "not found" });
        return;
      }

      sendJson(res, 404, { ok: false, error: "not found" });
    })().catch((err) => {
      log("[server] unexpected error:", err);
      try {
        sendJson(res, 500, { ok: false, error: "handler error" });
      } catch {
        // Response already gone; nothing left to do.
      }
    });
  });

  server.listen(PORT, HOST, () => {
    log(`[boot] mintsentry listening on http://${HOST}:${PORT}`);
    log(`[boot] hmacConfigured=${Boolean(HMAC_SECRET)}`);
    runSelfTest();
  });
}

main();
