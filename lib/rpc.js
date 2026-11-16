// Minimal BSC JSON-RPC client over Node's stdlib https. No dependencies.
//
// Public endpoints only, tried in order; the first one that answers wins.
// A call that reverts returns { error } (the caller treats a revert as
// "this view does not exist here", not as a crash). Timeouts are short so
// a dead endpoint cannot stall a verification.

const https = require("node:https");

const RPCS = [
  "https://bsc-dataseed.binance.org/",
  "https://bsc-dataseed1.defibit.io/",
  "https://bsc-dataseed1.ninicoin.io/",
];

const TIMEOUT_MS = 8000;

function post(url, body) {
  return new Promise((resolve, reject) => {
    const data = Buffer.from(JSON.stringify(body), "utf8");
    const req = https.request(
      url,
      {
        method: "POST",
        headers: { "content-type": "application/json", "content-length": data.length },
        timeout: TIMEOUT_MS,
      },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          try {
            resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")));
          } catch (e) {
            reject(new Error(`bad json from ${url}: ${e.message}`));
          }
        });
      }
    );
    req.on("timeout", () => req.destroy(new Error(`timeout ${url}`)));
    req.on("error", reject);
    req.end(data);
  });
}

// One JSON-RPC call, trying each endpoint until one answers with a result
// or a revert (both are answers). Throws only when no endpoint responds.
async function rpc(method, params) {
  let lastErr = null;
  for (const url of RPCS) {
    try {
      const out = await post(url, { jsonrpc: "2.0", id: 1, method, params });
      if (out && out.error) return { error: out.error };
      if (out && out.result !== undefined) return { result: out.result };
      lastErr = new Error(`empty reply from ${url}`);
    } catch (err) {
      lastErr = err;
    }
  }
  throw lastErr || new Error("no RPC endpoint responded");
}

function hexToBigInt(hex) {
  if (typeof hex !== "string" || !/^0x[0-9a-fA-F]+$/.test(hex)) return null;
  try {
    return BigInt(hex);
  } catch {
    return null;
  }
}

// Read-only contract call. Returns the raw hex result, or null when the
// call reverts / the function does not exist on this contract.
async function ethCall(to, data, from) {
  const tx = { to, data };
  if (from) tx.from = from;
  const out = await rpc("eth_call", [tx, "latest"]);
  if (out.error || typeof out.result !== "string") return null;
  return out.result;
}

async function blockNumber() {
  const out = await rpc("eth_blockNumber", []);
  if (out.error) return null;
  return hexToBigInt(out.result);
}

async function gasPrice() {
  const out = await rpc("eth_gasPrice", []);
  if (out.error) return null;
  return hexToBigInt(out.result);
}

// Gas estimate for a mint calldata. Returns a BigInt, or null when the
// call would revert (which itself is evidence the mint would fail).
async function estimateGas(to, data, from) {
  const tx = { to, data };
  if (from) tx.from = from;
  const out = await rpc("eth_estimateGas", [tx, "latest"]);
  if (out.error) return null;
  return hexToBigInt(out.result);
}

module.exports = { RPCS, rpc, ethCall, blockNumber, gasPrice, estimateGas, hexToBigInt };
