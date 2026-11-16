// MintSentry — the deterministic mint checklist.
//
// Given a mint link or contract address, answer: is this mint really free,
// really the official contract, and really still open?
//
// The seven checks (each { code, pass, detail, source }):
//   source_match        contract (+function) matches the official registry
//   selector_verified   the calldata selector is the one computed from the
//                       verified function signature (never a copied hex)
//   value_free          the mint costs nothing (value 0)
//   pool_open           supply remains AND the wallet's free quota is unused
//   no_permit_gate      no server-issued signature / voucher / permit / PoW
//   no_hidden_approval  no token approval is required to mint
//   gas_estimate        a live RPC answered (informational; never decides)
//
// Verdict (first failing check wins, in this order):
//   source_match / selector_verified fail  -> RISKY
//   value_free fails                      -> PAID
//   no_permit_gate fails                  -> BLOCKED (permit-gated; checked
//                                            before pool, so a gated mint is
//                                            named a trap even with supply left)
//   pool_open fails                       -> BLOCKED (sold out / quota / window)
//   no_hidden_approval fails              -> RISKY
//   a safety check is unverifiable        -> RISKY (UNVERIFIED)
//   otherwise                             -> FREE
//
// The verdict is then mapped onto the Gatekeeper circuit's inputs so a
// Groth16 proof can attest it (see toCircuitFields). The mapping is
// documented in README.md; the short version:
//   VK check (proofVk == registeredVk)  -> source_match (contract identity)
//   threshold (balance >= minimum)      -> pool_open (remaining slots >= 1)
//   expiry (current < expiry)           -> no_permit_gate (no gate)
//   recipient (== conditionRecipient)   -> selector_verified
//   amount (<= maxTransfer = 0)         -> value_free AND no_hidden_approval
// decision is 1 exactly when the verdict is FREE. Every non-FREE verdict
// has at least one circuit check failing, so the prover accepts the
// decision and refuses the opposite one (fail-closed, as in Gatekeeper).
//
// Honesty: a check whose evidence is a registry snapshot is labelled
// source "snapshot", never "live". A failed live fetch is "unverified",
// never a pass. The proof attests the verdict follows the checks given
// the inputs; it does NOT prove the external source itself is truthful.

const { keccak256 } = require("js-sha3");

const known = require("./known");
const rpcLib = require("../lib/rpc");

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
// The registry owner's wallet. Only used to interpret wallet-specific
// snapshot statuses (free_minted etc.) — never as a default querier.
const REGISTRY_WALLET = "0x3e8bf222ee06e8820af628940ead047b492aa685";

// ---------------------------------------------------------------------------
// Selectors and calldata
// ---------------------------------------------------------------------------

function selectorOf(fn) {
  if (!fn || typeof fn !== "string") return null;
  if (!/^[a-zA-Z_][a-zA-Z0-9_]*\([^)]*\)$/.test(fn)) return null;
  return "0x" + keccak256(fn).slice(0, 8);
}

// Parse a function signature into its parameter types.
function fnParamTypes(fn) {
  const m = /^([a-zA-Z_][a-zA-Z0-9_]*)\(([^)]*)\)$/.exec(fn || "");
  if (!m) return null;
  const inner = m[2].trim();
  if (inner === "") return [];
  return inner.split(",").map((t) => t.trim());
}

// Resolve one registry arg to a concrete value. Args in the registry are
// sometimes placeholders that embed a concrete hex
// ("<agentTokenId keccak256('aspjawir') = 0x7e3b...>") — the hex inside is
// the usable value. Returns the value, or null when it cannot be resolved.
function resolveArg(arg) {
  if (arg === null || arg === undefined) return null;
  if (typeof arg === "number") return arg;
  if (typeof arg !== "string") return null;
  const s = arg.trim();
  if (/^0x[0-9a-fA-F]+$/.test(s)) return s;
  if (/^-?\d+$/.test(s)) return Number(s);
  if (s === "true") return true;
  if (s === "false") return false;
  const hex = s.match(/0x[0-9a-fA-F]{40,64}/);
  if (hex) return hex[0];
  return null; // a placeholder with no concrete value inside
}

// ABI-encode one argument for its type. Returns a 64-hex-char word, or null.
function encodeArg(type, value) {
  if (value === null || value === undefined) return null;
  if (type === "uint256" || type.startsWith("uint")) {
    const n = typeof value === "number" ? BigInt(value) : BigInt(String(value));
    return n.toString(16).padStart(64, "0");
  }
  if (type === "address") {
    const a = String(value).toLowerCase();
    if (!/^0x[0-9a-f]{40}$/.test(a)) return null;
    return "0".repeat(24) + a.slice(2);
  }
  if (type === "bytes32") {
    const b = String(value).toLowerCase();
    if (!/^0x[0-9a-f]{64}$/.test(b)) return null;
    return b.slice(2);
  }
  if (type === "bool") {
    return (value === true || value === "true" ? "1" : "0").padStart(64, "0");
  }
  return null;
}

// Build the full mint calldata (selector + encoded args), or null when the
// args cannot be resolved concretely.
function buildCalldata(fn, args) {
  const selector = selectorOf(fn);
  const types = fnParamTypes(fn);
  if (!selector || types === null) return null;
  if (types.length === 0) return selector;
  if (!Array.isArray(args) || args.length < types.length) return null;
  let data = selector;
  for (let i = 0; i < types.length; i++) {
    const resolved = resolveArg(args[i]);
    const word = encodeArg(types[i], resolved);
    if (word === null) return null;
    data += word;
  }
  return data;
}

// ---------------------------------------------------------------------------
// On-chain probing (generic view selectors; a revert means "not present")
// ---------------------------------------------------------------------------

const SUPPLY_UINT_VIEWS = [
  "freeRemaining()",
  "freeLeft()",
  "totalMinted()",
  "totalSupply()",
  "freeMinted()",
  "freeSold()",
  "totalShares()",
  "sold()",
];
const CAP_UINT_VIEWS = ["maxSupply()", "MAX_SUPPLY()", "freeSupply()", "freeCap()", "cap()"];
const QUOTA_VIEWS = [
  // [signature, kind] — kind "bool" means used when true; "uint" means
  // used when > 0; "available" means used when false.
  ["freeUsed(address)", "bool"],
  ["freeClaimed(address)", "bool"],
  ["hasMinted(address)", "bool"],
  ["claimedBy(address)", "bool"],
  ["mintedByWallet(address)", "uint"],
  ["freeAvailable(address)", "available"],
  ["balanceOf(address)", "uint"],
];

function padAddress(addr) {
  return "0".repeat(24) + addr.toLowerCase().replace(/^0x/, "");
}

function parseUint256(hex) {
  if (typeof hex !== "string" || !/^0x[0-9a-fA-F]+$/.test(hex)) return null;
  try {
    return BigInt(hex);
  } catch {
    return null;
  }
}

// Probe every supply view; return what answered.
async function probeSupply(rpc, contract) {
  const out = { freeRemaining: null, minted: null, cap: null, raw: {} };
  for (const sig of SUPPLY_UINT_VIEWS) {
    const sel = selectorOf(sig);
    let hex;
    try {
      hex = await rpc.ethCall(contract, sel);
    } catch {
      hex = null;
    }
    const v = parseUint256(hex);
    if (v === null) continue;
    out.raw[sig] = v.toString();
    if (sig === "freeRemaining()" || sig === "freeLeft()") out.freeRemaining = v;
    else if (out.minted === null) out.minted = v;
  }
  for (const sig of CAP_UINT_VIEWS) {
    const sel = selectorOf(sig);
    let hex;
    try {
      hex = await rpc.ethCall(contract, sel);
    } catch {
      hex = null;
    }
    const v = parseUint256(hex);
    if (v === null) continue;
    out.raw[sig] = v.toString();
    if (out.cap === null) out.cap = v;
  }
  return out;
}

// Probe every quota view for one wallet. Returns
// { used: true|false|null, details: { view: "used"|"unused" } }.
async function probeQuota(rpc, contract, wallet) {
  const details = {};
  let anyAnswered = false;
  let used = false;
  for (const [sig, kind] of QUOTA_VIEWS) {
    const sel = selectorOf(sig);
    let hex;
    try {
      hex = await rpc.ethCall(contract, sel + padAddress(wallet));
    } catch {
      hex = null;
    }
    const v = parseUint256(hex);
    if (v === null) continue;
    anyAnswered = true;
    let isUsed;
    if (kind === "bool") isUsed = v !== 0n;
    else if (kind === "available") isUsed = v === 0n;
    else isUsed = v > 0n;
    details[sig] = isUsed ? "used" : "unused";
    if (isUsed) used = true;
  }
  return { used: anyAnswered ? used : null, details };
}

// ---------------------------------------------------------------------------
// Cost parsing
// ---------------------------------------------------------------------------

// Parse a registry value like "0", "0.001 BNB", "10 USDT/share" into
// { human, amountWeiOrUnits (BigInt, smallest unit of the payment asset),
//   asset, paid: boolean }. Unparseable -> amount 1n (fail-closed sentinel).
function parseCost(value) {
  if (value === null || value === undefined) return { human: null, amount: null, asset: null, paid: null };
  const s = String(value).trim();
  if (s === "0" || s === "0.0") return { human: "0 (free)", amount: 0n, asset: "BNB", paid: false };
  const m = s.match(/^([\d.]+)\s*([A-Za-z]*)/);
  if (!m) return { human: s, amount: 1n, asset: null, paid: true };
  const num = Number(m[1]);
  const asset = (m[2] || "BNB").toUpperCase();
  if (!Number.isFinite(num) || num <= 0) return { human: s, amount: 1n, asset, paid: true };
  let amount;
  if (asset === "BNB" || asset === "ETH") amount = BigInt(Math.round(num * 1e18));
  else if (asset === "USDT" || asset === "USDC") amount = BigInt(Math.round(num * 1e6));
  else amount = BigInt(Math.round(num * 1e18));
  return { human: s, amount, asset, paid: true };
}

// ---------------------------------------------------------------------------
// The checklist
// ---------------------------------------------------------------------------

function check(code, pass, detail, source) {
  return { code, pass, detail, source };
}

// Resolve the request to a registry entry.
// Returns { found, wallet, contract, fn, suppliedFn, suppliedSelector }.
// contract is always the submitted contract (normalized) when one was
// given — even for an unknown contract, so the response echoes it and the
// proof records which contract was judged.
function resolveTarget(input) {
  const wallet = known.normalizeAddress(input.wallet) || null;
  const submittedContract = known.normalizeAddress(input.contract);
  const suppliedSelector =
    typeof input.selector === "string" ? input.selector.toLowerCase() : null;
  let found = null;
  if (submittedContract) found = known.findByContract(submittedContract, input.function);
  if (!found && input.url) found = known.findByUrl(input.url);
  if (!found) {
    return {
      found: null,
      wallet,
      contract: submittedContract,
      fn: input.function || null,
      suppliedFn: input.function || null,
      suppliedSelector,
      error: null,
    };
  }

  const { key, entry } = found;
  const contract = entry.contract
    ? known.normalizeAddress(entry.contract)
    : submittedContract;
  return {
    found: { key, entry },
    wallet,
    contract,
    fn: input.function || entry.fn || null,
    suppliedFn: input.function || null,
    suppliedSelector,
    error: null,
  };
}

// Run the full checklist. `rpc` is an object with ethCall, blockNumber,
// gasPrice, estimateGas (lib/rpc.js, or a stub in tests).
async function verify(input, rpc) {
  if (!input || typeof input !== "object") throw new Error("input must be an object");
  if (!input.contract && !input.url) throw new Error("give a contract address or a mint URL");

  const target = resolveTarget(input);
  const checks = [];
  const wallet = target.wallet;

  // --- 1. source_match -------------------------------------------------
  let entry = null;
  let key = null;
  const contract = target.contract;
  const fn = target.fn;
  if (!target.found) {
    checks.push(check("source_match", false,
      input.contract
        ? `contract ${input.contract} is not in the verified registry — no official source confirms it`
        : `no verified project matches ${input.url}`,
      "registry"));
  } else {
    ({ key, entry } = target.found);
    // A supplied function that differs from the registry's verified one
    // (or one the registry has no function for at all).
    if (target.suppliedFn && (!entry.fn || target.suppliedFn.trim().toLowerCase() !== entry.fn.toLowerCase())) {
      checks.push(check("source_match", false,
        `function ${target.suppliedFn} does not match the verified function ${entry.fn || "(none on file)"} for ${key}`,
        "registry"));
    } else if (input.contract && entry.contract && known.normalizeAddress(input.contract) !== known.normalizeAddress(entry.contract)) {
      checks.push(check("source_match", false,
        `contract ${input.contract} does not match the verified contract ${entry.contract} for ${key}`,
        "registry"));
    } else {
      const contractNote = contract
        ? `contract ${contract} matches the verified registry entry`
        : `project matches the verified registry entry (no contract on file)`;
      checks.push(check("source_match", true,
        `${key}: ${contractNote} (${entry.site || "no site"})`,
        "registry"));
    }
  }

  // --- 2. selector_verified --------------------------------------------
  // The selector is computed from the function signature (keccak256) —
  // never copied from a page. It is then cross-checked against the
  // selector the official source itself states (recordedSelector, from the
  // project's skill.md). If they disagree, the function signature on file
  // is suspect (this caught meow-cards: the registry had bytes32 where
  // the official source has uint256) and the check fails closed.
  const computedSelector = selectorOf(fn);
  let selector = computedSelector;
  if (target.found && entry) {
    const supplied = target.suppliedSelector;
    if (supplied && computedSelector && supplied !== computedSelector) {
      checks.push(check("selector_verified", false,
        `supplied selector ${supplied} != selector computed from ${fn} (${computedSelector}) — a truncated or wrong selector, the BAO trap`,
        "computed"));
    } else if (!computedSelector) {
      checks.push(check("selector_verified", null,
        `no verified function signature on file for ${key}, so no selector can be computed — unverified`,
        "unverified"));
    } else if (entry.recordedSelector && entry.recordedSelector !== computedSelector) {
      checks.push(check("selector_verified", false,
        `selector computed from ${fn} is ${computedSelector}, but the official source states ${entry.recordedSelector} — the function signature on file disagrees with the official source`,
        "computed"));
    } else {
      let detail = `selector ${computedSelector} computed from ${fn} (keccak256, never copied)`;
      if (entry.recordedSelector) detail += ` — matches the official source's stated selector`;
      checks.push(check("selector_verified", true, detail, "computed"));
    }
  } else {
    checks.push(check("selector_verified", null, "no registry entry, nothing to verify against", "unverified"));
  }

  // --- 3. value_free ----------------------------------------------------
  const cost = entry ? parseCost(entry.value) : { human: null, amount: null, asset: null, paid: null };
  let paidCost = null;
  if (entry && entry.paid && entry.paidCost) {
    paidCost = entry.paidCost;
    checks.push(check("value_free", false,
      `PAID mint: ${paidCost.amount} ${paidCost.asset} per share (contract ${contract})`,
      "registry"));
  } else if (cost.paid === false) {
    checks.push(check("value_free", true, "mint value is 0 — gas only", "registry"));
  } else if (cost.paid === true) {
    checks.push(check("value_free", false,
      `mint costs ${cost.human} — not free`,
      "registry"));
  } else {
    checks.push(check("value_free", null, "mint cost is not on file — unverified", "unverified"));
  }

  // --- 4. pool_open -----------------------------------------------------
  let poolPass = null;
  let poolDetail = "";
  let poolSource = "unverified";
  let liveRemaining = null;
  const nowSec = Math.floor(Date.now() / 1000);
  if (entry && entry.deadline && nowSec >= entry.deadline) {
    poolPass = false;
    poolDetail = `mint window closed (deadline ${new Date(entry.deadline * 1000).toISOString()})`;
    poolSource = "registry";
  } else if (entry && contract) {
    // Live supply probe first.
    let supply = null;
    try {
      supply = await probeSupply(rpc, contract);
    } catch {
      supply = null;
    }
    if (supply) {
      if (supply.freeRemaining !== null) {
        liveRemaining = supply.freeRemaining;
        if (supply.freeRemaining > 0n) {
          poolPass = true;
          poolDetail = `live: ${supply.freeRemaining} free slots remaining`;
          poolSource = "live";
        } else {
          poolPass = false;
          poolDetail = "live: freeRemaining is 0 — free pool is empty";
          poolSource = "live";
        }
      } else if (supply.minted !== null) {
        const cap = supply.cap !== null ? supply.cap : (entry.cap !== null ? BigInt(entry.cap) : null);
        if (cap !== null) {
          liveRemaining = cap - supply.minted;
          if (liveRemaining > 0n) {
            poolPass = true;
            poolDetail = `live: minted ${supply.minted} / cap ${cap} — ${liveRemaining} left`;
            poolSource = "live";
          } else {
            poolPass = false;
            poolDetail = `live: minted ${supply.minted} / cap ${cap} — sold out`;
            poolSource = "live";
          }
        }
      }
    }
    // Snapshot fallback when the live probe could not decide.
    if (poolPass === null) {
      if (known.snapshotSaysClosed(entry)) {
        poolPass = false;
        poolDetail = `registry snapshot (${entry.status}): free pool is closed`;
        poolSource = "snapshot";
      } else if (known.snapshotSaysOpen(entry)) {
        poolPass = true;
        poolDetail = `registry snapshot (${entry.status}): pool was open — not re-checked live`;
        poolSource = "snapshot";
      }
    }
    // Per-wallet quota, when a wallet was supplied.
    if (poolPass === true && wallet) {
      let quota = null;
      try {
        quota = await probeQuota(rpc, contract, wallet);
      } catch {
        quota = null;
      }
      if (quota && quota.used === true) {
        poolPass = false;
        poolDetail += `; wallet ${wallet} already used its free quota (${Object.entries(quota.details).filter(([, v]) => v === "used").map(([k]) => k).join(", ")})`;
        poolSource = "live";
      } else if (quota && quota.used === false) {
        poolDetail += `; wallet quota unused (live)`;
      } else if (quota && quota.used === null) {
        if (wallet === REGISTRY_WALLET && known.snapshotSaysQuotaUsed(entry)) {
          poolPass = false;
          poolDetail += `; registry snapshot (${entry.status}): this wallet already used its free quota`;
          poolSource = "snapshot";
        } else {
          poolPass = null;
          poolDetail += "; per-wallet quota could not be verified live — unverified";
          poolSource = "unverified";
        }
      }
    } else if (poolPass === true && !wallet) {
      poolDetail += "; per-wallet quota not checked (no wallet supplied)";
    }
    if (poolPass === null && !poolDetail) {
      poolDetail = "pool state could not be determined live or from the snapshot — unverified";
    }
  } else if (entry && !contract) {
    // Known project, no contract on file: only the snapshot can speak.
    if (known.snapshotSaysClosed(entry)) {
      poolPass = false;
      poolDetail = `registry snapshot (${entry.status}): free pool is closed`;
      poolSource = "snapshot";
    } else if (known.snapshotSaysOpen(entry)) {
      poolPass = true;
      poolDetail = `registry snapshot (${entry.status}): pool was open — not re-checked live`;
      poolSource = "snapshot";
    } else {
      poolPass = null;
      poolDetail = "no contract on file and no snapshot pool state — unverified";
      poolSource = "unverified";
    }
  } else {
    poolPass = null;
    poolDetail = "unknown contract — no pool to check";
    poolSource = "unverified";
  }
  checks.push(check("pool_open", poolPass, poolDetail, poolSource));

  // --- 5. no_permit_gate -------------------------------------------------
  if (entry) {
    if (entry.permitGated) {
      checks.push(check("no_permit_gate", false,
        `${key} needs a server-issued permit / signature / voucher / PoW step — it cannot be minted in one direct call`,
        "registry"));
    } else {
      checks.push(check("no_permit_gate", true, "direct one-call mint, no server-issued permit needed", "registry"));
    }
  } else {
    checks.push(check("no_permit_gate", null, "unknown contract — cannot tell if a permit is required", "unverified"));
  }

  // --- 6. no_hidden_approval ---------------------------------------------
  if (entry) {
    const costAsset = paidCost ? paidCost.asset : cost.asset;
    if (paidCost || (cost.paid === true && costAsset && costAsset !== "BNB" && costAsset !== "ETH")) {
      checks.push(check("no_hidden_approval", false,
        `mint is paid in ${costAsset}, so an ERC-20 approval is required before minting`,
        "registry"));
    } else if (cost.paid === false) {
      checks.push(check("no_hidden_approval", true, "value-0 mint, no token approval involved", "registry"));
    } else {
      checks.push(check("no_hidden_approval", null, "cost is unknown, cannot tell if an approval is required", "unverified"));
    }
  } else {
    checks.push(check("no_hidden_approval", null, "unknown contract — cannot tell if an approval is required", "unverified"));
  }

  // --- 7. gas_estimate (informational) ------------------------------------
  let gasPriceWei = null;
  let gasEstimateWei = null;
  let gasUnits = null;
  let gasDetail = "";
  try {
    const gp = await rpc.gasPrice();
    if (gp !== null) {
      gasPriceWei = gp;
      gasDetail = `live gas price ${gp.toString()} wei`;
      // Estimate the mint call itself when the calldata is concrete.
      if (contract && fn) {
        const calldata = buildCalldata(fn, entry ? entry.args : null);
        if (calldata) {
          const est = await rpc.estimateGas(contract, calldata, wallet || REGISTRY_WALLET);
          if (est !== null) {
            gasUnits = est;
            gasEstimateWei = est * gp;
            gasDetail += `; estimated ${est.toString()} gas (~${gasEstimateWei.toString()} wei)`;
          } else {
            gasDetail += "; estimateGas reverted — the mint call would fail on-chain";
          }
        } else {
          gasDetail += "; mint calldata not concrete (args need a server-issued value), estimate skipped";
        }
      }
      checks.push(check("gas_estimate", true, gasDetail, "live"));
    } else {
      checks.push(check("gas_estimate", false, "live RPC did not answer — no gas data", "unverified"));
    }
  } catch {
    checks.push(check("gas_estimate", false, "live RPC did not answer — no gas data", "unverified"));
  }

  // --- verdict ------------------------------------------------------------
  const byCode = {};
  for (const c of checks) byCode[c.code] = c;
  const SAFETY = ["source_match", "selector_verified", "pool_open", "no_permit_gate", "no_hidden_approval"];
  let verdict = null;
  let reasonCode = null;
  const firstFail = [
    ["source_match", "RISKY", "CONTRACT_UNKNOWN"],
    ["selector_verified", "RISKY", "SELECTOR_MISMATCH"],
    ["value_free", "PAID", "COST"],
    // Permit gate before pool: a gated mint is a trap even when the pool
    // still has supply (UFO), and the gate is the operative reason.
    ["no_permit_gate", "BLOCKED", "PERMIT_GATE"],
    ["pool_open", "BLOCKED", "POOL_CLOSED"],
    ["no_hidden_approval", "RISKY", "HIDDEN_APPROVAL"],
  ];
  for (const [code, v, r] of firstFail) {
    if (byCode[code] && byCode[code].pass === false) {
      verdict = v;
      reasonCode = r;
      break;
    }
  }
  // Refine the BLOCKED reason from the pool detail.
  if (verdict === "BLOCKED" && reasonCode === "POOL_CLOSED") {
    const d = (byCode.pool_open.detail || "").toLowerCase();
    if (d.includes("quota")) reasonCode = "QUOTA_USED";
    else if (d.includes("window closed")) reasonCode = "WINDOW_CLOSED";
    else if (d.includes("empty") || d.includes("sold out") || d.includes("closed") || d.includes("exhausted")) reasonCode = "SOLD_OUT";
  }
  if (!verdict) {
    const unknown = SAFETY.find((code) => byCode[code] && byCode[code].pass === null);
    if (unknown) {
      verdict = "RISKY";
      reasonCode = "UNVERIFIED";
    } else {
      verdict = "FREE";
      reasonCode = "FREE";
    }
  }

  const result = {
    verdict,
    reasonCode,
    checks,
    contract,
    function: fn,
    selector,
    project: key,
    site: entry ? entry.site : null,
    gasPriceWei: gasPriceWei === null ? null : gasPriceWei.toString(),
    gasEstimateWei: gasEstimateWei === null ? null : gasEstimateWei.toString(),
    gasUnits: gasUnits === null ? null : gasUnits.toString(),
    cost: paidCost
      ? { human: `${paidCost.amount} ${paidCost.asset}/share`, amount: paidCost.raw, asset: paidCost.asset }
      : cost.paid === false
        ? { human: "0 (free)", amount: "0", asset: "BNB" }
        : cost.paid === true
          ? { human: cost.human, amount: cost.amount === null ? null : cost.amount.toString(), asset: cost.asset }
          : { human: null, amount: null, asset: null },
    liveRemaining: liveRemaining === null ? null : liveRemaining.toString(),
  };
  result.circuitFields = toCircuitFields(result, { entry, wallet, suppliedSelector: target.suppliedSelector, suppliedFn: target.suppliedFn });
  return result;
}

// ---------------------------------------------------------------------------
// Map a verdict onto the Gatekeeper circuit's inputs.
//
//   registered_vk / proof_vk  contract identity (registry vs submitted)
//   minimum / public_balance  pool: remaining slots, minimum 1
//   expiry / current block    permit gate: fails (1 >= 1) when gated
//   recipient / condition     selector: computed vs expected
//   amount / max_transfer     cost: 0 only when free with no approval
//   decision                  1 exactly when the verdict is FREE
// ---------------------------------------------------------------------------
function toCircuitFields(result, { entry, wallet, suppliedSelector, suppliedFn }) {
  const byCode = {};
  for (const c of result.checks) byCode[c.code] = c;

  const registeredContract = entry && entry.contract ? entry.contract.toLowerCase() : ZERO_ADDRESS;
  const submittedContract = result.contract ? result.contract.toLowerCase() : ZERO_ADDRESS;

  // Pool: live remaining when known; 1 when a snapshot says open (the
  // minimal claim "at least one slot was open"); 0 otherwise.
  let publicBalance;
  if (result.liveRemaining !== null) publicBalance = result.liveRemaining;
  else if (byCode.pool_open && byCode.pool_open.pass === true) publicBalance = "1";
  else publicBalance = "0";

  // Permit gate: a gated mint fails the expiry check (current == expiry).
  const gated = byCode.no_permit_gate && byCode.no_permit_gate.pass === false;
  const currentBlock = gated ? "1" : "0";
  const expiryBlock = gated ? "1" : "100000";

  // Selector: computed vs expected (supplied selector, supplied function's
  // selector, or the computed one). Unknown function -> a deliberate
  // mismatch so the check fails closed.
  const computed = result.selector;
  let expected;
  if (suppliedSelector) expected = suppliedSelector;
  else if (suppliedFn) expected = selectorOf(suppliedFn) || "0x0000000000000000000000000000000000000001";
  else expected = computed;
  const recipient = computed || ZERO_ADDRESS;
  const conditionRecipient = expected || "0x0000000000000000000000000000000000000001";

  // Cost: 0 only when known-free with no approval. Otherwise the cost in
  // smallest units, or 1 as a fail-closed sentinel (approval required or
  // cost unknown).
  let amount;
  const approvalBad = byCode.no_hidden_approval && byCode.no_hidden_approval.pass === false;
  const approvalUnknown = byCode.no_hidden_approval && byCode.no_hidden_approval.pass === null;
  const valueBad = byCode.value_free && byCode.value_free.pass === false;
  const valueUnknown = byCode.value_free && byCode.value_free.pass === null;
  if (!valueBad && !approvalBad && !valueUnknown && !approvalUnknown) {
    amount = "0";
  } else if (result.cost && result.cost.amount && result.cost.amount !== "0" && result.cost.amount !== null) {
    amount = result.cost.amount;
  } else {
    amount = "1";
  }

  return {
    task_id: `mintsentry:${submittedContract}:${Date.now()}`,
    registered_vk: registeredContract,
    proof_vk: submittedContract,
    minimum: "1",
    public_balance: String(publicBalance),
    expiry_block: expiryBlock,
    current_block: currentBlock,
    recipient,
    condition_recipient: conditionRecipient,
    amount,
    max_transfer: "0",
  };
}

module.exports = {
  verify,
  selectorOf,
  buildCalldata,
  probeSupply,
  probeQuota,
  parseCost,
  toCircuitFields,
  ZERO_ADDRESS,
  REGISTRY_WALLET,
};
