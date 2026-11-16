// Build the bundled registry data/known-mints.json from the full local
// registry ~/workspace/fast-mint/known-mints.json.
//
// This is a build-time derivation, not a hand copy. For every entry it keeps
// the verified facts (contract, function, site, value, status) and ADDS:
//   selector     — computed with keccak256 from the fn signature. The
//                  fn signature itself comes from the project's official
//                  source; when the registry's recorded fn type is wrong
//                  (meow-cards had bytes32 where the official skill.md
//                  has uint256), FN_OVERRIDES below corrects it, and the
//                  checker cross-checks the computed selector against the
//                  selector the official source states (recordedSelector).
//   recordedSelector — the selector stated in the project's official
//                  source (via the registry note). Used as the cross-check
//                  target; a mismatch with the computed selector fails
//                  the selector check closed.
//   permitGated  — true when the mint needs a server-issued signature /
//                  voucher / permit / PoW / commit-reveal step.
//   cap          — the free-pool cap, when the registry note states it
//                  confidently. Absent when unknown.
//   deadline     — unix seconds, when the note states a closing time.
//
// The BAGENT paid-mint entry is added here (it is not a free entry in the
// source registry): contract + 10 USDT/share cost, fn unknown on purpose —
// the checker must NOT invent a function signature it has not verified.
//
// Run: node scripts/build-registry.js   (writes data/known-mints.json)

const fs = require("node:fs");
const path = require("node:path");
const { keccak256 } = require("js-sha3");

const SRC = "/home/hatch/workspace/fast-mint/known-mints.json";
const DEST = path.join(__dirname, "..", "data", "known-mints.json");

// Hand-curated derived flags, from reading the registry notes.
const PERMIT_GATED = new Set(["ufo", "qtards", "agentite", "pawgang", "periodiclab"]);

// Free-pool cap, only where the note states it confidently.
const CAP = {
  agentbox: 9999,
  agentite: 1000,
  bao: 5000,
  bnbcity: 4444,
  fagent: 4444,
  likhin: 2000,
  m3mo: 10000,
  meow: 10000,
  "meow-cards": 10000,
  niulai: 4444,
  oathbots: 10000,
  pawgang: 3333,
  pokechain: 15555,
  qtards: 1250,
  rigbypass: 1111,
  sidecoin: 500,
  stamppass: 111,
  thewall: 20000,
  ufo: 1000,
  unwritten: 8888,
  wno: 3000,
  agent888: 888,
  agentcosmos: 100000,
  nebula: 5000,
};

// Function signature corrections, where the registry's recorded fn type
// is wrong. The authoritative source is the project's own skill.md.
//   meow-cards: the registry records mint(uint256,bytes32), but the
//   official skill.md states mint is 0x1b2ef1ca with (quantity, agentTokenId)
//   and agentTokenId is a uint256 (uint256(keccak256(handle))). So the real
//   signature is mint(uint256,uint256) and the recorded selector 0x1b2ef1ca
//   was RIGHT all along — the bytes32 type was the error. Computing a
//   selector from a wrong signature gives a wrong selector, which is why
//   the checker also cross-checks against the official stated selector.
const FN_OVERRIDES = {
  "meow-cards": "mint(uint256,uint256)",
};
const CONTRACT_OVERRIDES = {
  "agentic-gangster": "0x0a2a07ef09dd7d83e2312476f0588abaa3e34ce3",
};
const DEADLINE = {
  bnbbaby: 1793795358,
  qtards: Math.floor(Date.parse("2026-11-12T15:05:45Z") / 1000),
  ufo: Math.floor(Date.parse("2026-11-12T15:05:45Z") / 1000),
  runinai: Math.floor(Date.parse("2026-11-05T16:58:00Z") / 1000),
};

function selectorOf(fn) {
  if (!fn || typeof fn !== "string") return null;
  // fn is like "mint(uint256,address)" or "mintFree()". Only a clean
  // signature (name + parenthesised types, no spaces) gets a selector.
  if (!/^[a-zA-Z_][a-zA-Z0-9_]*\([^)]*\)$/.test(fn)) return null;
  return "0x" + keccak256(fn).slice(0, 8);
}

// Find a "0x........" selector mentioned in a note, if any.
function recordedSelector(note) {
  if (!note) return null;
  const m = note.match(/selector\s+(0x[0-9a-fA-F]{8})/i);
  return m ? m[1].toLowerCase() : null;
}

function main() {
  const src = JSON.parse(fs.readFileSync(SRC, "utf8"));
  const out = { _note: "Curated snapshot of the verified free-mint registry, derived by scripts/build-registry.js from ~/workspace/fast-mint/known-mints.json. Selectors are COMPUTED from function signatures (keccak256), never copied. Status is a snapshot, not a live guarantee — the live RPC check is the gate. See README.md.", entries: {} };

  for (const [key, e] of Object.entries(src)) {
    if (key.startsWith("_")) continue;
    const fn = FN_OVERRIDES[key] || e.fn || null;
    const entry = {
      contract: e.contract || CONTRACT_OVERRIDES[key] || null,
      fn,
      args: e.args || null,
      site: e.site || null,
      value: e.value !== undefined ? String(e.value) : null,
      status: e.status || null,
      selector: selectorOf(fn),
      recordedSelector: recordedSelector(e.note),
      permitGated: PERMIT_GATED.has(key),
      cap: CAP[key] !== undefined ? CAP[key] : null,
      deadline: DEADLINE[key] !== undefined ? DEADLINE[key] : null,
    };
    out.entries[key] = entry;
  }

  // BAGENT mint: PAID, 10 USDT/share. Not a free entry; added so the
  // checker can return a clean PAID verdict. fn is deliberately null:
  // the mint function signature was never verified, and MintSentry does
  // not invent one.
  out.entries.bagent = {
    contract: "0x9CA1A3eeA74829aA5011c56386b226DB472D0F4f",
    fn: null,
    site: "https://bagent.club/",
    value: "10 USDT/share",
    status: "paid_only_10_usdt_per_share",
    selector: null,
    recordedSelector: null,
    permitGated: false,
    cap: null,
    deadline: null,
    paid: true,
    paidCost: { amount: "10", asset: "USDT", decimals: 6, raw: "10000000" },
  };

  fs.mkdirSync(path.dirname(DEST), { recursive: true });
  fs.writeFileSync(DEST, JSON.stringify(out, null, 1) + "\n");
  const n = Object.keys(out.entries).length;
  console.log(`wrote ${DEST} (${n} entries)`);
  // Report selector mismatches between computed and recorded (a real find).
  for (const [key, e] of Object.entries(out.entries)) {
    if (e.recordedSelector && e.selector && e.recordedSelector !== e.selector) {
      console.log(`  MISMATCH ${key}: recorded ${e.recordedSelector} vs computed ${e.selector} (using computed)`);
    }
  }
}

main();
