// The verified-contracts registry: the primary source MintSentry judges
// against. Loaded from the bundled data/known-mints.json (derived by
// scripts/build-registry.js from the user's verified registry).
//
// A contract is "known" only if it is in this file. Anything else is
// unverified by definition — the checker says RISKY, never "probably fine".

const path = require("node:path");

const DATA = require(path.join(__dirname, "..", "data", "known-mints.json"));
const ENTRIES = DATA.entries || {};

function normalizeAddress(addr) {
  if (typeof addr !== "string") return null;
  const s = addr.trim().toLowerCase();
  if (!/^0x[0-9a-f]{40}$/.test(s)) return null;
  return s;
}

// Find entries by contract address (case-insensitive). One contract can
// host several functions (BAGENT has a free mining claim AND a paid mint
// on 0x9CA1A3ee...), so this returns every match in registry order.
function findAllByContract(contract) {
  const addr = normalizeAddress(contract);
  if (!addr) return [];
  const out = [];
  for (const [key, entry] of Object.entries(ENTRIES)) {
    if (entry.contract && normalizeAddress(entry.contract) === addr) {
      out.push({ key, entry });
    }
  }
  return out;
}

// Find one entry by contract address. When a function signature is given,
// the entry whose fn matches it wins (the contract alone is ambiguous).
// Otherwise the base project entry wins over a suffixed one (bagent over
// bagent-mining). Returns { key, entry } or null.
function findByContract(contract, fn) {
  const matches = findAllByContract(contract);
  if (matches.length === 0) return null;
  if (fn) {
    const wanted = fn.trim().toLowerCase();
    const byFn = matches.find((m) => (m.entry.fn || "").toLowerCase() === wanted);
    if (byFn) return byFn;
  }
  const base = matches.find((m) => !m.key.includes("-"));
  return base || matches[0];
}

// Find an entry by project URL. Matches when the given URL's host equals
// the entry site's host (so https://ufo-bsc.netlify.app/ and
// https://ufo-bsc.netlify.app/mint are the same project).
function findByUrl(url) {
  let host;
  try {
    host = new URL(url).host.toLowerCase();
  } catch {
    return null;
  }
  for (const [key, entry] of Object.entries(ENTRIES)) {
    if (!entry.site) continue;
    try {
      if (new URL(entry.site).host.toLowerCase() === host) return { key, entry };
    } catch {
      // A site that is not a parseable URL cannot match.
    }
  }
  return null;
}

// Is this registry status a snapshot that says the free pool is closed?
function snapshotSaysClosed(entry) {
  const s = (entry.status || "").toLowerCase();
  return (
    s.includes("sold_out") ||
    s.includes("exhausted") ||
    s.includes("free_ended") ||
    s.includes("closed")
  );
}

// Is this registry status a snapshot that says the free pool was open?
function snapshotSaysOpen(entry) {
  const s = (entry.status || "").toLowerCase();
  return s.includes("free_live_verified") || s.includes("open_daily");
}

// Did this snapshot say THIS wallet already used its free quota? The
// statuses that record a mint/quota use are wallet-specific to the
// registry owner's wallet (aspjawir). Only meaningful when the queried
// wallet is that wallet.
function snapshotSaysQuotaUsed(entry) {
  const s = (entry.status || "").toLowerCase();
  return (
    s.includes("free_minted") ||
    s.includes("free_used") ||
    s.includes("free_quota_used") ||
    s.includes("free_used_up") ||
    s.startsWith("minted_")
  );
}

module.exports = {
  ENTRIES,
  findByContract,
  findAllByContract,
  findByUrl,
  normalizeAddress,
  snapshotSaysClosed,
  snapshotSaysOpen,
  snapshotSaysQuotaUsed,
};
