// Download the official Gatekeeper circuit artifacts at boot (or standalone).
//
//   node scripts/fetch-circuits.js            # download whatever is missing
//   node scripts/fetch-circuits.js --force    # re-download everything
//
// The artifacts are NOT committed to git (see .gitignore): they are
// ~2 MB of binaries the platform publishes, and the server fetches them
// itself on first boot. Exit code is non-zero on any failure — the server
// must fail loud at boot, never run without circuits.

const fs = require("node:fs");
const path = require("node:path");
const https = require("node:https");
const http = require("node:http");

const CIRCUITS_DIR = path.join(__dirname, "..", "circuits");

const CIRCUITS = [
  {
    url: "https://agentgames.zkverify.io/circuits/gatekeeper.wasm",
    file: "gatekeeper.wasm",
  },
  {
    url: "https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey",
    file: "gatekeeper_final.zkey",
  },
];

// One GET, following up to 5 redirects. Rejects on any non-200 status.
function download(url, dest, redirectsLeft = 5) {
  return new Promise((resolve, reject) => {
    const get = url.startsWith("https:") ? https.get : http.get;
    const req = get(url, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        if (redirectsLeft === 0) {
          reject(new Error(`too many redirects fetching ${url}`));
          return;
        }
        const next = new URL(res.headers.location, url).toString();
        res.resume();
        download(next, dest, redirectsLeft - 1).then(resolve, reject);
        return;
      }
      if (res.statusCode !== 200) {
        res.resume();
        reject(new Error(`HTTP ${res.statusCode} fetching ${url}`));
        return;
      }
      const out = fs.createWriteStream(dest);
      res.pipe(out);
      out.on("finish", () => out.close(resolve));
      out.on("error", (err) => {
        fs.unlink(dest, () => {});
        reject(err);
      });
    });
    req.on("error", reject);
    req.setTimeout(120000, () => {
      req.destroy(new Error(`timeout fetching ${url}`));
    });
  });
}

async function fetchCircuits({ force = false } = {}) {
  fs.mkdirSync(CIRCUITS_DIR, { recursive: true });
  for (const circuit of CIRCUITS) {
    const dest = path.join(CIRCUITS_DIR, circuit.file);
    if (!force && fs.existsSync(dest)) {
      console.log(`[circuits] ${circuit.file} already present, skipping`);
      continue;
    }
    console.log(`[circuits] downloading ${circuit.url}`);
    await download(circuit.url, dest);
    console.log(
      `[circuits] saved ${circuit.file} (${fs.statSync(dest).size} bytes)`
    );
  }
  return CIRCUITS.map((c) => path.join(CIRCUITS_DIR, c.file));
}

if (require.main === module) {
  fetchCircuits({ force: process.argv.includes("--force") }).catch((err) => {
    console.error(`[circuits] FAILED: ${err.message}`);
    process.exit(1);
  });
}

module.exports = { fetchCircuits, CIRCUITS_DIR, CIRCUITS };
