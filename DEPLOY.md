# MintSentry — deploy handoff (for the parent agent)

Status 2026-11-16 ~20:50 WIB: **code complete, tested, committed locally. GitHub repo + Railway deploy NOT done — both need the live browser** (a subagent cannot use it).

## What is done

- Code: `~/workspace/zkverify/mintsentry/` — server.js, mintsentry/{check,known,prove}.js,
  lib/{field,hmac,rpc}.js, scripts/{build-registry,fetch-circuits}.js,
  data/known-mints.json (37 entries), test.js, README.md, package.json.
- `node test.js` = **ALL 27 CHECKS PASSED** (all four verdicts, real Groth16 proofs,
  fail-closed, HMAC, selector checks).
- Local live server verified (port 8090, real BSC RPC):
  - GET /health → `{ok:true, agent:"mintsentry", hmacConfigured:false, selfTest:"PASS"}`
  - POST /verify Meow Cards → **FREE**, 7/7 checks, gas 263,367 units (~1.32e13 wei),
    proof verified_locally: true (pool live 1564/10000, quota unused).
  - POST /verify BAGENT → **PAID** (10 USDT/share), proof verified.
  - POST /verify BAO → **BLOCKED / SOLD_OUT**, proof verified.
  - POST /verify UFO → **BLOCKED / PERMIT_GATE**, proof verified.
  - POST /verify unknown contract → **RISKY / CONTRACT_UNKNOWN**, proof verified.
  - POST /agent preflight → `{ok:true, protocolVersion:"v1"}`; with a test HMAC secret:
    unsigned → 401, valid signature → 200 + signed response header.
  - Cold boot (no circuits dir) downloads both circuit files from the official URLs
    (verified byte-identical SHA-256) and boots with selfTest PASS.
- Git: local repo committed, HEAD **07bb6ce** (2 commits). 15 files, 117,068 bytes.
  Manifest ready: `~/workspace/github-push/manifests/mintsentry-paths.txt` (+ .json).
  No secrets in tracked files (checked).
- A real bug was found and fixed during this build: the registry recorded Meow's fn as
  mint(uint256,bytes32), but the official skill.md says mint is 0x1b2ef1ca with
  (quantity, agentTokenId) where agentTokenId is a uint256 — so the real signature is
  mint(uint256,uint256) and the recorded selector was right all along. The checker now
  cross-checks the computed selector against the official stated selector (fails closed).
  This is documented in the README.

## Step 1 — GitHub repo (browser, signed in as tozietzx)

`gh` is NOT logged in and the connector cannot create personal repos (403 for apps),
so create the repo in the browser, then push with the CLI.

1. Browser → https://github.com/new — create repo **mintsentry**, **PUBLIC**, no README/.gitignore/license (content comes from the push).
2. Back in the VM:
   ```
   /opt/hatch/bin/github push-files --repo tozietzx/mintsentry --branch main \
     --paths-file ~/workspace/github-push/manifests/mintsentry-paths.txt \
     --commit-message "MintSentry: verifiable free-mint checker for zkVerify Agent Games Wildcard"
   ```
   (If push-files needs different flags, check `--help` first; the Gatekeeper push used the
   same flow. The --paths-file must be NUL-delimited and end with a trailing NUL — the
   manifest already is.)
3. Verify via GitHub API: repo exists, PUBLIC, 15 files, README renders.
4. Grant the Meta Muse AI App access: browser → https://github.com/settings/installations/182493270
   → add repo `mintsentry` → Save (same as the 11 repos already on it, incl. agent-games-gatekeeper).

## Step 2 — Railway deploy (browser, same account as Gatekeeper)

Project "angelic-recreation" (https://railway.com/project/d98f8770-e372-4d76-b42a-95ab4d191faf),
signed in via GitHub OAuth as tozietzx, no card (free trial, $5.00 left).

1. In the project, **New Service → GitHub Repo → tozietzx/mintsentry** (new service in the
   same project, or a new project if cleaner).
2. Set NO env vars yet (the HMAC secret comes later from the dashboard).
3. Railway runs `npm install` then `npm start` (package.json has both). The server downloads
   the circuit files itself on first boot from the official zkVerify URLs (verified working).
   Start command uses PORT from the environment (server listens on process.env.PORT).
4. Get the service domain (e.g. https://mintsentry-production-XXXX.up.railway.app) and verify:
   - GET /health → 200, `{ok:true, agent:"mintsentry", hmacConfigured:false, selfTest:"PASS"}`
   - POST /verify `{"contract":"0xb8164afefc53910d7a74cece15a60a9e0c86089e"}` → verdict FREE,
     proof verified_locally: true.

## Step 3 — report to Bey (do NOT do the registration for him)

- Repo URL, live endpoint URL, /health result, one /verify example per verdict.
- Exact next steps for him:
  1. In the zkVerify dashboard modal, register a new agent with **Wildcard** checked,
     repo `tozietzx/mintsentry`, endpoint = the Railway host (host-only, no https://, no path —
     same quirk as the Gatekeeper registration).
  2. The dashboard issues an HMAC secret (shown once). He sets it as
     `AGENT_GAMES_HMAC_SECRET` on the Railway service (Variables → New Variable → redeploy),
     or via Secure Vault if he asks morph to set it.
  3. Check GET /health: `hmacConfigured` should become `true` and `selfTest` `PASS`.

## Do NOT touch

- The TOZIE Gatekeeper agent/service (separate Railway service, separate repo).
- Do not register anything in the zkVerify dashboard (needs Bey's sign-in).
- Do not invent an HMAC secret.
