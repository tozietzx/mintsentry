# MintSentry

**Is this mint really free, really the official contract, and really still open?**

A verifiable free-mint checker for zkVerify Agent Games Season 01, Wildcard track (handle: `aspjawir`). It only judges — it never signs or sends anything.

## The problem it solves

Free mints on BNB Chain are a minefield, and every trap below is one the author walked into before building this:

| Lesson (learned the hard way) | MintSentry check |
|---|---|
| A mint advertised as "free" can hide a token approval, a permit gate, or a price. | `value_free`, `no_hidden_approval`, `no_permit_gate` |
| A contract can look official and be a copy. The registry has to match the project's own source. | `source_match` |
| A free pool can be empty while the site still shows "mint". | `pool_open` (live on-chain supply + per-wallet quota) |
| A function selector copied from a page can be truncated. BAO's was once read as `0xb2ef1ca0`; the correct one is `0x1b2ef1ca`. | `selector_verified` — the selector is **computed** from the function signature with keccak256, never copied |
| A "sent" claim means nothing until the chain says so. | Every on-chain check reads a live BSC RPC; a failed fetch is "unverified", never a pass |

A real find while building this: the author's own registry recorded Meow Cards' function as `mint(uint256,bytes32)`, but the official skill.md states the mint selector is `0x1b2ef1ca` with `(quantity, agentTokenId)` — and `agentTokenId` is a `uint256`, not a `bytes32`. So the real signature is `mint(uint256,uint256)`, and the registry note's recorded selector `0x1b2ef1ca` was right all along. Computing a selector from a wrong signature gives a wrong selector (`0x1801fbe5`), which is why MintSentry also cross-checks the computed selector against the selector the official source itself states — and why the first gas estimate reverted with the wrong selector, then simulated cleanly (~308,754 gas) once the signature was corrected.

## Verdicts

- **FREE** — value 0, official contract, selector verified, pool open, no permit, no approval.
- **PAID** — the mint costs money (e.g. BAGENT, 10 USDT/share).
- **BLOCKED** — sold out, free quota used, mint window closed, or permit-gated (e.g. BAO sold out; UFO needs a server-issued EIP-712 permit).
- **RISKY** — unknown contract, selector mismatch, hidden approval, or anything that could not be verified.

## Endpoints

- `GET /` — interactive dashboard. Paste a mint URL or contract address, click Verify. One-click presets: a known-good free mint (Meow Cards), a paid mint (BAGENT), a sold-out mint (BAO), a permit-gated trap (UFO). No wallet, no sign-in, no payment.
- `POST /verify` — `{ url?, contract?, function?, selector?, wallet? }` → `{ verdict, reasonCode, checks: [{code, pass, detail, source}], gasPriceWei, gasEstimateWei, gasUnits, contract, function, selector, project, site, cost, liveRemaining, zk_proof }`.
- `POST /agent` — same as `/verify`, but the request must carry a valid `x-agent-games-signature` (HMAC-SHA256 over the raw body) when `AGENT_GAMES_HMAC_SECRET` is set, and the response is signed the same way. This follows the platform's transport convention (same as the Proof Gatekeeper agent). The Wildcard track has no platform-defined task envelope, so `/agent` accepts the same body as `/verify`.
- `GET /health` — `{ ok, agent: "mintsentry", hmacConfigured, selfTest }`. The self-test runs a real verification plus a real proof and reports PASS/FAIL honestly.
- Any `POST` with body `{ "type": "agent-games.preflight.v1" }` → `{ ok: true, protocolVersion: "v1" }`.

## The proof — what it does and does NOT prove

Every `/verify` and `/agent` response carries a Groth16 proof (bn128, same official Gatekeeper circuit and verification key as the Proof Gatekeeper agent, vk hash `0x6b79c6…d77b0`), generated for the verdict and verified locally with snarkjs before the response is sent (`zk_proof.verified_locally`).

The proof attests that **the verdict follows the checks, given the inputs**. It does **not** prove that the external source itself is truthful. The build page says it plainly:

> "A proof can verify perfectly and still authorize the wrong action."

That is why the per-check list in the response is the real evidence and the proof is only a seal on it. Each check is labelled with its source — `live` (a BSC RPC just answered), `snapshot` (the verified registry, dated), `registry`, `computed` (keccak256 from a verified signature), or `unverified`. A snapshot is never presented as live, and a failed live fetch is reported as "unverified", never as a pass.

### How the verdict maps onto the circuit

The Gatekeeper circuit has five checks and a decision that must equal their AND. MintSentry maps them like this:

| Circuit check | MintSentry check | Encoding |
|---|---|---|
| `proofVk == registeredVk` | `source_match` | registry contract vs submitted contract |
| `publicBalance >= minimum` | `pool_open` | remaining slots (live, or 1 = "≥1 open per snapshot"), minimum 1 |
| `currentBlock < expiryBlock` | `no_permit_gate` | gated mints set both to 1, so the check fails |
| `recipient == conditionRecipient` | `selector_verified` | computed selector vs expected selector |
| `amount <= maxTransfer (= 0)` | `value_free` + `no_hidden_approval` | cost in smallest units; 0 only when free with no approval; 1 is the fail-closed sentinel for an approval or an unknown cost |

`decision` is 1 exactly when the verdict is FREE. Every non-FREE verdict has at least one circuit check failing, so the prover accepts the decision and refuses the opposite one (fail-closed). Gas estimation is response-only: it is a liveness signal, not part of the proof.

## The verified-contracts registry

`data/known-mints.json` is the primary source: contracts, functions, sites, and statuses already verified from each project's official `skill.md`/`llms.txt` plus live on-chain checks. It is derived by `scripts/build-registry.js` from the author's registry — selectors are computed there, never copied. Status is a snapshot, not a live guarantee; the live RPC check is the gate.

## Run it

```sh
npm install
npm test          # 27 checks: all four verdicts + real proofs + fail-closed
npm start         # PORT=8080 by default
```

Set `AGENT_GAMES_HMAC_SECRET` (the secret the zkVerify dashboard issues when you register this agent) to enable signed requests/responses. Until then the agent runs with `hmacConfigured: false`, exactly like the Gatekeeper agent did before its secret was set. No other secrets exist; nothing is ever signed or sent on-chain.

## Registering (for the owner)

1. In the zkVerify dashboard, register a new agent with **Wildcard** checked, repo `tozietzx/mintsentry`, endpoint `https://<this-service>.up.railway.app`.
2. The dashboard issues an HMAC secret (shown once). Set it as `AGENT_GAMES_HMAC_SECRET` on the Railway service (Variables → New Variable → redeploy).
3. Check `GET /health`: `hmacConfigured` should be `true` and `selfTest` `PASS`.

## Stack

Plain Node.js stdlib HTTP server + `snarkjs` (Groth16) + `js-sha3`. Public BSC RPCs for on-chain reads. No private keys, no wallet, no signing.
