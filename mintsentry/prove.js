// Groth16 proving for MintSentry, reusing the official Gatekeeper circuit
// (snarkjs) — the same circuit and the same 13 inputs the Gatekeeper agent
// uses, with a different meaning per field (see mintsentry/check.js):
//   registeredVkHash / proofVkHash  registry contract vs submitted contract
//   minimum / publicBalance         pool remaining slots (minimum 1)
//   expiryBlock / currentBlock      permit gate (equal => gated => fails)
//   recipient / conditionRecipient  computed selector vs expected selector
//   amount / maxTransfer            mint cost (0 = free, maxTransfer = 0)
//   decision                        "1" exactly when the verdict is FREE
//   taskId, salt                    as in the Gatekeeper agent
//
// The circuit asserts decision == AND of its five checks, so a proof can
// only be generated for a decision the circuit agrees with. Feed it a
// wrong decision and fullProve throws — that fail-closed behaviour is
// what makes the proof worth anything: a FREE proof can only exist when
// the contract matches, the pool has a slot, there is no permit gate,
// the selector checks out, and the cost is zero.

const crypto = require("node:crypto");
const snarkjs = require("snarkjs");
const { toField, taskIdToField } = require("../lib/field");

// Build the circuit input object for one decided task.
// Throws on a field that cannot be mapped (malformed task).
function buildCircuitInput(fields, decision, taskIdMode) {
  return {
    taskId: taskIdToField(fields.task_id, taskIdMode).toString(),
    minimum: toField(fields.minimum).toString(),
    publicBalance: toField(fields.public_balance).toString(),
    expiryBlock: toField(fields.expiry_block).toString(),
    currentBlock: toField(fields.current_block).toString(),
    recipient: toField(fields.recipient).toString(),
    conditionRecipient: toField(fields.condition_recipient).toString(),
    amount: toField(fields.amount).toString(),
    maxTransfer: toField(fields.max_transfer).toString(),
    registeredVkHash: toField(fields.registered_vk).toString(),
    proofVkHash: toField(fields.proof_vk).toString(),
    salt: toField("0x" + crypto.randomBytes(32).toString("hex")).toString(),
    // "FREE" (or "APPROVE") proves as 1; every other verdict proves as 0.
    decision: decision === "FREE" || decision === "APPROVE" ? "1" : "0",
  };
}

// Generate a Groth16 proof for a decided task. Returns
// { proof, publicSignals }. Throws when the circuit refuses the decision
// (wrong decision for the inputs) or the artifacts are unreadable.
async function generateProof(fields, decision, { wasmPath, zkeyPath, taskIdMode }) {
  const input = buildCircuitInput(fields, decision, taskIdMode);
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    input,
    wasmPath,
    zkeyPath
  );
  return { proof, publicSignals };
}

// Load the verification key out of the zkey (needed to verify locally).
async function loadVerificationKey(zkeyPath) {
  return snarkjs.zKey.exportVerificationKey(zkeyPath);
}

// Verify a proof against its public signals with a verification key.
async function verifyProof(publicSignals, proof, verificationKey) {
  return snarkjs.groth16.verify(verificationKey, publicSignals, proof);
}

module.exports = { buildCircuitInput, generateProof, loadVerificationKey, verifyProof };
