// Field arithmetic helpers for the Gatekeeper circuit (BN254 / alt_bn128).
//
// The circuit works over the BN254 scalar field. Every task value that enters
// the circuit has to become a field element first. This module owns that
// mapping so the decision code and the prover never disagree about it.

const { keccak256 } = require("js-sha3");

// BN254 scalar field prime.
const FIELD_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// Hash of the verification key the platform registered for this tournament.
// A task is only valid when proof_vk matches registered_vk; both arrive as
// this hex hash string in the envelope.
const REGISTERED_VK_HASH =
  "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";

function modP(n) {
  const r = n % FIELD_PRIME;
  return r >= 0n ? r : r + FIELD_PRIME;
}

// Convert one task field value to a field element (BigInt, reduced mod p).
// The envelope carries every field as a string; the mapping is:
//   - "0x..." hex  -> the number it names
//   - decimal digits -> the number it names
//   - anything else -> keccak256(utf8(value)) mod p (a deterministic fallback
//     so a non-numeric value can still enter the circuit instead of crashing)
function toField(value) {
  if (typeof value === "bigint") return modP(value);
  if (typeof value === "number") {
    if (!Number.isInteger(value)) throw new Error(`not an integer field value: ${value}`);
    return modP(BigInt(value));
  }
  const s = String(value);
  if (/^0x[0-9a-fA-F]+$/.test(s)) return modP(BigInt(s));
  if (/^-?\d+$/.test(s)) return modP(BigInt(s));
  return modP(BigInt("0x" + keccak256(s)));
}

// Map a task_id string to a field element.
//   keccak (default): keccak256(utf8(task_id)) mod p
//   numeric:          the decimal digits of the id, as a number, mod p
//   hex:              the hex digits of the id, as a hex number, mod p
// Modes other than the three above throw; a mode whose digits are empty
// falls back to keccak so an id like "abc" still maps deterministically.
function taskIdToField(taskId, mode = "keccak") {
  const id = String(taskId);
  if (mode === "keccak") {
    return modP(BigInt("0x" + keccak256(id)));
  }
  if (mode === "numeric") {
    const digits = id.replace(/[^0-9]/g, "");
    if (digits.length === 0) return modP(BigInt("0x" + keccak256(id)));
    return modP(BigInt(digits));
  }
  if (mode === "hex") {
    const hex = id.replace(/[^0-9a-fA-F]/g, "");
    if (hex.length === 0) return modP(BigInt("0x" + keccak256(id)));
    return modP(BigInt("0x" + hex));
  }
  throw new Error(`unknown GATEKEEPER_TASK_ID_MODE: ${mode}`);
}

module.exports = { FIELD_PRIME, REGISTERED_VK_HASH, modP, toField, taskIdToField };
