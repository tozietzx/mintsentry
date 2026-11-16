// HMAC-SHA256 signing for the Agent Games wire protocol.
//
// The platform signs every request body and sends the digest in the
// `x-agent-games-signature` header; every response we send is signed the
// same way, over the raw response body bytes. The signature is HMAC-SHA256
// with the secret as UTF-8 bytes, hex-encoded. When
// AGENT_GAMES_HMAC_FORMAT is "sha256=" the header value is "sha256=" +
// hex instead of bare hex.
//
// Inbound verification accepts both spellings regardless of the configured
// format: the HMAC itself is what is checked, the prefix is cosmetic, and
// accepting both can only avoid a false rejection, never a false accept.
// Comparison is constant-time.

const crypto = require("node:crypto");

const SIGNATURE_HEADER = "x-agent-games-signature";

function hmacHex(secret, bodyBuffer) {
  return crypto.createHmac("sha256", secret).update(bodyBuffer).digest("hex");
}

// Build the signature header value for a response body.
function sign(secret, bodyBuffer, format = "hex") {
  const hex = hmacHex(secret, bodyBuffer);
  return format === "sha256=" ? "sha256=" + hex : hex;
}

// Verify an inbound signature header against a raw request body.
// Returns false when the header is missing or does not match.
function verify(secret, bodyBuffer, headerValue) {
  if (typeof headerValue !== "string" || headerValue.length === 0) return false;
  const hex = hmacHex(secret, bodyBuffer);
  const candidates = [hex, "sha256=" + hex];
  for (const candidate of candidates) {
    const a = Buffer.from(candidate, "utf8");
    const b = Buffer.from(headerValue, "utf8");
    if (a.length === b.length && crypto.timingSafeEqual(a, b)) return true;
  }
  return false;
}

module.exports = { SIGNATURE_HEADER, sign, verify };
