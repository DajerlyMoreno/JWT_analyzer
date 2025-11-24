// services/base64url.service.js

const RX_B64URL = /^[A-Za-z0-9\-_]+$/;

/** ======================
 *  Base64URL helpers
 *  ====================== */
export function base64UrlEncode(data) {
  return Buffer.from(data)
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

export function base64UrlDecode(str) {
  let b64 = str.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4 !== 0) b64 += "=";
  return Buffer.from(b64, "base64");
}

export function validateBase64UrlPart(part) {
  if (typeof part !== "string" || part.length === 0) return false;
  return RX_B64URL.test(part);
}

export { RX_B64URL };
