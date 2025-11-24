// services/hmac.service.js
import crypto from "crypto";
import { base64UrlEncode } from "./base64url.service.js";

/** ======================
 *  Firmas HMAC
 *  ====================== */
const ALG_MAP = {
  HS256: "sha256",
  HS384: "sha384",
  HS512: "sha512"
};

export function signHmac(headerB64, payloadB64, secret, algorithm = "HS256") {
  if (!ALG_MAP[algorithm]) throw new Error(`Algoritmo no soportado: ${algorithm}`);
  const hmac = crypto.createHmac(ALG_MAP[algorithm], secret);
  hmac.update(`${headerB64}.${payloadB64}`);
  return base64UrlEncode(hmac.digest());
}

export function verifyHmac(
  headerB64,
  payloadB64,
  signatureB64,
  secret,
  algorithm = "HS256"
) {
  if (!ALG_MAP[algorithm]) throw new Error(`Algoritmo no soportado: ${algorithm}`);
  const expected = signHmac(headerB64, payloadB64, secret, algorithm);
  const a = Buffer.from(expected);
  const b = Buffer.from(signatureB64);
  if (a.length !== b.length) return false;
  // comparación tiempo-constante
  return crypto.timingSafeEqual(a, b);
}

export { ALG_MAP };
