// services/parserJwt.service.js
import { base64UrlDecode, validateBase64UrlPart } from "./base64url.service.js";
import { parseJsonObjectWithTree } from "./jsonParser.service.js";

function safeJsonParse(str) {
  try {
    return JSON.parse(str);
  } catch {
    return null;
  }
}

/** ======================
 *  Parseo / estructura JWT
 *  ====================== */
export function parseJwt(token) {
  const parts = token.split(".");
  const [headerB64, payloadB64, signatureB64] = parts;

  // --- Decodificación ---
  const headerStr = base64UrlDecode(headerB64).toString("utf8");
  const payloadStr = base64UrlDecode(payloadB64).toString("utf8");

  // --- Parseo simple JSON (para semántica) ---
  const header = safeJsonParse(headerStr);
  const payload = safeJsonParse(payloadStr);

  // --- Parseo JSON formal (nuevo parser con árbol), pero SOLO si Base64URL es válido ---
  let headerJson = null;
  let payloadJson = null;
  let headerJsonTree = null;
  let payloadJsonTree = null;

  // HEADER: solo intento parser formal si el segmento cumple Base64URL
  if (validateBase64UrlPart(headerB64)) {
    try {
      const parsedHeader = parseJsonObjectWithTree(headerStr);
      headerJson = parsedHeader.value;
      headerJsonTree = parsedHeader.tree;
    } catch (e) {
      headerJson = null;
      headerJsonTree = null;
    }
  }

  // PAYLOAD: igual
  if (validateBase64UrlPart(payloadB64)) {
    try {
      const parsedPayload = parseJsonObjectWithTree(payloadStr);
      payloadJson = parsedPayload.value;
      payloadJsonTree = parsedPayload.tree;
    } catch (e) {
      payloadJson = null;
      payloadJsonTree = null;
    }
  }

  return {
    header,
    payload,
    signatureB64,
    parts: { headerB64, payloadB64, signatureB64 },
    raw: { headerStr, payloadStr },
    headerJson,
    payloadJson,
    headerJsonTree,
    payloadJsonTree
  };
}
