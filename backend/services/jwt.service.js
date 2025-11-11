// services/jwt.service.js
import crypto from "crypto";
import { jwtAutomaton } from "./automata.service.js";

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

const RX_B64URL = /^[A-Za-z0-9\-_]+$/;
export function validateBase64UrlPart(part) {
  return RX_B64URL.test(part) && part.length > 0;
}

function safeJsonParse(str) {
  try { return JSON.parse(str); } catch { return null; }
}

/** ======================
 *  Parseo / estructura JWT
 *  ====================== */
export function parseJwt(token) {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("El token debe tener exactamente 3 partes separadas por '.'");

  const [headerB64, payloadB64, signatureB64] = parts;

  // Validación léxica por parte (alfabeto Base64URL)
  if (!validateBase64UrlPart(headerB64)) throw new Error("HEADER no es Base64URL válido");
  if (!validateBase64UrlPart(payloadB64)) throw new Error("PAYLOAD no es Base64URL válido");
  if (!validateBase64UrlPart(signatureB64)) throw new Error("SIGNATURE no es Base64URL válido");

  // Decodificación + JSON
  const headerStr = base64UrlDecode(headerB64).toString("utf8");
  const payloadStr = base64UrlDecode(payloadB64).toString("utf8");

  const header = safeJsonParse(headerStr);
  const payload = safeJsonParse(payloadStr);

  if (!header) throw new Error("HEADER no es JSON válido");
  if (!payload) throw new Error("PAYLOAD no es JSON válido");

  return { header, payload, signatureB64, parts: { headerB64, payloadB64, signatureB64 }, raw: { headerStr, payloadStr } };
}

/** ======================
 *  Firmas HMAC
 *  ====================== */
const ALG_MAP = { HS256: "sha256", HS384: "sha384", HS512: "sha512" };

export function signHmac(headerB64, payloadB64, secret, algorithm = "HS256") {
  if (!ALG_MAP[algorithm]) throw new Error(`Algoritmo no soportado: ${algorithm}`);
  const hmac = crypto.createHmac(ALG_MAP[algorithm], secret);
  hmac.update(`${headerB64}.${payloadB64}`);
  return base64UrlEncode(hmac.digest());
}

export function verifyHmac(headerB64, payloadB64, signatureB64, secret, algorithm = "HS256") {
  if (!ALG_MAP[algorithm]) throw new Error(`Algoritmo no soportado: ${algorithm}`);
  const expected = signHmac(headerB64, payloadB64, secret, algorithm);
  const a = Buffer.from(expected);
  const b = Buffer.from(signatureB64);
  if (a.length !== b.length) return false;
  // comparación tiempo-constante
  return crypto.timingSafeEqual(a, b);
}

/** ======================
 *  Análisis Léxico
 *  ====================== */
export function lexicalAnalysis(token) {
  const tokens = [];
  let currentLexeme = "";
  let part = 0;
  for (let c of token) {
    if (c === ".") {
      tokens.push({ type: part === 0 ? "HEADER" : "PAYLOAD", value: currentLexeme, validB64Url: validateBase64UrlPart(currentLexeme) });
      currentLexeme = "";
      part++;
    } else {
      // base64url o punto
      const isAllowed = /[A-Za-z0-9\-_]/.test(c);
      if (!isAllowed) {
        tokens.push({ type: "ERROR", value: c, message: "Carácter fuera del alfabeto Base64URL" });
      }
      currentLexeme += c;
    }
  }
  if (currentLexeme) tokens.push({ type: "SIGNATURE", value: currentLexeme, validB64Url: validateBase64UrlPart(currentLexeme) });

  return {
    tokens,
    automaton: jwtAutomaton,
    summary: {
      dots: (token.match(/\./g) || []).length,
      parts: tokens.filter(t => ["HEADER", "PAYLOAD", "SIGNATURE"].includes(t.type)).length,
    }
  };
}

/** ======================
 *  Análisis Sintáctico (verificador CFG)
 *  ====================== */
export function syntacticAnalysis(parsed) {
  // Gramática informal/didáctica
  const grammar = `
S -> J
J -> H "." P "." Sg
H -> Base64url(JSON)
P -> Base64url(JSON)
Sg -> Base64url(firma)
  `.trim();

  // Verificación estructural (descendente simple)
  const isValid =
    typeof parsed?.parts?.headerB64 === "string" &&
    typeof parsed?.parts?.payloadB64 === "string" &&
    typeof parsed?.parts?.signatureB64 === "string" &&
    validateBase64UrlPart(parsed.parts.headerB64) &&
    validateBase64UrlPart(parsed.parts.payloadB64) &&
    validateBase64UrlPart(parsed.parts.signatureB64) &&
    parsed.header && parsed.payload;

  const errors = [];
  if (!validateBase64UrlPart(parsed.parts.headerB64)) errors.push("HEADER no cumple Base64URL");
  if (!validateBase64UrlPart(parsed.parts.payloadB64)) errors.push("PAYLOAD no cumple Base64URL");
  if (!validateBase64UrlPart(parsed.parts.signatureB64)) errors.push("SIGNATURE no cumple Base64URL");
  if (!parsed.header) errors.push("HEADER no es JSON válido");
  if (!parsed.payload) errors.push("PAYLOAD no es JSON válido");

  return { grammar, isValid, errors };
}

/** ======================
 *  Utilidades semánticas
 *  ====================== */
function validateTimeClaims(payload, now = Math.floor(Date.now() / 1000), skew = 300) {
  const errs = [];
  if (typeof payload.exp === "number" && now - skew >= payload.exp) errs.push("exp expirado");
  if (typeof payload.nbf === "number" && now + skew < payload.nbf) errs.push("nbf aún no válido");
  if (typeof payload.iat === "number" && payload.iat - skew > now) errs.push("iat en el futuro");
  // tipos
  ["exp", "nbf", "iat"].forEach(k => {
    if (payload[k] !== undefined && typeof payload[k] !== "number") errs.push(`${k} debe ser número (segundos Unix)`);
  });
  return errs;
}

function allowedAlg(alg) {
  return ["HS256", "HS384", "HS512"].includes(alg);
}

/** ======================
 *  Análisis Semántico
 *  ====================== */
export function semanticAnalysis(parsed, secret = null) {
  const header = parsed.header || {};
  const payload = parsed.payload || {};
  const errors = [];
  const warnings = [];

  // Header obligatorio
  if (!header.alg) errors.push("HEADER.alg es obligatorio");
  if (header.typ && header.typ !== "JWT") warnings.push(`HEADER.typ recomendado "JWT", recibido: ${header.typ}`);
  if (header.alg && !allowedAlg(header.alg)) errors.push(`Algoritmo no permitido: ${header.alg}`);

  // Claims estándar
  const timeErrs = validateTimeClaims(payload);
  errors.push(...timeErrs);

  // Tipos comunes
  if (payload.aud && typeof payload.aud !== "string" && !Array.isArray(payload.aud)) {
    errors.push("aud debe ser string o array de strings");
  }
  ["iss","sub","jti"].forEach(k => {
    if (payload[k] !== undefined && typeof payload[k] !== "string") errors.push(`${k} debe ser string`);
  });

  // Verificación criptográfica (si se provee secret)
  let signatureVerified = null;
  if (secret) {
    try {
      signatureVerified = verifyHmac(parsed.parts.headerB64, parsed.parts.payloadB64, parsed.parts.signatureB64, secret, header.alg || "HS256");
    } catch (e) {
      errors.push(`Error verificando firma: ${e.message}`);
      signatureVerified = false;
    }
  }

  return {
    valid: errors.length === 0 && (signatureVerified !== false),
    errors,
    warnings,
    signatureVerified,
    algorithm: header.alg || null,
    symbolTable: {
      header: Object.fromEntries(Object.entries(header).map(([k,v]) => [k, typeof v])),
      payload: Object.fromEntries(Object.entries(payload).map(([k,v]) => [k, typeof v]))
    }
  };
}

/** ======================
 *  Pumping lemma (didáctico)
 *  ====================== 
 *  Lenguaje Regular L = base64url+ "." base64url+ "." base64url+
 *  Retorna una descomposición x y z para |y|>0, |xy|<=p, con p=mínimo 5
 */
// Lenguaje didáctico: L = base64url+ "." base64url+ "." base64url+
export function pumpingLemmaAnalysis(token, p = 5) {
  const regex = /^([A-Za-z0-9\-_]+)\.([A-Za-z0-9\-_]+)\.([A-Za-z0-9\-_]+)$/;
  const m = regex.exec(token);
  const inLanguage = Boolean(m);

  // Resultado base (sin fallar)
  const base = {
    language: "L = base64url+ '.' base64url+ '.' base64url+",
    pumpingLength: p,
    inLanguage,
    decomposition: null
  };

  if (!inLanguage) return base;
  if (token.length < p) return { ...base, note: "Token más corto que p; no se aplica descomposición." };

  // Tomamos y como el PRIMER carácter del primer segmento (garantiza |y| >= 1)
  const first = m[1];
  const y = first.charAt(0);
  if (!y) return { ...base, note: "Primer segmento vacío (no debería pasar con la regex)." };

  const x = "";                           // elegimos x vacío para simplificar y asegurar |xy|<=p
  const rest = first.slice(1) + `.${m[2]}.${m[3]}`;  // lo que queda del primer segmento + ".segundo.tercero"
  const zStr = rest;                      // <- z es la “cola” restante

  // Construimos las cadenas bombeadas sin usar ninguna variable no declarada
  const pumped2 = y.repeat(2) + zStr;     // duplica y
  const pumped0 = "" + zStr;              // elimina y

  return {
    ...base,
    decomposition: {
      x,
      y,
      z: zStr,
      check: {
        yLength: y.length,
        xyLength: (x + y).length,
        pumped2,
        pumped0
      }
    }
  };
}
