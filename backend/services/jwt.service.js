// services/jwt.service.js
import crypto from "crypto";
import { runJwtAutomaton } from "./automata.service.js";


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

function safeJsonParse(str) {
  try { return JSON.parse(str); } catch { return null; }
}

export function validateBase64UrlPart(part) {
  if (typeof part !== "string" || part.length === 0) return false;
  return RX_B64URL.test(part);
}

/** ======================
 *  Parseo / estructura JWT
 *  ====================== */
export function parseJwt(token) {
  const parts = token.split(".");

  const [headerB64, payloadB64, signatureB64] = parts;

  // Decodificación + JSON
  const headerStr = base64UrlDecode(headerB64).toString("utf8");
  const payloadStr = base64UrlDecode(payloadB64).toString("utf8");

  const header = safeJsonParse(headerStr);
  const payload = safeJsonParse(payloadStr);

  //if (!header) throw new Error("HEADER no es JSON válido");
  //if (!payload) throw new Error("PAYLOAD no es JSON válido");

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
  const parts = token.split(".");   // divide en segmentos
  const table = [];
  let idx = 1;

  const push = (lexeme, tokenType, estado) => {
    table.push({
      index: idx++,
      lexeme,
      token: tokenType,
      estado
    });
  };

  const MAX_SEGMENTS = 3;  // HEADER, PAYLOAD, SIGNATURE
  let segments = 0;

  // 👉 Solo analizamos como máximo 3 segmentos (JWT estándar)
  for (let i = 0; i < parts.length && segments < MAX_SEGMENTS; i++) {
    const part = parts[i];

    // --- SEGMENTO ---
    if (part && part !== "") {
      if (!validateBase64UrlPart(part)) {
        push(part, "SEGMENT", "❌ ERROR Base64URL inválido");
      } else {
        push(part, "SEGMENT", "🟢 Válido");
      }
    } else {
      push("(vacío)", "SEGMENT", "❌ ERROR BLOQUE VACÍO");
    }

    segments++;

    // --- DOT entre segmentos (solo 2 puntos) ---
    if (segments < MAX_SEGMENTS && i < parts.length - 1) {
      push(".", "DOT", "🟢 Válido");
    }
  }
  
  // --- EOF ---
  push("EOF", "EOF", "—");

  return { table };
}


/** ======================
 *  Análisis Sintáctico (verificador CFG)
 *  ====================== */
// services/jwt.service.js

export function syntacticAnalysis(parsed, rawToken = null) {
  const grammar = `
S  -> J
J  -> H "." P "." Sg
H  -> Base64url(JSON)
P  -> Base64url(JSON)
Sg -> Base64url(firma)
  `.trim();

  const errors = [];
  let automaton = null;

  if (!parsed || !parsed.parts) {
    errors.push("Token incompleto o no se pudo parsear correctamente.");
    return {
      grammar,
      isValid: false,
      errors,
      derivation: [],
      parseTree: null,
      segments: null,
      automaton
    };
  }

  // 🧩 Validación de estructura: cantidad de segmentos
  if (rawToken) {
    const rawParts = rawToken.split(".");
    if (rawParts.length !== 3) {
      errors.push(
        `Estructura inválida: el token tiene ${rawParts.length} segmentos. Un JWT válido debe tener exactamente 3 (HEADER.PAYLOAD.SIGNATURE).`
      );
    }
  }
  
  // ✅ Ejecutar el autómata sobre el token crudo (si lo pasas)
  if (rawToken) {
    automaton = runJwtAutomaton(rawToken);
    if (!automaton.accepted) {
      errors.push(
        `Autómata rechaza el token en la posición ${automaton.errorPosition}: ${automaton.errorReason}`
      );
    }
  }

  const { headerB64, payloadB64, signatureB64 } = parsed.parts;

  // ... (resto de validaciones que ya tienes)
  if (!validateBase64UrlPart(headerB64)) {
    errors.push("HEADER no cumple Base64URL");
  }
  if (!validateBase64UrlPart(payloadB64)) {
    errors.push("PAYLOAD no cumple Base64URL");
  }
  if (!validateBase64UrlPart(signatureB64)) {
    errors.push("SIGNATURE no cumple Base64URL");
  }
  if (!parsed.header) {
    errors.push("HEADER no es JSON válido");
  }
  if (!parsed.payload) {
    errors.push("PAYLOAD no es JSON válido");
  }

  const isValid = errors.length === 0;

  const derivation = [
    "S",
    "J",
    'H "." P "." Sg',
    'Base64url(JSON) "." Base64url(JSON) "." Base64url(firma)',
    `${headerB64} "." ${payloadB64} "." ${signatureB64}`
  ];

  const parseTree = {
    symbol: "S",
    children: [
      {
        symbol: "J",
        rule: "S -> J",
        children: [
          {
            symbol: "H",
            rule: 'J -> H "." P "." Sg',
            children: [{ symbol: "Base64url(JSON)", value: headerB64 }]
          },
          { symbol: '"."', value: "." },
          {
            symbol: "P",
            children: [{ symbol: "Base64url(JSON)", value: payloadB64 }]
          },
          { symbol: '"."', value: "." },
          {
            symbol: "Sg",
            children: [{ symbol: "Base64url(firma)", value: signatureB64 }]
          }
        ]
      }
    ]
  };

  const segments = {
    headerB64,
    payloadB64,
    signatureB64,
    header: parsed.header || null,
    payload: parsed.payload || null,
    signatureRaw: signatureB64
  };

  return {
    grammar,
    isValid,
    errors,
    derivation,
    parseTree,
    segments,
    automaton   // 👈 para mostrar en el front la traza del AFD
  };
}



/* ======================================================
 *  Validación de Claims Temporales
 * ====================================================== */
function validateTimeClaims(
  payload,
  now = Math.floor(Date.now() / 1000),
  skew = 300
) {
  const errs = [];

  // exp
  if (typeof payload.exp === "number" && now - skew >= payload.exp)
    errs.push("exp expirado");

  // nbf
  if (typeof payload.nbf === "number" && now + skew < payload.nbf)
    errs.push("nbf aún no válido");

  // iat
  if (typeof payload.iat === "number" && payload.iat - skew > now)
    errs.push("iat en el futuro");

  // tipos
  ["exp", "nbf", "iat"].forEach(k => {
    if (payload[k] !== undefined && typeof payload[k] !== "number")
      errs.push(`${k} debe ser número (segundos Unix)`);
  });

  return errs;
}

/* ======================================================
 *  Algoritmos permitidos
 * ====================================================== */
function allowedAlg(alg) {
  return ["HS256", "HS384", "HS512"].includes(alg);
}

/* ======================================================
 *  Análisis Semántico Completo
 * ====================================================== */
export function semanticAnalysis(parsed, syntacticIsValid, secret = null) {

  if (!syntacticIsValid) {
    return {
      valid: false,
      errors: [
        "No se realizó el análisis semántico porque el análisis sintáctico presentó errores."
      ],
      warnings: [],
      signatureVerified: null,
      algorithm: parsed?.header?.alg || null,
      symbolTable: {
        header: {},
        payload: {}
      },
      skipped: true   // bandera útil para el front
    };
  }

  // 🔓 2) Si la sintaxis es válida, continuamos como antes
  const header = parsed.header || {};
  const payload = parsed.payload || {};
  const errors = [];
  const warnings = [];

  /* ------------------------
   * Claims obligatorios (TU TOKEN)
   * ------------------------ */
  const REQUIRED_CLAIMS = ["sub", "name", "admin", "iat"];

  REQUIRED_CLAIMS.forEach(c => {
    if (payload[c] === undefined)
      errors.push(`Claim obligatorio '${c}' ausente`);
  });

  /* ------------------------
   * Validación del HEADER
   * ------------------------ */
  if (!header.alg)
    errors.push("HEADER.alg es obligatorio");

  if (header.typ && header.typ !== "JWT")
    warnings.push(`HEADER.typ recomendado 'JWT', recibido: ${header.typ}`);

  if (header.alg && !allowedAlg(header.alg))
    errors.push(`Algoritmo no permitido: ${header.alg}`);

  /* ------------------------
   * Claims Estándar (tipos)
   * ------------------------ */
  const timeErrs = validateTimeClaims(payload);
  errors.push(...timeErrs);

  ["sub", "name"].forEach(k => {
    if (payload[k] !== undefined && typeof payload[k] !== "string")
      errors.push(`${k} debe ser string`);
  });

  if (payload.admin !== undefined && typeof payload.admin !== "boolean")
    errors.push("admin debe ser boolean (true/false)");

  /* ------------------------
   * Verificación criptográfica (opcional)
   * ------------------------ */
  let signatureVerified = null;
  if (secret) {
    try {
      signatureVerified = verifyHmac(
        parsed.parts.headerB64,
        parsed.parts.payloadB64,
        parsed.parts.signatureB64,
        secret,
        header.alg || "HS256"
      );
    } catch (e) {
      errors.push(`Error verificando firma: ${e.message}`);
      signatureVerified = false;
    }
  }

  /* ------------------------
   * Tabla de Símbolos
   * ------------------------ */
  const symbolTable = {
    header: Object.fromEntries(
      Object.entries(header).map(([k, v]) => [k, typeof v])
    ),
    payload: Object.fromEntries(
      Object.entries(payload).map(([k, v]) => [k, typeof v])
    )
  };

  /* ------------------------
   * Resultado final
   * ------------------------ */
  return {
    valid: errors.length === 0 && (signatureVerified !== false),
    errors,
    warnings,
    signatureVerified,
    algorithm: header.alg || null,
    symbolTable,
    skipped: false    // aquí explícitamente NO se omitió
  };
}
