// services/semanticJwt.service.js
import { verifyHmac } from "./hmac.service.js";

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
      skipped: true
    };
  }

  const header = parsed.header || {};
  const payload = parsed.payload || {};
  const errors = [];
  const warnings = [];

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

  ["iss", "sub", "name", "jti"].forEach(k => {
    if (payload[k] !== undefined && typeof payload[k] !== "string") {
      errors.push(`${k} debe ser string`);
    }
  });

  if (payload.aud !== undefined) {
    const aud = payload.aud;
    const ok =
      typeof aud === "string" ||
      (Array.isArray(aud) && aud.every(x => typeof x === "string"));
    if (!ok) {
      errors.push("aud debe ser string o arreglo de strings");
    }
  }

  if (payload.admin !== undefined && typeof payload.admin !== "boolean") {
    errors.push("admin debe ser boolean (true/false)");
  }

  if (payload.sub === undefined) {
    warnings.push(
      "El token no incluye 'sub' (Subject). Es opcional según la RFC 7519, " +
      "pero muchas APIs lo usan para identificar al usuario."
    );
  }

  if (payload.exp === undefined) {
    warnings.push(
      "El token no incluye 'exp' (Expiration Time). Es opcional, " +
      "pero en tokens de autenticación se recomienda fuertemente " +
      "tener fecha de expiración."
    );
  }

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

  return {
    valid: errors.length === 0 && (signatureVerified !== false),
    errors,
    warnings,
    signatureVerified,
    algorithm: header.alg || null,
    symbolTable,
    skipped: false
  };
}
