// services/syntacticJwt.service.js
import { runJwtAutomaton } from "./automata.service.js";
import { validateBase64UrlPart } from "./base64url.service.js";

/** ======================
 *  Análisis Sintáctico (verificador CFG)
 *  ====================== */
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
    automaton
  };
}
