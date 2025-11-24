// services/lexicalJwt.service.js
import { validateBase64UrlPart } from "./base64url.service.js";

/** ======================
 *  Análisis Léxico
 *  ====================== */
export function lexicalAnalysis(token) {
  const parts = token.split("."); // Divide por puntos (incluye vacíos al inicio/fin)
  const table = [];
  const tokens = [];
  let idx = 1;

  const pushRow = (lexeme, tokenType, estado) => {
    table.push({
      index: idx++,
      lexeme,
      token: tokenType,
      estado
    });
  };

  const pushToken = (type, lexeme) => {
    tokens.push({ type, lexeme });
  };

  // Recorremos TODOS los "bloques" separados por '.'
  parts.forEach((part, i) => {
    // --- SEGMENTO ---
    if (part && part !== "") {
      // Hay contenido, validamos Base64URL
      if (!validateBase64UrlPart(part)) {
        pushRow(part, "SEGMENT", "❌ ERROR Base64URL inválido");
      } else {
        pushRow(part, "SEGMENT", "🟢 Válido");
      }
      // Sintácticamente sigue siendo un SEGMENT, aunque léxicamente tenga error
      pushToken("SEGMENT", part);
    } else {
      // Bloque vacío → error léxico de segmento vacío
      pushRow("(vacío)", "SEGMENT", "❌ ERROR BLOQUE VACÍO");
      pushToken("SEGMENT", "(vacío)");
    }

    // --- DOT (el punto que separa este bloque del siguiente) ---
    if (i < parts.length - 1) {
      pushRow(".", "DOT", "🟢 Válido");
      pushToken("DOT", ".");
    }
  });

  // --- EOF ---
  pushRow("EOF", "EOF", "—");
  pushToken("EOF", "EOF");

  return { table, tokens };
}
