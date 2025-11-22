// services/automata.service.js

export const jwtAutomaton = {
  description: "AFD que reconoce la estructura base de un JWT: HEADER.PAYLOAD.SIGNATURE",
  alphabet: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.",
  states: ["q0", "qHeader", "qPayload", "qSignature", "qError"],
  startState: "q0",
  acceptStates: ["qSignature"],
  transitions: {
    q0:       { base64url: "qHeader",   ".": "qError" },
    qHeader:  { base64url: "qHeader",   ".": "qPayload" },
    qPayload: { base64url: "qPayload",  ".": "qSignature" },
    qSignature: { base64url: "qSignature", ".": "qError" },
    qError:   { base64url: "qError",    ".": "qError" }
  }
};

// Regex para un carácter Base64URL (SIN el punto)
const RX_B64URL_CHAR = /^[A-Za-z0-9\-_]$/;

/**
 * Ejecuta el AFD sobre un token JWT completo (string).
 * Devuelve si es aceptado, el estado final, la traza, etc.
 */
export function runJwtAutomaton(token) {
  const { startState, acceptStates, transitions } = jwtAutomaton;

  let current = startState;
  const path = [{
    index: -1,
    char: null,
    symbol: "(start)",
    from: null,
    to: current
  }];

  let errorPosition = null;
  let errorReason = null;

  for (let i = 0; i < token.length; i++) {
    const ch = token[i];
    let symbol;

    if (ch === ".") {
      symbol = ".";
    } else if (RX_B64URL_CHAR.test(ch)) {
      symbol = "base64url";
    } else {
      symbol = "other"; // carácter que no pertenece al alfabeto
    }

    const stateTransitions = transitions[current] || {};
    let next = stateTransitions[symbol];

    // Si no hay transición definida o símbolo "other", vamos a qError
    if (!next || symbol === "other") {
      next = "qError";
    }

    path.push({ index: i, char: ch, symbol, from: current, to: next });
    current = next;

    // Guardamos el primer error "real"
    if (current === "qError" && errorPosition === null) {
      errorPosition = i;
      if (symbol === "other") {
        errorReason = `Carácter '${ch}' no pertenece al alfabeto Base64URL/JWT`;
      } else {
        errorReason = `Transición inválida con símbolo '${symbol}' desde el estado '${path[path.length - 2].from}'`;
      }
    }
  }

  const accepted = acceptStates.includes(current);

  // Si terminó en estado no aceptado pero sin haber caído en qError explícito
  if (!accepted && errorPosition === null) {
    errorPosition = token.length;
    errorReason = `La cadena terminó en el estado no aceptado '${current}'`;
  }

  return {
    description: jwtAutomaton.description,
    accepted,
    finalState: current,
    path,           // traza de (índice, carácter, símbolo, from, to)
    errorPosition,  // índice donde se detectó el problema (o fin de cadena)
    errorReason     // explicación corta
  };
}
