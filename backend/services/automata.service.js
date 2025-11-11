// services/automata.service.js
export const jwtAutomaton = {
    description: "AFD que reconoce la estructura base de un JWT: HEADER.PAYLOAD.SIGNATURE",
    alphabet: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.",
    states: ["q0", "qHeader", "qPayload", "qSignature", "qError"],
    startState: "q0",
    acceptStates: ["qSignature"],
    transitions: {
      q0: { base64url: "qHeader", ".": "qError" },
      qHeader: { base64url: "qHeader", ".": "qPayload" },
      qPayload: { base64url: "qPayload", ".": "qSignature" },
      qSignature: { base64url: "qSignature", ".": "qError" },
      qError: { base64url: "qError", ".": "qError" }
    }
  };
  