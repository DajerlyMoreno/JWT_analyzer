// controllers/jwt.controller.js
import History from "../models/History.js";
import {
  parseJwt,
  lexicalAnalysis,
  //syntacticAnalysis,
  semanticAnalysis,
  signHmac,
  base64UrlEncode,
  verifyHmac,
  validateBase64UrlPart
} from "../services/jwt.service.js";
import { runJwtAutomaton } from "../services/automata.service.js";
import { runSyntacticParserFromLexical } from "../services/jwtParser.service.js";


/** ========== DECODIFICACIÓN ========== */
export const analyzeToken = async (req, res) => {
  try {
    const { token } = req.body;
    if (!token || typeof token !== "string") {
      return res.status(400).json({ error: "Debes enviar un token." });
    }

    const parts = token.split(".");

    // Deben existir EXACTAMENTE 3 partes
    if (parts.length !== 3) {
      return res.status(400).json({
        error: `El token debe tener 3 segmentos (HEADER.PAYLOAD.SIGNATURE). Se detectaron: ${parts.length}`
      });
    }

    const [headerB64, payloadB64, signatureB64] = parts;
    
    // ⚠️ Validación estricta BASE64URL antes de decodificar
    if (!validateBase64UrlPart(headerB64)) {
      return res.status(400).json({ error: "HEADER contiene caracteres no permitidos Base64URL." });
    }
    if (!validateBase64UrlPart(payloadB64)) {
      return res.status(400).json({ error: "PAYLOAD contiene caracteres no permitidos Base64URL." });
    }
    if (!validateBase64UrlPart(signatureB64)) {
      return res.status(400).json({ error: "SIGNATURE contiene caracteres no permitidos Base64URL." });
    }

    // 🔍 Ejecutar autómata (estructura HEADER.PAYLOAD.SIGNATURE)
    const automaton = runJwtAutomaton(token);
    if (!automaton.accepted) {
      return res.status(400).json({
        error: `El autómata rechaza el token: ${automaton.errorReason}`,
        position: automaton.errorPosition
      });
    }

    // 🧩 Si todo está bien, ahora sí parseamos
    const parsed = parseJwt(token);

   const response = {
      token,

      // Datos decodificados visibles en el front
      header: parsed.header,
      payload: parsed.payload,
      signature: parsed.signature,

      // Segmentos
      parts: parsed.parts,

      // Texto JSON original (string, para mostrarlo bonito)
      headerJson: parsed.headerJson,
      payloadJson: parsed.payloadJson,

      // Árboles sintácticos JSON (para el futuro árbol visual)
      headerJsonTree: parsed.headerJsonTree,
      payloadJsonTree: parsed.payloadJsonTree,

      // Autómata de estructura
      automaton
    };


    // 📝 Guardamos en historial (solo decodificación)
    await History.create({
      type: "decode",
      token,
      header: parsed.header,
      payload: parsed.payload,
      secret: null,
      algorithm: parsed.header?.alg || null
    });

    res.json(response);

  } catch (err) {
    res.status(400).json({ error: err.message });
  }
};


/** ========== ANÁLISIS COMPLETO  ========== */

export const fullAnalysis = async (req, res) => {
  const { token, secret } = req.body;

  // 1. Análisis léxico
  const lexical = lexicalAnalysis(token);

  // 2. Parseo base del JWT (decodificación + parser JSON)
  let parsed = null;
  try {
    parsed = parseJwt(token);
  } catch (e) {
    return res.json({
      lexical,
      syntactic: { isValid: false, errors: ["Error al decodificar token: " + e.message] },
      semantic: null
    });
  }

  // 3. Parser sintáctico FORMAL del JWT
  const syntactic = runSyntacticParserFromLexical(lexical);

  // 4. Adjuntar árboles JSON desde parseJwt
  syntactic.jsonTrees = {
    header: parsed.headerJsonTree,
    payload: parsed.payloadJsonTree
  };

  // 5. Análisis semántico (opcional si la sintaxis es válida)
  const semantic = semanticAnalysis(parsed, syntactic.isValid, secret);

  return res.json({
    lexical,
    syntactic,
    semantic
  });
};




/** ========== CODIFICACIÓN ========== */
export const encodeToken = async (req, res) => {
  try {
    const { header, payload, secret, algorithm } = req.body;

    const headerB64 = base64UrlEncode(JSON.stringify(header));
    const payloadB64 = base64UrlEncode(JSON.stringify(payload));
    const signature = signHmac(headerB64, payloadB64, secret, algorithm);
    const token = `${headerB64}.${payloadB64}.${signature}`;

    const response = { token, algorithm };

    // ✅ Guardamos encode con todo lo que pediste
    await History.create({
      type: "encode",
      token,
      header,
      payload,
      secret,
      algorithm
    });

    res.json(response);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
};


/** ========== VERIFICACIÓN (firma) – NO GUARDAR EN BD ========== */
export const verifySignature = async (req, res) => {
  try {
    const { token, secret } = req.body;

    if (!token || typeof token !== "string") {
      return res.status(400).json({ error: "Debes enviar un token para verificar la firma." });
    }

    if (!secret || typeof secret !== "string") {
      return res.status(400).json({ error: "Debes enviar el secret para verificar la firma." });
    }

    const parts = token.split(".");
    if (parts.length !== 3) {
      return res.status(400).json({
        error: `El token debe tener 3 segmentos (HEADER.PAYLOAD.SIGNATURE). Se detectaron: ${parts.length}`
      });
    }

    // Parseamos JWT
    const parsed = parseJwt(token);
    if (!parsed || !parsed.header) {
      return res.status(400).json({
        error: "No se pudo parsear el token o el HEADER es inválido."
      });
    }

    const { headerB64, payloadB64, signatureB64 } = parsed.parts;
    const alg = parsed.header?.alg || "HS256";

    const ok = verifyHmac(headerB64, payloadB64, signatureB64, secret, alg);

    const response = { algorithm: alg, signatureVerified: ok };

    // 😶‍🌫️ No guardamos nada en BD, solo respondemos
    res.json(response);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
};


/** ========== HISTORIAL ========== */
export const getHistory = async (req, res) => {
  const data = await History.find().sort({ createdAt: -1 });
  res.json(data);
};


/** ========== LIMPIAR HISTORIAL ========== */
export const clearHistory = async (req, res) => {
  try {
    console.log("🗑️ DELETE /api/history llamado");

    const result = await History.deleteMany({});
    console.log("🗑️ Documentos borrados:", result.deletedCount);

    res.json({ 
      message: "Historial eliminado por completo", 
      deleted: result.deletedCount 
    });
  } catch (err) {
    console.error("❌ Error al borrar historial:", err);
    res.status(500).json({ error: err.message });
  }
};
