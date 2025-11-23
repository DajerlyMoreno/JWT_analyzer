// controllers/jwt.controller.js
import History from "../models/History.js";
import {
  parseJwt,
  lexicalAnalysis,
  syntacticAnalysis,
  semanticAnalysis,
  signHmac,
  base64UrlEncode,
  verifyHmac,
  validateBase64UrlPart
} from "../services/jwt.service.js";
import { runJwtAutomaton } from "../services/automata.service.js";


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
      header: parsed.header,
      payload: parsed.payload,
      parts: parsed.parts,
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
// ⚠️ Tu frontend llama a /api/comprehensive-analysis, así que en las rutas
// asegúrate de tener algo como:
// router.post("/api/comprehensive-analysis", fullAnalysis);
export const fullAnalysis = async (req, res) => {
  const { token, secret } = req.body;

  if (!token || typeof token !== "string") {
    return res.status(400).json({ error: "Debes enviar un token." });
  }

  // 1) Siempre construimos la tabla léxica
  const lexical = lexicalAnalysis(token);

  let parsed = null;
  let syntactic = { grammar: "", isValid: false, errors: [] };
  let semantic = null;

  try {
    // 2) Intentamos parsear
    parsed = parseJwt(token);

    // Le pasamos también el token crudo para que el autómata pueda usarse
    syntactic = syntacticAnalysis(parsed, token);

    // 3) Análisis semántico con secret (para verificar firma)
    semantic = semanticAnalysis(parsed, syntactic.isValid, secret);
  } catch (e) {
    // Si algo truena (JSON inválido, etc.) lo agregamos como error sintáctico
    syntactic.errors.push(e.message);
  }

  // 4) Respondemos SIEMPRE con la estructura completa
  res.json({ lexical, syntactic, semantic });
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
