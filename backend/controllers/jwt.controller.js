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
  pumpingLemmaAnalysis
} from "../services/jwt.service.js";

/** ========== DECODIFICACIÓN ========== */
export const analyzeToken = async (req, res) => {
  try {
    const { token } = req.body;
    const parsed = parseJwt(token);

    const response = {
      token,
      header: parsed.header,
      payload: parsed.payload,
      parts: parsed.parts
    };

    // ✅ Guardamos SOLO decode, con campos clave
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

/** ========== ANÁLISIS COMPLETO (NO SE GUARDA EN BD) ========== */
export const fullAnalysis = async (req, res) => {
  const { token, secret } = req.body;

  // 📌 1) Siempre construimos la tabla léxica
  const lexical = lexicalAnalysis(token);

  let parsed = null;
  let syntactic = { grammar: "", isValid: false, errors: [] };
  let semantic = null;
  let pumping = null;

  try {
    // 📌 2) Intentamos parsear, pero si falla NO devolvemos 400
    parsed = parseJwt(token);
    syntactic = syntacticAnalysis(parsed);
    semantic = semanticAnalysis(parsed, secret || null);
  } catch (e) {
    // 📌 3) Metemos el error como error sintáctico
    syntactic.errors.push(e.message);
  }

  try {
    pumping = pumpingLemmaAnalysis(token);
  } catch (e) {
    pumping = { error: `pumping failed: ${e.message}` };
  }

  // 📌 4) Respondemos SIEMPRE con la estructura completa
  res.json({ lexical, syntactic, semantic, pumping });
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
    const parsed = parseJwt(token);
    const { headerB64, payloadB64, signatureB64 } = parsed.parts;
    const alg = parsed.header?.alg || "HS256";

    const ok = verifyHmac(headerB64, payloadB64, signatureB64, secret, alg);

    const response = { algorithm: alg, signatureVerified: ok };


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
    console.log("🗑️ DELETE /api/history llamado"); // <--- para verificar que entra aquí

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
