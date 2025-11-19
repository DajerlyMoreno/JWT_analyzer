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
  try {
    const { token, secret } = req.body;
    const parsed = parseJwt(token);

    const lexical = lexicalAnalysis(token);
    const syntactic = syntacticAnalysis(parsed);
    const semantic = semanticAnalysis(parsed, secret || null);

    let pumping;
    try {
      pumping = pumpingLemmaAnalysis(token);
    } catch (e) {
      pumping = { error: `pumping failed: ${e.message}` };
    }

    const response = { lexical, syntactic, semantic, pumping };

    // ❌ YA NO SE GUARDA EN MONGO
    // Antes: History.create({ type: "analysis", ... })

    res.json(response);
  } catch (err) {
    console.error("❌ /comprehensive-analysis error:", err);
    res.status(400).json({ error: err.message });
  }
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

    // ❌ Antes se guardaba como type: "analysis"
    // await History.create({ type: "analysis", ... });

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
