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
      header: parsed.header,
      payload: parsed.payload,
      parts: parsed.parts
    };

    await History.create({ type: "decode", requestData: { token }, responseData: response });
    res.json(response);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
};

/** ========== ANÁLISIS COMPLETO ========== */
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

    await History.create({
      type: "analysis",
      requestData: { token, withSecret: Boolean(secret) },
      responseData: response
    });

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

    // Por seguridad NO guardamos el secret en responseData
    const response = { token, algorithm };

    await History.create({
      type: "encode",
      requestData: { header, payload, algorithm, withSecret: Boolean(secret) },
      responseData: response
    });

    res.json(response);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
};

/** ========== VERIFICACIÓN (firma) ========== */
export const verifySignature = async (req, res) => {
  try {
    const { token, secret } = req.body;
    const parsed = parseJwt(token);
    const { headerB64, payloadB64, signatureB64 } = parsed.parts;
    const alg = parsed.header?.alg || "HS256";

    const ok = verifyHmac(headerB64, payloadB64, signatureB64, secret, alg);

    const response = { algorithm: alg, signatureVerified: ok };
    await History.create({ type: "analysis", requestData: { verify: true }, responseData: response });
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
