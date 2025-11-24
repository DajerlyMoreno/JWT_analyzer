// routes/jwt.routes.js
import express from "express";
import {
  analyzeToken,
  encodeToken,
  fullAnalysis,
  getHistory,
  verifySignature,
  clearHistory
} from "../controllers/jwt.controller.js";

const router = express.Router();

router.post("/analyze", analyzeToken);
router.post("/encode", encodeToken);

// 🔍 Análisis completo (léxico / sintáctico / semántico / pumping)
router.post("/comprehensive-analysis", fullAnalysis);

// 🔐 Verificar solo firma
router.post("/verify", verifySignature);

// Historial
router.get("/history", getHistory);
router.delete("/history", clearHistory);

export default router;
