// routes/jwt.routes.js
import express from "express";
import {
  analyzeToken,
  encodeToken,
  fullAnalysis,
  getHistory,
  verifySignature
} from "../controllers/jwt.controller.js";

const router = express.Router();

router.post("/analyze", analyzeToken);
router.post("/encode", encodeToken);
router.post("/comprehensive-analysis", fullAnalysis);
router.post("/verify", verifySignature);
router.get("/history", getHistory);

export default router;
