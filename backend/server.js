// server.js
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { connectDB } from "./config/db.js";
import jwtRoutes from "./routes/jwt.routes.js";

dotenv.config();

const app = express();

// CORS
app.use(cors({
  origin: ["http://127.0.0.1:5500", "http://localhost:5173"],
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type"],
}));

app.use(express.json());

// 🔌 Conexión a MongoDB (segura, no revienta Lambda si falla)
connectDB();

// Rutas de la API
app.use("/api", jwtRoutes);

// Ruta simple para probar raíz
app.get("/", (req, res) => {
  res.json({ message: "JWT Analyzer API online" });
});

export default app;
