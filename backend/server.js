// server.js
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { connectDB } from "./config/db.js";
import jwtRoutes from "./routes/jwt.routes.js";
import mongoose from "mongoose";

dotenv.config();

const app = express();
const URI = process.env.MONGO_URI;

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

// Puerto de escucha
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en http://localhost:${PORT}`);
});
export default app;
