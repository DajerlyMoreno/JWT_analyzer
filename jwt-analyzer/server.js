import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import path from "path"; 
import { fileURLToPath } from 'url'; 
import { connectDB } from "./config/db.js";
import jwtRoutes from "./routes/jwt.routes.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config();
const app = express();
app.use(cors({
  origin: ["http://127.0.0.1:5500", "http://localhost:5173"],
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type"],
}));
app.use(express.json());

//app.use(express.static(path.join(__dirname, '..', 'frontend'))); 

// Conexión a MongoDB
//connectDB();

// Rutas de la API (solo bajo el prefijo /api)
app.use("/api", jwtRoutes); 

//const PORT = process.env.PORT || 3000;

// Exporta app para tests
export default app;



