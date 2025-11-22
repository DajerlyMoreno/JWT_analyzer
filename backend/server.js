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
app.use(cors());
app.use(express.json());

app.use(express.static(path.join(__dirname, '..', 'frontend'))); 

// Conexión a MongoDB
connectDB();

// Rutas de la API (solo bajo el prefijo /api)
app.use("/api", jwtRoutes); 
app.use(express.json());

const PORT = process.env.PORT || 3000;

// Exporta app para tests
export default app;

// Solo levantar servidor si no está bajo test
if (process.env.JEST_WORKER_ID === undefined) {
  app.listen(PORT, () => console.log(`✅ Servidor en http://localhost:${PORT}`));
}


