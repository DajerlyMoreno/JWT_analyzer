// server.js
import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import { connectDB } from "./config/db.js";
import jwtRoutes from "./routes/jwt.routes.js";

dotenv.config();
const app = express();
app.use(cors());
app.use(express.json());

// Conexión a MongoDB
connectDB();

// Rutas
app.use("/api", jwtRoutes);

const PORT = process.env.PORT || 3000;

// Exporta app para tests
export default app;

// Solo levantar servidor si no está bajo test
if (process.env.JEST_WORKER_ID === undefined) {
  app.listen(PORT, () => console.log(`✅ Servidor en http://localhost:${PORT}`));
}
