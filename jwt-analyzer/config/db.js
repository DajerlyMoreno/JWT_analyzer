// config/db.js
import mongoose from "mongoose";

export const connectDB = async () => {
  try {
    const uri = process.env.MONGO_URI;

    if (!uri) {
      console.warn("⚠️ MONGO_URI no definida. Saltando conexión a Mongo.");
      return;
    }

    await mongoose.connect(uri);
    console.log("✅ MongoDB conectado");
  } catch (err) {
    console.error("❌ Error conectando a MongoDB:", err.message);
    // OJO: en Lambda NUNCA hagas process.exit()
  }
};
