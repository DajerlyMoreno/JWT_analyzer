// models/History.js
import mongoose from "mongoose";

const historySchema = new mongoose.Schema({
  type: { 
    type: String, 
    enum: ["decode", "encode"], 
    required: true 
  },

  // Siempre guardamos el token ya armado o recibido
  token: { 
    type: String, 
    required: true 
  },

  // Header y payload como objetos JSON
  header: { 
    type: Object, 
    required: false 
  },

  payload: { 
    type: Object, 
    required: false 
  },

  // Secret (contraseña) – opcional (solo existe en encode normalmente)
  secret: { 
    type: String, 
    required: false 
  },

  // Algoritmo usado (HS256, HS384, etc.)
  algorithm: { 
    type: String, 
    required: false 
  },

  createdAt: { 
    type: Date, 
    default: Date.now 
  }
});

export default mongoose.model("History", historySchema);
