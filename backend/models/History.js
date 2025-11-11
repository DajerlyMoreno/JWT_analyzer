// models/History.js
import mongoose from "mongoose";

const historySchema = new mongoose.Schema({
  type: { type: String, enum: ["decode", "encode", "analysis"], required: true },
  requestData: { type: Object },
  responseData: { type: Object },
  createdAt: { type: Date, default: Date.now }
});

export default mongoose.model("History", historySchema);
