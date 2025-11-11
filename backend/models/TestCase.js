// models/TestCase.js
import mongoose from "mongoose";

const testCaseSchema = new mongoose.Schema({
  category: { type: String, enum: ["valid", "expired", "bad-signature", "malformed", "missing-claims", "bad-types"], required: true },
  input: {
    token: { type: String },
    header: { type: Object },
    payload: { type: Object },
    algorithm: { type: String },
    secret: { type: String } // opcional; NO devolver al cliente
  },
  expected: {
    signatureVerified: { type: Boolean, default: null },
    semanticValid: { type: Boolean, default: null },
    syntacticValid: { type: Boolean, default: null }
  },
  result: {
    passed: { type: Boolean, default: null },
    details: { type: Object }
  },
  createdAt: { type: Date, default: Date.now }
});

export default mongoose.model("TestCase", testCaseSchema);
