// tests/jwt.spec.js
import request from "supertest";
import app from "../server.js"; // exporta app desde server.js (ver nota)
import { base64UrlEncode, signHmac } from "../services/jwt.service.js";

describe("JWT Analyzer", () => {
  test("encode + analyze + verify HS256 válido", async () => {
    const header = { alg: "HS256", typ: "JWT" };
    const payload = { sub: "user1", iat: 1516239022, exp: Math.floor(Date.now()/1000)+3600 };
    const secret = "x".repeat(32);

    const enc = await request(app).post("/api/encode").send({ header, payload, secret, algorithm: "HS256" }).expect(200);
    const token = enc.body.token;

    const ana = await request(app).post("/api/comprehensive-analysis").send({ token, secret }).expect(200);
    expect(ana.body.semantic.signatureVerified).toBe(true);
    expect(ana.body.syntactic.isValid).toBe(true);
  });

  test("firma inválida", async () => {
    const headerB64 = base64UrlEncode(JSON.stringify({ alg: "HS256", typ: "JWT" }));
    const payloadB64 = base64UrlEncode(JSON.stringify({ sub: "u" }));
    const signature = signHmac(headerB64, payloadB64, "secret-1".repeat(4), "HS256");
    const token = `${headerB64}.${payloadB64}.${signature}`;

    const res = await request(app).post("/api/verify").send({ token, secret: "otro-secret".repeat(4) }).expect(200);
    expect(res.body.signatureVerified).toBe(false);
  });

  test("token malformado (dos partes)", async () => {
    const bad = "abc.def";
    const res = await request(app).post("/api/analyze").send({ token: bad });
    expect(res.status).toBe(400);
  });

  test("token expirado (semántica)", async () => {
    const header = { alg: "HS256", typ: "JWT" };
    const payload = { sub: "u", exp: 1 };
    const secret = "y".repeat(32);

    const enc = await request(app).post("/api/encode").send({ header, payload, secret, algorithm: "HS256" }).expect(200);
    const token = enc.body.token;

    const ana = await request(app).post("/api/comprehensive-analysis").send({ token, secret }).expect(200);
    expect(ana.body.semantic.valid).toBe(false);
    expect(ana.body.semantic.errors.some(e => e.includes("exp"))).toBe(true);
  });
});
