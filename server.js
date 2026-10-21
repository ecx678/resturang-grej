
const express = require("express");
const http = require("http");
const path = require("path");
const crypto = require("crypto");
const { Server } = require("socket.io");
const { rateLimit } = require("express-rate-limit");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 3000;
const ACCESS_CODE = process.env.ACCESS_CODE;
const SESSION_SECRET = process.env.SESSION_SECRET;

if (!ACCESS_CODE || !SESSION_SECRET ||
    SESSION_SECRET.length < 32) {
  throw new Error(
    "Konfigurera ACCESS_CODE och SESSION_SECRET."
  );
}

app.use(express.json({ limit: "10kb" }));

app.use(express.static(path.join(__dirname, "public")));

const sign = (payload) =>
  crypto.createHmac("sha256", SESSION_SECRET)
    .update(payload)
    .digest("hex");

function createToken() {
  const payload = Buffer.from(JSON.stringify({
    expires: Date.now() + 12 * 60 * 60 * 1000
  })).toString("base64url");

  return `${payload}.${sign(payload)}`;
}

function validToken(token) {
  if (typeof token !== "string") return false;

  const parts = token.split(".");
  if (parts.length !== 2) return false;

  const [payload, signature] = parts;
  const expected = sign(payload);
  const a = Buffer.from(signature);
  const b = Buffer.from(expected);

  if (a.length !== b.length ||
      !crypto.timingSafeEqual(a, b)) return false;

  try {
    const data = JSON.parse(
      Buffer.from(payload, "base64url").toString()
    );
    return Number.isFinite(data.expires) &&
      data.expires > Date.now();
  } catch {
    return false;
  }
}

app.post("/api/login", (req, res) => {
  const code = req.body?.code;

  if (typeof code !== "string" ||
      code.length > 200 ||
      code !== ACCESS_CODE) {
    return res.status(401).json({
      error: "Fel åtkomstkod."
    });
  }

  res.json({ token: createToken() });
});

io.use((socket, next) => {
  if (validToken(socket.handshake.auth?.token)) {
    return next();
  }
  next(new Error("Logga in för att ansluta."));
});

io.on("connection", () => {
  console.log("Mottagare ansluten.");
});

app.use("/api/bestallning", rateLimit({
  windowMs: 60 * 1000,
  limit: 30,
  standardHeaders: "draft-7",
  legacyHeaders: false
}));

app.post("/api/bestallning", (req, res) => {
  const artikel = req.body?.artikel;
  const antal = Number(req.body?.antal);

  if (typeof artikel !== "string" ||
      !artikel.trim() ||
      artikel.length > 100 ||
      !Number.isInteger(antal) ||
      antal < 1 || antal > 100) {
    return res.status(400).json({
      error: "Kontrollera artikel och antal."
    });
  }

  const order = {
    id: crypto.randomUUID(),
    artikel: artikel.trim(),
    antal,
    tid: new Date().toISOString()
  };

  io.emit("ny-bestallning", order);

  console.log("Ny beställning:", order);
  res.status(201).json({
    success: true,
    bestallning: order
  });
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Servern kör på port ${PORT}`);
});
