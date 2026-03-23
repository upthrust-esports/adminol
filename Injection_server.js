// ============================================================
//  FF CG ENGINE — INJECTION / LICENSE SERVER
//  Run this on your remote VPS (not on the tournament PC)
//  Keep this file private — never share it
// ============================================================

const http = require("http");
const crypto = require("crypto");

// ── APPROVED IPs ─────────────────────────────────────────────
// Add your tournament venue static IPs or home IPs here
// These are obfuscated — actual IPs stored as SHA256 hashes
// To add an IP: node -e "const c=require('crypto');console.log(c.createHash('sha256').update('1.2.3.4').digest('hex'))"

const _a = [
  // Example — replace with your real IP hashes:
  // "aaaaabbbbcccc...64charhex" // venue IP 1
  // "aaaaabbbbcccc...64charhex" // home IP
  "b74307fdae3fba78cc9003d260587c7d0a3f28e1e9b9b850f9cb84948b90b2d6",
  "4d8dd950571928fece6534b4615770a42b443ee20b9e060ba2f721354a460d5a",
  "3e756943455d85ad43c492ff2999d680b991dd785e0dd764076ac612100b815f", // 192.168.1.38
  "12ca17b49af2289436f303e0166030a21e525d266e209267433801a8fd4071a0", //
  "d16ba92ae1b2cac526d360d59036f6e6c708d59b6112b7875b3995f79c3cc279",
];

// ── SECRET HANDSHAKE ─────────────────────────────────────────
// Must match _K in server.js — change this to something random
const _K = "ff_cg_k3y_ch4ng3_th1s_n0w_xX9z";

// ── TOKEN CACHE ───────────────────────────────────────────────
// Issued tokens expire after 2 hours
const _tok = new Map(); // token → { ip, exp }

function _h(s) {
  return crypto.createHash("sha256").update(s).digest("hex");
}

function _clean() {
  const now = Date.now();
  for (const [k, v] of _tok) if (v.exp < now) _tok.delete(k);
}

// ── SERVER ────────────────────────────────────────────────────
const PORT = process.env.PORT || 7331;

http.createServer((req, res) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Cache-Control", "no-store");

  // Only one endpoint — everything else 404
  if (req.method !== "POST" || req.url !== "/v") {
    res.writeHead(404); res.end("Not found"); return;
  }

  let body = "";
  req.on("data", d => { body += d; if (body.length > 512) { res.writeHead(400); res.end(); } });
  req.on("end", () => {
    try {
      const { k, t } = JSON.parse(body);

      // Validate secret key
      if (!k || _h(k) !== _h(_K)) {
        res.writeHead(403); res.end("x"); return;
      }

      // Get real client IP (works behind nginx/cloudflare)
      const ip = (
        req.headers["cf-connecting-ip"] ||
        req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
        req.socket.remoteAddress ||
        ""
      ).replace("::ffff:", "");

      const ipHash = _h(ip);
      _clean();

      // Check if IP is approved
      if (!_a.includes(ipHash)) {
        console.log(`[DENY] ${new Date().toISOString()} ip=${ip} hash=${ipHash.slice(0,8)}...`);
        res.writeHead(403); res.end("x"); return;
      }

      // Issue or refresh token
      const token = crypto.randomBytes(32).toString("hex");
      _tok.set(token, { ip, exp: Date.now() + 2 * 60 * 60 * 1000 });

      console.log(`[GRANT] ${new Date().toISOString()} ip=${ip}`);
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ ok: true, token, exp: Date.now() + 7200000 }));

    } catch(e) {
      res.writeHead(400); res.end("x");
    }
  });
}).listen(PORT, () => {
  console.log(`[INJ] License server running on :${PORT}`);
  console.log(`[INJ] ${_a.length} approved IP hash(es) loaded`);
});
