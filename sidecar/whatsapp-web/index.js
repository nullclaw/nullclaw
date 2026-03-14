"use strict";

// NullClaw WhatsApp Web Sidecar
// Bridges WhatsApp Web (via Baileys) to NullClaw's gateway webhook.
//
// Config via environment variables:
//   NULLCLAW_GATEWAY_URL  - NullClaw gateway URL (default: http://127.0.0.1:8080)
//   SIDECAR_PORT          - HTTP port for this sidecar (default: 7100)
//   SIDECAR_AUTH_TOKEN    - Shared secret for authenticating requests (required)
//   WA_CREDENTIALS_DIR    - Credential storage dir (default: ~/.nullclaw/credentials/whatsapp_web)
//   WA_ALLOW_FROM         - Comma-separated phone allowlist (default: * = all)
//   WA_GROUP_POLICY       - "open", "allowlist", or "disabled" (default: allowlist)
//   WA_GROUP_ALLOW_FROM   - Comma-separated group phone allowlist (falls back to WA_ALLOW_FROM)

const http = require("http");
const path = require("path");
const fs = require("fs");
const qrcodeTerminal = require("qrcode-terminal");

const crypto = require("crypto");
const os = require("os");

let makeWASocket, useMultiFileAuthState, DisconnectReason, makeCacheableSignalKeyStore, fetchLatestBaileysVersion, downloadMediaMessage;

async function loadBaileys() {
  const baileys = await import("@whiskeysockets/baileys");
  makeWASocket = baileys.default || baileys.makeWASocket;
  useMultiFileAuthState = baileys.useMultiFileAuthState;
  DisconnectReason = baileys.DisconnectReason;
  makeCacheableSignalKeyStore = baileys.makeCacheableSignalKeyStore;
  fetchLatestBaileysVersion = baileys.fetchLatestBaileysVersion;
  downloadMediaMessage = baileys.downloadMediaMessage;
}

// ── Config ─────────────────────────────────────────────────────────

const GATEWAY_URL = process.env.NULLCLAW_GATEWAY_URL || "http://127.0.0.1:8080";
const SIDECAR_PORT = parseInt(process.env.SIDECAR_PORT || "7100", 10);
const AUTH_TOKEN = process.env.SIDECAR_AUTH_TOKEN || "";
const CREDENTIALS_DIR =
  process.env.WA_CREDENTIALS_DIR ||
  path.join(process.env.HOME || "/tmp", ".nullclaw", "credentials", "whatsapp_web");
const ALLOW_FROM = parseList(process.env.WA_ALLOW_FROM || "*");
const GROUP_POLICY = process.env.WA_GROUP_POLICY || "allowlist";
const GROUP_ALLOW_FROM = process.env.WA_GROUP_ALLOW_FROM
  ? parseList(process.env.WA_GROUP_ALLOW_FROM)
  : ALLOW_FROM;
const MEDIA_DIR =
  process.env.WA_MEDIA_DIR ||
  path.join(process.env.HOME || "/tmp", ".nullclaw", "media", "whatsapp_web");

function parseList(s) {
  return s.split(",").map((x) => x.trim()).filter(Boolean);
}

// ── Media Handling ────────────────────────────────────────────────

const MEDIA_EXTENSIONS = {
  "image/jpeg": ".jpg",
  "image/png": ".png",
  "image/webp": ".webp",
  "image/gif": ".gif",
  "audio/ogg; codecs=opus": ".ogg",
  "audio/mpeg": ".mp3",
  "audio/mp4": ".m4a",
  "video/mp4": ".mp4",
  "application/pdf": ".pdf",
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx",
};

function detectMediaInfo(message) {
  if (message.imageMessage) return { type: "image", msg: message.imageMessage };
  if (message.audioMessage) return { type: "audio", msg: message.audioMessage };
  if (message.videoMessage) return { type: "video", msg: message.videoMessage };
  if (message.documentMessage) return { type: "document", msg: message.documentMessage };
  if (message.stickerMessage) return { type: "sticker", msg: message.stickerMessage };
  return null;
}

async function downloadAndSaveMedia(msg) {
  fs.mkdirSync(MEDIA_DIR, { recursive: true });

  const buffer = await downloadMediaMessage(msg, "buffer", {});
  const mediaInfo = detectMediaInfo(msg.message);
  if (!mediaInfo) return null;

  const mimetype = mediaInfo.msg.mimetype || "application/octet-stream";
  const ext = MEDIA_EXTENSIONS[mimetype] || MEDIA_EXTENSIONS[mimetype.split(";")[0]] || ".bin";
  const id = crypto.randomBytes(8).toString("hex");
  const filename = `wa_${id}${ext}`;
  const filepath = path.join(MEDIA_DIR, filename);

  fs.writeFileSync(filepath, buffer);
  console.log(`[nullclaw-wa-web] Saved media: ${filepath} (${mimetype}, ${buffer.length} bytes)`);

  return { path: filepath, type: mediaInfo.type, mimetype, size: buffer.length };
}

// ── State ──────────────────────────────────────────────────────────

let sock = null;
let qrCode = null;
let connectionState = "disconnected"; // disconnected | connecting | open
let lastError = null;

// ── Baileys Connection ─────────────────────────────────────────────

async function connectWhatsApp() {
  fs.mkdirSync(CREDENTIALS_DIR, { recursive: true });

  const { version } = await fetchLatestBaileysVersion();
  console.log(`[nullclaw-wa-web] Using WA version: ${version.join(".")}`);

  const { state, saveCreds } = await useMultiFileAuthState(CREDENTIALS_DIR);
  const pino = (await import("pino")).default;
  const logger = pino({ level: "warn" });

  sock = makeWASocket({
    version,
    auth: {
      creds: state.creds,
      keys: makeCacheableSignalKeyStore(state.keys, logger),
    },
    logger,
    generateHighQualityLinkPreview: false,
    browser: ["NullClaw", "Chrome", "120.0.0"],
  });

  sock.ev.on("creds.update", saveCreds);

  sock.ev.on("connection.update", (update) => {
    const { connection, lastDisconnect, qr } = update;

    if (qr) {
      qrCode = qr;
      connectionState = "connecting";
      console.log("[nullclaw-wa-web] QR code generated. Scan with WhatsApp to connect:");
      qrcodeTerminal.generate(qr, { small: true });
      console.log("[nullclaw-wa-web] QR also available at GET /qr");
    }

    if (connection === "close") {
      connectionState = "disconnected";
      const statusCode = lastDisconnect?.error?.output?.statusCode;
      const shouldReconnect = statusCode !== DisconnectReason.loggedOut;
      lastError = lastDisconnect?.error?.message || "connection closed";
      console.log(
        `[nullclaw-wa-web] Connection closed (status=${statusCode}). Reconnect: ${shouldReconnect}`
      );
      if (shouldReconnect) {
        setTimeout(connectWhatsApp, 3000);
      } else {
        console.log("[nullclaw-wa-web] Logged out. Delete credentials and restart to re-pair.");
      }
    } else if (connection === "open") {
      connectionState = "open";
      qrCode = null;
      lastError = null;
      console.log("[nullclaw-wa-web] Connected to WhatsApp Web.");
    }
  });

  sock.ev.on("messages.upsert", async (upsert) => {
    const messages = upsert.messages || upsert;
    const type = upsert.type;
    // In Baileys v7, type may be undefined; in v6 it's "notify" for new messages
    if (type !== undefined && type !== "notify") return;

    for (const msg of messages) {
      if (msg.key.fromMe) continue;
      if (!msg.message) continue;

      // Use remoteJidAlt (phone-based JID) if available, fall back to remoteJid (LID)
      const sender = msg.key.remoteJidAlt || msg.key.remoteJid;
      if (!sender) continue;

      // Extract phone number from JID
      const phone = jidToPhone(sender);
      const isGroup = sender.endsWith("@g.us");
      const groupId = isGroup ? sender : null;
      const individualSender = isGroup
        ? jidToPhone(msg.key.participant || "")
        : phone;

      // Apply allowlist
      if (!isGroup) {
        if (!isAllowed(ALLOW_FROM, individualSender)) continue;
      } else {
        if (GROUP_POLICY === "disabled") continue;
        if (GROUP_POLICY !== "open") {
          if (!isAllowed(GROUP_ALLOW_FROM, individualSender)) continue;
        }
      }

      // Extract text and media
      const text = extractText(msg.message);
      const msgHasMedia = hasMedia(msg.message);

      // Skip messages with no text AND no media
      if (!text && !msgHasMedia) continue;

      // Download media if present
      let media = null;
      if (msgHasMedia) {
        try {
          media = await downloadAndSaveMedia(msg);
        } catch (err) {
          console.log(`[nullclaw-wa-web] Media download failed: ${err.message}`);
        }
      }

      // Skip if no text and media download failed
      if (!text && !media) continue;

      // Forward to NullClaw gateway
      // Use the original remoteJid (possibly LID format) for reply_to, as that's
      // what Baileys needs for sendMessage
      const replyJid = msg.key.remoteJid || sender;
      const payloadObj = {
        from: individualSender,
        text: text || "",
        timestamp: (msg.messageTimestamp || Math.floor(Date.now() / 1000)).toString(),
        is_group: isGroup,
        group_id: groupId,
        reply_to: replyJid,
      };

      if (media) {
        payloadObj.media_type = media.type;
        payloadObj.media_path = media.path;
        payloadObj.media_mimetype = media.mimetype;
      }

      const payload = JSON.stringify(payloadObj);

      console.log(
        `[nullclaw-wa-web] Message from ${individualSender}: ` +
        `${text ? text.substring(0, 50) : "[media-only]"}` +
        `${media ? ` [${media.type}:${media.mimetype}]` : ""}`
      );

      forwardToGateway(payload);
    }
  });
}

function jidToPhone(jid) {
  if (!jid) return "";
  const num = jid.split("@")[0].split(":")[0];
  return num.startsWith("+") ? num : "+" + num;
}

function isAllowed(allowlist, phone) {
  if (allowlist.includes("*")) return true;
  return allowlist.some(
    (a) => a === phone || a === phone.replace("+", "") || "+" + a === phone
  );
}

function extractText(message) {
  if (message.conversation) return message.conversation;
  if (message.extendedTextMessage?.text) return message.extendedTextMessage.text;
  if (message.imageMessage?.caption) return message.imageMessage.caption;
  if (message.videoMessage?.caption) return message.videoMessage.caption;
  if (message.documentMessage?.caption) return message.documentMessage.caption;
  return null;
}

function hasMedia(message) {
  return !!(
    message.imageMessage ||
    message.audioMessage ||
    message.videoMessage ||
    message.documentMessage ||
    message.stickerMessage
  );
}

function forwardToGateway(payload) {
  const url = new URL("/whatsapp_web", GATEWAY_URL);
  const options = {
    hostname: url.hostname,
    port: url.port || 80,
    path: url.pathname,
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(payload),
    },
  };

  const req = http.request(options, (res) => {
    if (res.statusCode !== 200) {
      console.log(`[nullclaw-wa-web] Gateway returned ${res.statusCode}`);
    }
    res.resume(); // drain
  });

  req.on("error", (err) => {
    console.log(`[nullclaw-wa-web] Gateway error: ${err.message}`);
  });

  req.write(payload);
  req.end();
}

// ── HTTP API ───────────────────────────────────────────────────────

function startHttpServer() {
  const server = http.createServer(async (req, res) => {
    // Auth check (skip for health)
    if (req.url !== "/health" && AUTH_TOKEN) {
      const auth = req.headers["authorization"] || "";
      if (auth !== `Bearer ${AUTH_TOKEN}`) {
        res.writeHead(401, { "Content-Type": "application/json" });
        res.end('{"error":"unauthorized"}');
        return;
      }
    }

    if (req.url === "/health" && req.method === "GET") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          status: connectionState,
          error: lastError,
        })
      );
      return;
    }

    if (req.url === "/qr" && req.method === "GET") {
      if (qrCode) {
        res.writeHead(200, { "Content-Type": "text/plain" });
        res.end(qrCode);
      } else if (connectionState === "open") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end('{"status":"already connected"}');
      } else {
        res.writeHead(404, { "Content-Type": "application/json" });
        res.end('{"error":"no QR code available"}');
      }
      return;
    }

    if (req.url === "/send" && req.method === "POST") {
      let body = "";
      req.on("data", (chunk) => (body += chunk));
      req.on("end", async () => {
        try {
          const { to, text, media } = JSON.parse(body);

          if (!to || !text) {
            res.writeHead(400, { "Content-Type": "application/json" });
            res.end('{"error":"missing to or text"}');
            return;
          }

          if (connectionState !== "open" || !sock) {
            res.writeHead(503, { "Content-Type": "application/json" });
            res.end('{"error":"not connected"}');
            return;
          }

          // Convert phone to JID
          const jid = phoneToJid(to);

          if (media && media.length > 0) {
            // Send media (first item only for now)
            const mediaPath = media[0];
            if (fs.existsSync(mediaPath)) {
              await sock.sendMessage(jid, {
                image: fs.readFileSync(mediaPath),
                caption: text,
              });
            } else {
              await sock.sendMessage(jid, { text });
            }
          } else {
            await sock.sendMessage(jid, { text });
          }

          res.writeHead(200, { "Content-Type": "application/json" });
          res.end('{"status":"sent"}');
        } catch (err) {
          console.log(`[nullclaw-wa-web] Send error: ${err.message}`);
          res.writeHead(500, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: err.message }));
        }
      });
      return;
    }

    res.writeHead(404, { "Content-Type": "application/json" });
    res.end('{"error":"not found"}');
  });

  server.listen(SIDECAR_PORT, "127.0.0.1", () => {
    console.log(`[nullclaw-wa-web] HTTP API listening on 127.0.0.1:${SIDECAR_PORT}`);
  });
}

function phoneToJid(phone) {
  // If already a JID, return as-is
  if (phone.includes("@")) return phone;
  // Strip leading +
  const num = phone.startsWith("+") ? phone.slice(1) : phone;
  return `${num}@s.whatsapp.net`;
}

// ── Main ───────────────────────────────────────────────────────────

async function main() {
  if (!AUTH_TOKEN) {
    console.warn(
      "[nullclaw-wa-web] WARNING: SIDECAR_AUTH_TOKEN not set. " +
      "The /send endpoint is unprotected. Set SIDECAR_AUTH_TOKEN for production use."
    );
  }

  console.log("[nullclaw-wa-web] Starting NullClaw WhatsApp Web sidecar...");
  console.log(`[nullclaw-wa-web] Gateway URL: ${GATEWAY_URL}`);
  console.log(`[nullclaw-wa-web] Credentials: ${CREDENTIALS_DIR}`);

  await loadBaileys();
  startHttpServer();
  await connectWhatsApp();
}

main().catch((err) => {
  console.error("[nullclaw-wa-web] Fatal:", err);
  process.exit(1);
});
