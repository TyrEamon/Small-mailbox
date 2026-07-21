const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
};

const CORS_HEADERS = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET,POST,OPTIONS",
  "access-control-allow-headers": "authorization,content-type,x-admin-auth",
};

let schemaReadyPromise;

export default {
  async fetch(request, env, ctx) {
    if (request.method === "OPTIONS") {
      return withCors(new Response(null, { status: 204 }));
    }

    try {
      ensureBindings(env);
      await ensureSchema(env);

      const url = new URL(request.url);
      const path = trimTrailingSlash(url.pathname);

      if (request.method === "GET" && path === "/health") {
        return json({ ok: true });
      }

      if (request.method === "POST" && path === "/admin/new_address") {
        return handleNewAddress(request, env);
      }

      if (request.method === "GET" && path === "/api/mails") {
        return handleMailList(request, env, url);
      }

      if (request.method === "GET" && path.startsWith("/api/mail/")) {
        const id = decodeURIComponent(path.slice("/api/mail/".length));
        return handleMailDetail(request, env, id);
      }

      return errorJson("not_found", 404);
    } catch (error) {
      console.error(error);
      return errorJson(error.message || "internal_error", error.status || 500);
    }
  },

  async email(message, env, ctx) {
    ensureBindings(env);
    await ensureSchema(env);

    const recipient = normalizeEmail(message.to);
    const domain = getEmailDomain(recipient);

    if (!isAllowedDomain(env, domain)) {
      message.setReject("unsupported domain");
      return;
    }

    const maxRawBytes = getMaxRawBytes(env);
    if (message.rawSize && message.rawSize > maxRawBytes) {
      message.setReject("message too large");
      return;
    }

    const rawBuffer = await new Response(message.raw).arrayBuffer();
    if (rawBuffer.byteLength > maxRawBytes) {
      message.setReject("message too large");
      return;
    }

    const rawText = new TextDecoder().decode(rawBuffer);
    const id = createMailId();
    const rawKey = `raw/${domain}/${recipient}/${id}.eml`;
    const subject = getHeader(message.headers, "subject") || getRawHeader(rawText, "subject") || "";
    const messageId = getHeader(message.headers, "message-id") || getRawHeader(rawText, "message-id") || "";
    const sender = normalizeEmail(message.from || getRawHeader(rawText, "from") || "");
    const name = getEmailName(recipient);

    await env.MAIL_RAW.put(rawKey, rawBuffer, {
      httpMetadata: {
        contentType: "message/rfc822",
      },
      customMetadata: {
        recipient,
        sender,
      },
    });

    await env.MAIL_DB.prepare(
      `INSERT INTO addresses (address, name, domain)
       VALUES (?, ?, ?)
       ON CONFLICT(address) DO NOTHING`
    ).bind(recipient, name, domain).run();

    await env.MAIL_DB.prepare(
      `INSERT INTO mails (id, address, sender, recipient, subject, raw_key, raw_size, message_id)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      id,
      recipient,
      sender,
      recipient,
      subject,
      rawKey,
      rawBuffer.byteLength,
      messageId
    ).run();
  },

  async scheduled(event, env, ctx) {
    ctx.waitUntil(cleanupExpiredMail(env));
  },
};

async function handleNewAddress(request, env) {
  const adminAuth = request.headers.get("x-admin-auth") || "";
  if (!env.EMAIL_AUTH || adminAuth !== env.EMAIL_AUTH) {
    return errorJson("unauthorized", 401);
  }

  const body = await readJsonBody(request);
  const name = normalizeAddressName(body.name || createAddressName());
  const domain = normalizeDomain(body.domain || env.EMAIL_DOMAIN);

  if (!isAllowedDomain(env, domain)) {
    return errorJson("domain_not_allowed", 400);
  }

  const address = `${name}@${domain}`;
  const iat = Math.floor(Date.now() / 1000);
  const jwt = await signJwt(env, { address, iat });

  await env.MAIL_DB.prepare(
    `INSERT INTO addresses (address, name, domain, last_jwt_iat)
     VALUES (?, ?, ?, ?)
     ON CONFLICT(address) DO UPDATE SET last_jwt_iat = excluded.last_jwt_iat`
  ).bind(address, name, domain, iat).run();

  return json({ address, jwt });
}

async function handleMailList(request, env, url) {
  const auth = await requireJwt(request, env);
  const limit = clampInt(url.searchParams.get("limit"), 5, 1, 50);
  const offset = clampInt(url.searchParams.get("offset"), 0, 0, 10000);

  const result = await env.MAIL_DB.prepare(
    `SELECT id, sender, recipient, subject, raw_size, message_id, created_at
     FROM mails
     WHERE address = ?
     ORDER BY created_at DESC, id DESC
     LIMIT ? OFFSET ?`
  ).bind(auth.address, limit, offset).all();

  const rows = (result.results || []).map((mail) => ({
    id: mail.id,
    _id: mail.id,
    from: mail.sender,
    to: mail.recipient,
    subject: mail.subject || "",
    raw_size: mail.raw_size,
    message_id: mail.message_id || "",
    created_at: mail.created_at,
  }));

  return json({ results: rows, data: rows });
}

async function handleMailDetail(request, env, id) {
  const auth = await requireJwt(request, env);

  if (!/^[A-Za-z0-9_.:-]{1,128}$/.test(id)) {
    return errorJson("mail_not_found", 404);
  }

  const mail = await env.MAIL_DB.prepare(
    `SELECT id, raw_key
     FROM mails
     WHERE id = ? AND address = ?
     LIMIT 1`
  ).bind(id, auth.address).first();

  if (!mail) {
    return errorJson("mail_not_found", 404);
  }

  const rawObject = await env.MAIL_RAW.get(mail.raw_key);
  if (!rawObject) {
    return errorJson("mail_raw_not_found", 404);
  }

  return json({
    id: mail.id,
    _id: mail.id,
    raw: await rawObject.text(),
  });
}

async function cleanupExpiredMail(env) {
  ensureBindings(env);
  await ensureSchema(env);

  const retentionHours = Number(env.RETENTION_HOURS || 0);
  if (!Number.isFinite(retentionHours) || retentionHours <= 0) {
    return;
  }

  const expired = await env.MAIL_DB.prepare(
    `SELECT id, raw_key
     FROM mails
     WHERE created_at < datetime('now', ?)
     LIMIT 100`
  ).bind(`-${retentionHours} hours`).all();

  const rows = expired.results || [];
  for (const row of rows) {
    await env.MAIL_RAW.delete(row.raw_key);
    await env.MAIL_DB.prepare("DELETE FROM mails WHERE id = ?").bind(row.id).run();
  }
}

async function ensureSchema(env) {
  if (!schemaReadyPromise) {
    schemaReadyPromise = initializeSchema(env).catch((error) => {
      schemaReadyPromise = undefined;
      throw error;
    });
  }

  return schemaReadyPromise;
}

async function initializeSchema(env) {
  await env.MAIL_DB.prepare(
    `CREATE TABLE IF NOT EXISTS addresses (
      address TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      domain TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      last_jwt_iat INTEGER
    )`
  ).run();

  await env.MAIL_DB.prepare(
    `CREATE TABLE IF NOT EXISTS mails (
      id TEXT PRIMARY KEY,
      address TEXT NOT NULL,
      sender TEXT NOT NULL,
      recipient TEXT NOT NULL,
      subject TEXT,
      raw_key TEXT NOT NULL,
      raw_size INTEGER NOT NULL DEFAULT 0,
      message_id TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (address) REFERENCES addresses(address) ON DELETE CASCADE
    )`
  ).run();

  await env.MAIL_DB.prepare(
    `CREATE INDEX IF NOT EXISTS idx_mails_address_created
     ON mails(address, created_at DESC)`
  ).run();

  await env.MAIL_DB.prepare(
    `CREATE INDEX IF NOT EXISTS idx_mails_message_id
     ON mails(message_id)`
  ).run();
}

async function readJsonBody(request) {
  try {
    const body = await request.json();
    return body && typeof body === "object" ? body : {};
  } catch {
    return {};
  }
}

async function requireJwt(request, env) {
  const authorization = request.headers.get("authorization") || "";
  const match = authorization.match(/^Bearer\s+(.+)$/i);

  if (!match) {
    throw httpError("unauthorized", 401);
  }

  const payload = await verifyJwt(env, match[1]);
  const address = normalizeEmail(payload.address || "");
  const domain = getEmailDomain(address);

  if (!address || !isAllowedDomain(env, domain)) {
    throw httpError("unauthorized", 401);
  }

  return { address };
}

async function signJwt(env, payload) {
  const secret = getJwtSecret(env);
  const header = { alg: "HS256", typ: "JWT" };
  const encodedHeader = base64urlEncodeJson(header);
  const encodedPayload = base64urlEncodeJson(payload);
  const data = `${encodedHeader}.${encodedPayload}`;
  const signature = await hmacSha256(secret, data);

  return `${data}.${base64urlEncodeBytes(signature)}`;
}

async function verifyJwt(env, jwt) {
  try {
    const parts = jwt.split(".");
    if (parts.length !== 3) {
      throw new Error("invalid jwt");
    }

    const [encodedHeader, encodedPayload, encodedSignature] = parts;
    const header = JSON.parse(new TextDecoder().decode(base64urlDecode(encodedHeader)));

    if (header.alg !== "HS256") {
      throw new Error("invalid jwt alg");
    }

    const data = `${encodedHeader}.${encodedPayload}`;
    const expectedSignature = base64urlEncodeBytes(await hmacSha256(getJwtSecret(env), data));

    if (!safeEqual(encodedSignature, expectedSignature)) {
      throw new Error("invalid jwt signature");
    }

    const payload = JSON.parse(new TextDecoder().decode(base64urlDecode(encodedPayload)));
    const now = Math.floor(Date.now() / 1000);

    if (payload.exp && payload.exp < now) {
      throw new Error("expired jwt");
    }

    return payload;
  } catch {
    throw httpError("unauthorized", 401);
  }
}

async function hmacSha256(secret, data) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  return crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
}

function base64urlEncodeJson(value) {
  return base64urlEncodeBytes(new TextEncoder().encode(JSON.stringify(value)));
}

function base64urlEncodeBytes(value) {
  const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64urlDecode(value) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);

  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }

  return bytes;
}

function safeEqual(left, right) {
  if (left.length !== right.length) {
    return false;
  }

  let diff = 0;
  for (let index = 0; index < left.length; index += 1) {
    diff |= left.charCodeAt(index) ^ right.charCodeAt(index);
  }

  return diff === 0;
}

function createMailId() {
  return `mail_${Date.now().toString(36)}_${randomHex(8)}`;
}

function createAddressName() {
  return `nv${randomHex(5)}`;
}

function randomHex(length) {
  const bytes = new Uint8Array(Math.ceil(length / 2));
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("").slice(0, length);
}

function normalizeAddressName(value) {
  const name = String(value || "").trim().toLowerCase();

  if (!/^[a-z0-9._-]{1,64}$/.test(name)) {
    throw httpError("invalid_address_name", 400);
  }

  return name;
}

function normalizeDomain(value) {
  return String(value || "")
    .trim()
    .replace(/^@/, "")
    .replace(/\.$/, "")
    .toLowerCase();
}

function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function getEmailDomain(email) {
  const parts = email.split("@");
  return parts.length === 2 ? normalizeDomain(parts[1]) : "";
}

function getEmailName(email) {
  return String(email.split("@")[0] || createAddressName()).slice(0, 64);
}

function getAllowedDomains(env) {
  const domains = new Set();

  if (env.EMAIL_DOMAIN) {
    domains.add(normalizeDomain(env.EMAIL_DOMAIN));
  }

  if (env.EMAIL_DOMAINS) {
    for (const domain of String(env.EMAIL_DOMAINS).split(",")) {
      const normalized = normalizeDomain(domain);
      if (normalized) {
        domains.add(normalized);
      }
    }
  }

  return domains;
}

function isAllowedDomain(env, domain) {
  return getAllowedDomains(env).has(normalizeDomain(domain));
}

function getHeader(headers, name) {
  return headers?.get?.(name) || "";
}

function getRawHeader(rawText, headerName) {
  const headerBlock = rawText.split(/\r?\n\r?\n/, 1)[0] || "";
  const lines = headerBlock.split(/\r?\n/);
  const headers = new Map();
  let currentName = "";
  let currentValue = "";

  for (const line of lines) {
    if (/^\s/.test(line) && currentName) {
      currentValue += ` ${line.trim()}`;
      continue;
    }

    if (currentName) {
      headers.set(currentName, currentValue);
    }

    const match = line.match(/^([^:]+):\s*(.*)$/);
    currentName = match ? match[1].trim().toLowerCase() : "";
    currentValue = match ? match[2].trim() : "";
  }

  if (currentName) {
    headers.set(currentName, currentValue);
  }

  return headers.get(headerName.toLowerCase()) || "";
}

function getMaxRawBytes(env) {
  const value = Number(env.MAX_RAW_BYTES || 2 * 1024 * 1024);
  return Number.isFinite(value) && value > 0 ? value : 2 * 1024 * 1024;
}

function getJwtSecret(env) {
  const secret = env.JWT_SECRET || env.EMAIL_AUTH;
  if (!secret) {
    throw httpError("missing_jwt_secret", 500);
  }
  return secret;
}

function clampInt(value, fallback, min, max) {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed)) {
    return fallback;
  }
  return Math.min(max, Math.max(min, parsed));
}

function ensureBindings(env) {
  if (!env.MAIL_DB) {
    throw httpError("missing_mail_db_binding", 500);
  }
  if (!env.MAIL_RAW) {
    throw httpError("missing_mail_raw_binding", 500);
  }
}

function trimTrailingSlash(path) {
  return path.length > 1 ? path.replace(/\/+$/g, "") : path;
}

function httpError(message, status) {
  const error = new Error(message);
  error.status = status;
  return error;
}

function json(data, status = 200) {
  return withCors(
    new Response(JSON.stringify(data), {
      status,
      headers: JSON_HEADERS,
    })
  );
}

function errorJson(message, status) {
  return json({ error: message }, status);
}

function withCors(response) {
  const headers = new Headers(response.headers);
  for (const [key, value] of Object.entries(CORS_HEADERS)) {
    headers.set(key, value);
  }

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}
