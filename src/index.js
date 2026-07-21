const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
};

const HTML_HEADERS = {
  "content-type": "text/html; charset=utf-8",
  "cache-control": "no-store",
};

const CORS_HEADERS = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET,POST,OPTIONS",
  "access-control-allow-headers": "authorization,content-type,x-admin-auth",
};

const USER_SESSION_TTL_SECONDS = 7 * 24 * 60 * 60;
const PASSWORD_ITERATIONS = 100000;
const DEFAULT_MAX_BATCH_CREATE = 100;

let schemaReadyPromise;

export default {
  async fetch(request, env, ctx) {
    if (request.method === "OPTIONS") {
      return withCors(new Response(null, { status: 204 }));
    }

    try {
      const url = new URL(request.url);
      const path = trimTrailingSlash(url.pathname);

      if (request.method === "GET" && (path === "/" || path === "/app")) {
        return html(getAppHtml(env));
      }

      if (request.method === "GET" && path === "/favicon.ico") {
        return new Response(null, { status: 204 });
      }

      if (request.method === "GET" && path === "/health") {
        return json({
          ok: true,
          bindings: {
            MAIL_DB: Boolean(env.MAIL_DB),
            MAIL_RAW: Boolean(env.MAIL_RAW),
            MAIL_KV: Boolean(env.MAIL_KV),
          },
        });
      }

      ensureBindings(env);
      await ensureSchema(env);

      if (request.method === "POST" && path === "/admin/new_address") {
        return handleNewAddress(request, env);
      }

      if (request.method === "POST" && path === "/admin/redeem_codes") {
        return handleCreateRedeemCode(request, env);
      }

      if (request.method === "POST" && path === "/app/api/register") {
        return handleRegister(request, env);
      }

      if (request.method === "POST" && path === "/app/api/login") {
        return handleLogin(request, env);
      }

      if (request.method === "GET" && path === "/app/api/me") {
        return handleMe(request, env);
      }

      if (request.method === "POST" && path === "/app/api/redeem") {
        return handleRedeem(request, env);
      }

      if (request.method === "GET" && path === "/app/api/api_keys") {
        return handleApiKeyList(request, env);
      }

      if (request.method === "POST" && path === "/app/api/api_keys") {
        return handleCreateApiKey(request, env);
      }

      if (request.method === "POST" && path === "/app/api/api_keys/revoke") {
        return handleRevokeApiKey(request, env);
      }

      if (request.method === "GET" && path === "/app/api/addresses") {
        return handleAppAddressList(request, env);
      }

      if (request.method === "POST" && path === "/app/api/addresses") {
        return handleCreateAppAddress(request, env);
      }

      if (request.method === "POST" && path === "/app/api/addresses/batch") {
        return handleCreateAppAddressBatch(request, env);
      }

      if (request.method === "GET" && path === "/app/api/mails") {
        return handleAppMailList(request, env, url);
      }

      if (request.method === "GET" && path.startsWith("/app/api/mail/")) {
        const id = decodeURIComponent(path.slice("/app/api/mail/".length));
        return handleAppMailDetail(request, env, id);
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

    await putRawMail(env, rawKey, rawBuffer, rawText, { recipient, sender });

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
  const actor = await requireAddressCreator(request, env);

  const body = await readJsonBody(request);
  const name = normalizeAddressName(body.name || createAddressName());
  const domain = normalizeDomain(body.domain || getDefaultDomain(env));

  if (actor.type === "user") {
    const created = await createOwnedAddressWithDebit(env, actor.user.id, name, domain);
    return json({
      address: created.address,
      jwt: created.jwt,
    }, created.created ? 201 : 200);
  }

  if (!isAllowedDomain(env, domain)) {
    return errorJson("domain_not_allowed", 400);
  }

  const address = `${name}@${domain}`;
  const iat = Math.floor(Date.now() / 1000);
  const jwt = await signJwt(env, { address, iat });

  await env.MAIL_DB.prepare(
    `INSERT INTO addresses (address, name, domain, last_jwt_iat)
     VALUES (?, ?, ?, ?)
     ON CONFLICT(address) DO UPDATE SET
       name = excluded.name,
       domain = excluded.domain,
       last_jwt_iat = excluded.last_jwt_iat`
  ).bind(address, name, domain, iat).run();

  return json({ address, jwt });
}

async function handleCreateRedeemCode(request, env) {
  await requireAdmin(request, env);

  const body = await readJsonBody(request);
  const credits = parsePositiveInt(body.credits, "invalid_credits", 1, 100000);
  const maxUses = parsePositiveInt(body.max_uses || body.maxUses || 1, "invalid_max_uses", 1, 100000);
  const code = normalizeRedeemCode(body.code || createRedeemCode());
  const expiresAt = normalizeNullableDate(body.expires_at || body.expiresAt);

  await env.MAIL_DB.prepare(
    `INSERT INTO redeem_codes (code, credits, max_uses, used_count, expires_at)
     VALUES (?, ?, ?, 0, ?)`
  ).bind(code, credits, maxUses, expiresAt).run();

  return json({
    code,
    credits,
    max_uses: maxUses,
    used_count: 0,
    expires_at: expiresAt,
  }, 201);
}

async function handleRegister(request, env) {
  if (String(env.ALLOW_REGISTRATION || "true").toLowerCase() === "false") {
    return errorJson("registration_disabled", 403);
  }

  const body = await readJsonBody(request);
  const username = normalizeUsername(body.username);
  const password = normalizePassword(body.password);
  const passwordRecord = await hashPassword(password);

  try {
    await env.MAIL_DB.prepare(
      `INSERT INTO users (username, password_hash, password_salt, credits)
       VALUES (?, ?, ?, 0)`
    ).bind(username, passwordRecord.hash, passwordRecord.salt).run();
  } catch {
    return errorJson("username_taken", 409);
  }

  const user = await getUserByUsername(env, username);
  const token = await signUserToken(env, user);

  return json(sessionPayload(user, token), 201);
}

async function handleLogin(request, env) {
  const body = await readJsonBody(request);
  const username = normalizeUsername(body.username);
  const password = normalizePassword(body.password);
  const user = await getUserByUsername(env, username);

  if (!user || !(await verifyPassword(password, user.password_salt, user.password_hash))) {
    return errorJson("invalid_login", 401);
  }

  const token = await signUserToken(env, user);
  return json(sessionPayload(user, token));
}

async function handleMe(request, env) {
  const user = await requireUser(request, env);
  const domains = Array.from(getAllowedDomains(env));

  return json({
    user: publicUser(user),
    domains,
    max_batch_create: getMaxBatchCreate(env),
  });
}

async function handleRedeem(request, env) {
  const user = await requireUser(request, env);
  const body = await readJsonBody(request);
  const code = normalizeRedeemCode(body.code);
  const redeemCode = await env.MAIL_DB.prepare(
    `SELECT code, credits, max_uses, used_count, expires_at
     FROM redeem_codes
     WHERE code = ?
     LIMIT 1`
  ).bind(code).first();

  if (!redeemCode) {
    return errorJson("redeem_code_not_found", 404);
  }

  if (redeemCode.expires_at && new Date(redeemCode.expires_at).getTime() < Date.now()) {
    return errorJson("redeem_code_expired", 410);
  }

  if (Number(redeemCode.used_count) >= Number(redeemCode.max_uses)) {
    return errorJson("redeem_code_exhausted", 409);
  }

  const useResult = await env.MAIL_DB.prepare(
    `INSERT OR IGNORE INTO redeem_uses (user_id, code)
     VALUES (?, ?)`
  ).bind(user.id, code).run();

  if (!hasChanges(useResult)) {
    return errorJson("redeem_code_already_used", 409);
  }

  const claimResult = await env.MAIL_DB.prepare(
    `UPDATE redeem_codes
     SET used_count = used_count + 1
     WHERE code = ? AND used_count < max_uses`
  ).bind(code).run();

  if (!hasChanges(claimResult)) {
    await env.MAIL_DB.prepare(
      `DELETE FROM redeem_uses
       WHERE user_id = ? AND code = ?`
    ).bind(user.id, code).run();
    return errorJson("redeem_code_exhausted", 409);
  }

  await addCredits(env, user.id, redeemCode.credits);
  const updatedUser = await getUserById(env, user.id);

  return json({
    user: publicUser(updatedUser),
    credits_added: Number(redeemCode.credits),
  });
}

async function handleApiKeyList(request, env) {
  const user = await requireUserSession(request, env);
  const result = await env.MAIL_DB.prepare(
    `SELECT id, name, key_prefix, created_at, last_used_at, revoked_at
     FROM user_api_keys
     WHERE user_id = ?
     ORDER BY created_at DESC`
  ).bind(user.id).all();
  const rows = (result.results || []).map(apiKeyRow);

  return json({ results: rows, data: rows });
}

async function handleCreateApiKey(request, env) {
  const user = await requireUserSession(request, env);
  const body = await readJsonBody(request);
  const name = normalizeApiKeyName(body.name || "default");
  const apiKey = createApiKey();
  const keyHash = await sha256Base64url(apiKey);
  const keyPrefix = apiKey.slice(0, 12);

  await env.MAIL_DB.prepare(
    `INSERT INTO user_api_keys (user_id, name, key_prefix, key_hash)
     VALUES (?, ?, ?, ?)`
  ).bind(user.id, name, keyPrefix, keyHash).run();

  const row = await env.MAIL_DB.prepare(
    `SELECT id, name, key_prefix, created_at, last_used_at, revoked_at
     FROM user_api_keys
     WHERE key_hash = ?
     LIMIT 1`
  ).bind(keyHash).first();

  return json({
    api_key: apiKey,
    key: apiKeyRow(row),
    env: {
      EMAIL_API: "https://你的-worker-域名",
      EMAIL_AUTH: apiKey,
      EMAIL_DOMAIN: getDefaultDomain(env),
    },
  }, 201);
}

async function handleRevokeApiKey(request, env) {
  const user = await requireUserSession(request, env);
  const body = await readJsonBody(request);
  const id = parsePositiveInt(body.id, "invalid_api_key_id", 1, 2147483647);
  const result = await env.MAIL_DB.prepare(
    `UPDATE user_api_keys
     SET revoked_at = CURRENT_TIMESTAMP
     WHERE id = ? AND user_id = ? AND revoked_at IS NULL`
  ).bind(id, user.id).run();

  if (!hasChanges(result)) {
    return errorJson("api_key_not_found", 404);
  }

  return json({ ok: true });
}

async function handleAppAddressList(request, env) {
  const user = await requireUser(request, env);
  const result = await env.MAIL_DB.prepare(
    `SELECT
       a.address,
       a.name,
       a.domain,
       a.created_at,
       COUNT(m.id) AS mail_count,
       MAX(m.created_at) AS last_mail_at
     FROM addresses a
     LEFT JOIN mails m ON m.address = a.address
     WHERE a.user_id = ?
     GROUP BY a.address, a.name, a.domain, a.created_at
     ORDER BY a.created_at DESC`
  ).bind(user.id).all();

  return json({
    results: result.results || [],
    data: result.results || [],
  });
}

async function handleCreateAppAddress(request, env) {
  const user = await requireUser(request, env);
  const body = await readJsonBody(request);
  const name = normalizeAddressName(body.name || createAddressName());
  const domain = normalizeDomain(body.domain || getDefaultDomain(env));
  const address = await createOwnedAddressWithDebit(env, user.id, name, domain);
  const updatedUser = await getUserById(env, user.id);

  return json({
    address: address.address,
    jwt: address.jwt,
    user: publicUser(updatedUser),
  }, address.created ? 201 : 200);
}

async function handleCreateAppAddressBatch(request, env) {
  const user = await requireUser(request, env);
  const body = await readJsonBody(request);
  const count = parsePositiveInt(body.count || 1, "invalid_count", 1, getMaxBatchCreate(env));
  const domain = normalizeDomain(body.domain || getDefaultDomain(env));
  const prefix = String(body.prefix || "").trim().toLowerCase();
  const startAt = clampInt(body.start_at || body.startAt, 1, 0, 999999);
  const addresses = await createOwnedAddressBatch(env, user.id, {
    count,
    domain,
    prefix,
    startAt,
  });
  const updatedUser = await getUserById(env, user.id);

  return json({
    addresses,
    user: publicUser(updatedUser),
  }, 201);
}

async function handleAppMailList(request, env, url) {
  const user = await requireUser(request, env);
  const address = normalizeEmail(url.searchParams.get("address") || "");

  await requireOwnedAddress(env, user.id, address);

  const limit = clampInt(url.searchParams.get("limit"), 20, 1, 50);
  const offset = clampInt(url.searchParams.get("offset"), 0, 0, 10000);
  const result = await env.MAIL_DB.prepare(
    `SELECT id, sender, recipient, subject, raw_size, message_id, created_at
     FROM mails
     WHERE address = ?
     ORDER BY created_at DESC, id DESC
     LIMIT ? OFFSET ?`
  ).bind(address, limit, offset).all();

  const rows = (result.results || []).map(mailListRow);
  return json({ results: rows, data: rows });
}

async function handleAppMailDetail(request, env, id) {
  const user = await requireUser(request, env);

  if (!isValidMailId(id)) {
    return errorJson("mail_not_found", 404);
  }

  const mail = await env.MAIL_DB.prepare(
    `SELECT m.id, m.sender, m.recipient, m.subject, m.raw_key, m.raw_size, m.message_id, m.created_at
     FROM mails m
     JOIN addresses a ON a.address = m.address
     WHERE m.id = ? AND a.user_id = ?
     LIMIT 1`
  ).bind(id, user.id).first();

  if (!mail) {
    return errorJson("mail_not_found", 404);
  }

  const raw = await getRawMail(env, mail.raw_key);
  if (!raw) {
    return errorJson("mail_raw_not_found", 404);
  }

  return json({
    ...mailListRow(mail),
    raw,
  });
}

async function handleMailList(request, env, url) {
  const auth = await requireAddressJwt(request, env);
  const limit = clampInt(url.searchParams.get("limit"), 5, 1, 50);
  const offset = clampInt(url.searchParams.get("offset"), 0, 0, 10000);

  const result = await env.MAIL_DB.prepare(
    `SELECT id, sender, recipient, subject, raw_size, message_id, created_at
     FROM mails
     WHERE address = ?
     ORDER BY created_at DESC, id DESC
     LIMIT ? OFFSET ?`
  ).bind(auth.address, limit, offset).all();

  const rows = (result.results || []).map(mailListRow);
  return json({ results: rows, data: rows });
}

async function handleMailDetail(request, env, id) {
  const auth = await requireAddressJwt(request, env);

  if (!isValidMailId(id)) {
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

  const raw = await getRawMail(env, mail.raw_key);
  if (!raw) {
    return errorJson("mail_raw_not_found", 404);
  }

  return json({
    id: mail.id,
    _id: mail.id,
    raw,
  });
}

async function createOwnedAddressWithDebit(env, userId, name, domain) {
  if (!isAllowedDomain(env, domain)) {
    throw httpError("domain_not_allowed", 400);
  }

  const address = `${name}@${domain}`;
  const existing = await getAddressOwner(env, address);

  if (existing && hasOwner(existing.user_id)) {
    if (Number(existing.user_id) === Number(userId)) {
      const jwt = await refreshAddressJwt(env, address);
      return { address, jwt, created: false };
    }

    throw httpError("address_exists", 409);
  }

  await debitCredits(env, userId, 1);

  try {
    return await claimAddressForUser(env, userId, name, domain);
  } catch (error) {
    await addCredits(env, userId, 1);
    throw error;
  }
}

async function createOwnedAddressBatch(env, userId, options) {
  if (!isAllowedDomain(env, options.domain)) {
    throw httpError("domain_not_allowed", 400);
  }

  if (options.prefix) {
    return createSequentialOwnedAddressBatch(env, userId, options);
  }

  await debitCredits(env, userId, options.count);

  const addresses = [];
  let attempts = 0;
  const maxAttempts = options.count * 20;

  while (addresses.length < options.count && attempts < maxAttempts) {
    attempts += 1;
    try {
      const created = await claimAddressForUser(env, userId, createAddressName(), options.domain);
      addresses.push(created);
    } catch (error) {
      if (error.message !== "address_exists") {
        const missing = options.count - addresses.length;
        if (missing > 0) {
          await addCredits(env, userId, missing);
        }
        throw error;
      }
    }
  }

  if (addresses.length < options.count) {
    const missing = options.count - addresses.length;
    await addCredits(env, userId, missing);
    if (addresses.length === 0) {
      throw httpError("unable_to_create_addresses", 500);
    }
  }

  return addresses;
}

async function createSequentialOwnedAddressBatch(env, userId, options) {
  if (!/^[a-z0-9._-]{1,48}$/.test(options.prefix)) {
    throw httpError("invalid_prefix", 400);
  }

  const names = [];
  for (let index = 0; index < options.count; index += 1) {
    names.push(normalizeAddressName(`${options.prefix}${String(options.startAt + index).padStart(3, "0")}`));
  }

  if (new Set(names).size !== names.length) {
    throw httpError("duplicate_address_names", 400);
  }

  await assertAddressesAvailable(env, names.map((name) => `${name}@${options.domain}`));
  await debitCredits(env, userId, options.count);

  const addresses = [];
  try {
    for (const name of names) {
      addresses.push(await claimAddressForUser(env, userId, name, options.domain));
    }
  } catch (error) {
    const missing = options.count - addresses.length;
    if (missing > 0) {
      await addCredits(env, userId, missing);
    }
    throw error;
  }

  return addresses;
}

async function claimAddressForUser(env, userId, name, domain) {
  const address = `${name}@${domain}`;
  const existing = await getAddressOwner(env, address);
  const iat = Math.floor(Date.now() / 1000);
  const jwt = await signJwt(env, { address, iat });

  if (existing && hasOwner(existing.user_id)) {
    throw httpError("address_exists", 409);
  }

  if (existing) {
    const update = await env.MAIL_DB.prepare(
      `UPDATE addresses
       SET user_id = ?, name = ?, domain = ?, last_jwt_iat = ?
       WHERE address = ? AND user_id IS NULL`
    ).bind(userId, name, domain, iat, address).run();

    if (!hasChanges(update)) {
      throw httpError("address_exists", 409);
    }

    return { address, jwt, created: true };
  }

  const insert = await env.MAIL_DB.prepare(
    `INSERT INTO addresses (address, name, domain, user_id, last_jwt_iat)
     VALUES (?, ?, ?, ?, ?)
     ON CONFLICT(address) DO NOTHING`
  ).bind(address, name, domain, userId, iat).run();

  if (!hasChanges(insert)) {
    throw httpError("address_exists", 409);
  }

  return { address, jwt, created: true };
}

async function assertAddressesAvailable(env, addresses) {
  const placeholders = addresses.map(() => "?").join(",");
  const result = await env.MAIL_DB.prepare(
    `SELECT address, user_id
     FROM addresses
     WHERE address IN (${placeholders})`
  ).bind(...addresses).all();
  const taken = (result.results || []).filter((row) => hasOwner(row.user_id));

  if (taken.length > 0) {
    throw httpError(`address_exists:${taken[0].address}`, 409);
  }
}

async function getAddressOwner(env, address) {
  return env.MAIL_DB.prepare(
    `SELECT address, user_id
     FROM addresses
     WHERE address = ?
     LIMIT 1`
  ).bind(address).first();
}

async function refreshAddressJwt(env, address) {
  const iat = Math.floor(Date.now() / 1000);
  const jwt = await signJwt(env, { address, iat });

  await env.MAIL_DB.prepare(
    `UPDATE addresses
     SET last_jwt_iat = ?
     WHERE address = ?`
  ).bind(iat, address).run();

  return jwt;
}

async function requireOwnedAddress(env, userId, address) {
  if (!address || !isAllowedDomain(env, getEmailDomain(address))) {
    throw httpError("address_not_found", 404);
  }

  const ownedAddress = await env.MAIL_DB.prepare(
    `SELECT address
     FROM addresses
     WHERE address = ? AND user_id = ?
     LIMIT 1`
  ).bind(address, userId).first();

  if (!ownedAddress) {
    throw httpError("address_not_found", 404);
  }

  return ownedAddress;
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
    await deleteRawMail(env, row.raw_key);
    await env.MAIL_DB.prepare("DELETE FROM mails WHERE id = ?").bind(row.id).run();
  }
}

async function putRawMail(env, rawKey, rawBuffer, rawText, metadata) {
  if (env.MAIL_RAW) {
    await env.MAIL_RAW.put(rawKey, rawBuffer, {
      httpMetadata: {
        contentType: "message/rfc822",
      },
      customMetadata: metadata,
    });
    return;
  }

  await env.MAIL_KV.put(rawKey, rawText);
}

async function getRawMail(env, rawKey) {
  if (env.MAIL_RAW) {
    const rawObject = await env.MAIL_RAW.get(rawKey);
    return rawObject ? rawObject.text() : null;
  }

  return env.MAIL_KV.get(rawKey);
}

async function deleteRawMail(env, rawKey) {
  if (env.MAIL_RAW) {
    await env.MAIL_RAW.delete(rawKey);
    return;
  }

  await env.MAIL_KV.delete(rawKey);
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
    `CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      password_salt TEXT NOT NULL,
      credits INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`
  ).run();

  await env.MAIL_DB.prepare(
    `CREATE TABLE IF NOT EXISTS addresses (
      address TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      domain TEXT NOT NULL,
      user_id INTEGER,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      last_jwt_iat INTEGER
    )`
  ).run();

  await ensureColumn(env, "addresses", "user_id", "user_id INTEGER");

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
    `CREATE TABLE IF NOT EXISTS redeem_codes (
      code TEXT PRIMARY KEY,
      credits INTEGER NOT NULL,
      max_uses INTEGER NOT NULL DEFAULT 1,
      used_count INTEGER NOT NULL DEFAULT 0,
      expires_at TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`
  ).run();

  await env.MAIL_DB.prepare(
    `CREATE TABLE IF NOT EXISTS redeem_uses (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      code TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(user_id, code)
    )`
  ).run();

  await env.MAIL_DB.prepare(
    `CREATE TABLE IF NOT EXISTS user_api_keys (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      name TEXT NOT NULL DEFAULT 'default',
      key_prefix TEXT NOT NULL,
      key_hash TEXT NOT NULL UNIQUE,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      last_used_at TEXT,
      revoked_at TEXT
    )`
  ).run();

  await env.MAIL_DB.prepare(
    `CREATE INDEX IF NOT EXISTS idx_addresses_user
     ON addresses(user_id, created_at DESC)`
  ).run();

  await env.MAIL_DB.prepare(
    `CREATE INDEX IF NOT EXISTS idx_mails_address_created
     ON mails(address, created_at DESC)`
  ).run();

  await env.MAIL_DB.prepare(
    `CREATE INDEX IF NOT EXISTS idx_mails_message_id
     ON mails(message_id)`
  ).run();

  await env.MAIL_DB.prepare(
    `CREATE INDEX IF NOT EXISTS idx_redeem_uses_code
     ON redeem_uses(code, created_at DESC)`
  ).run();

  await env.MAIL_DB.prepare(
    `CREATE INDEX IF NOT EXISTS idx_user_api_keys_user
     ON user_api_keys(user_id, created_at DESC)`
  ).run();
}

async function ensureColumn(env, table, column, definition) {
  const result = await env.MAIL_DB.prepare(`PRAGMA table_info(${table})`).all();
  const exists = (result.results || []).some((row) => row.name === column);

  if (!exists) {
    await env.MAIL_DB.prepare(`ALTER TABLE ${table} ADD COLUMN ${definition}`).run();
  }
}

async function readJsonBody(request) {
  try {
    const body = await request.json();
    return body && typeof body === "object" ? body : {};
  } catch {
    return {};
  }
}

async function requireAdmin(request, env) {
  const adminAuth = request.headers.get("x-admin-auth") || "";
  if (!env.EMAIL_AUTH || !safeEqual(adminAuth, env.EMAIL_AUTH)) {
    throw httpError("unauthorized", 401);
  }
}

async function requireAddressCreator(request, env) {
  const headerAuth = request.headers.get("x-admin-auth") || "";

  if (env.EMAIL_AUTH && safeEqual(headerAuth, env.EMAIL_AUTH)) {
    return { type: "admin" };
  }

  const user = await getUserByApiKey(env, headerAuth);
  if (user) {
    return { type: "user", user };
  }

  throw httpError("unauthorized", 401);
}

async function requireAddressJwt(request, env) {
  const payload = await requireBearerPayload(request, env);
  const address = normalizeEmail(payload.address || "");
  const domain = getEmailDomain(address);

  if (!address || !isAllowedDomain(env, domain)) {
    throw httpError("unauthorized", 401);
  }

  return { address };
}

async function requireUser(request, env) {
  const token = getBearerToken(request);

  if (isValidApiKey(token)) {
    const user = await getUserByApiKey(env, token);
    if (user) {
      return user;
    }
  }

  return requireUserSession(request, env);
}

async function requireUserSession(request, env) {
  const payload = await requireBearerPayload(request, env);

  if (payload.type !== "user" || !payload.userId) {
    throw httpError("unauthorized", 401);
  }

  const user = await getUserById(env, payload.userId);
  if (!user) {
    throw httpError("unauthorized", 401);
  }

  return user;
}

async function requireBearerPayload(request, env) {
  return verifyJwt(env, getBearerToken(request));
}

function getBearerToken(request) {
  const authorization = request.headers.get("authorization") || "";
  const match = authorization.match(/^Bearer\s+(.+)$/i);

  if (!match) {
    throw httpError("unauthorized", 401);
  }

  return match[1].trim();
}

async function signUserToken(env, user) {
  const now = Math.floor(Date.now() / 1000);
  return signJwt(env, {
    type: "user",
    userId: user.id,
    username: user.username,
    iat: now,
    exp: now + USER_SESSION_TTL_SECONDS,
  });
}

async function getUserByUsername(env, username) {
  return env.MAIL_DB.prepare(
    `SELECT id, username, password_hash, password_salt, credits, created_at
     FROM users
     WHERE username = ?
     LIMIT 1`
  ).bind(username).first();
}

async function getUserById(env, userId) {
  return env.MAIL_DB.prepare(
    `SELECT id, username, password_hash, password_salt, credits, created_at
     FROM users
     WHERE id = ?
     LIMIT 1`
  ).bind(userId).first();
}

async function getUserByApiKey(env, apiKey) {
  if (!isValidApiKey(apiKey)) {
    return null;
  }

  const keyHash = await sha256Base64url(apiKey);
  const row = await env.MAIL_DB.prepare(
    `SELECT
       u.id,
       u.username,
       u.password_hash,
       u.password_salt,
       u.credits,
       u.created_at,
       k.id AS api_key_id
     FROM user_api_keys k
     JOIN users u ON u.id = k.user_id
     WHERE k.key_hash = ? AND k.revoked_at IS NULL
     LIMIT 1`
  ).bind(keyHash).first();

  if (!row) {
    return null;
  }

  await env.MAIL_DB.prepare(
    `UPDATE user_api_keys
     SET last_used_at = CURRENT_TIMESTAMP
     WHERE id = ?`
  ).bind(row.api_key_id).run();

  return {
    id: row.id,
    username: row.username,
    password_hash: row.password_hash,
    password_salt: row.password_salt,
    credits: row.credits,
    created_at: row.created_at,
  };
}

async function hashPassword(password, salt = randomHex(16)) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: new TextEncoder().encode(salt),
      iterations: PASSWORD_ITERATIONS,
    },
    key,
    256
  );

  return {
    salt,
    hash: base64urlEncodeBytes(bits),
  };
}

async function verifyPassword(password, salt, expectedHash) {
  const passwordRecord = await hashPassword(password, salt);
  return safeEqual(passwordRecord.hash, expectedHash);
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

async function sha256Base64url(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return base64urlEncodeBytes(digest);
}

async function debitCredits(env, userId, amount) {
  const result = await env.MAIL_DB.prepare(
    `UPDATE users
     SET credits = credits - ?
     WHERE id = ? AND credits >= ?`
  ).bind(amount, userId, amount).run();

  if (!hasChanges(result)) {
    throw httpError("insufficient_credits", 402);
  }
}

async function addCredits(env, userId, amount) {
  await env.MAIL_DB.prepare(
    `UPDATE users
     SET credits = credits + ?
     WHERE id = ?`
  ).bind(amount, userId).run();
}

function sessionPayload(user, token) {
  return {
    token,
    user: publicUser(user),
  };
}

function publicUser(user) {
  return {
    id: user.id,
    username: user.username,
    credits: Number(user.credits || 0),
    created_at: user.created_at,
  };
}

function mailListRow(mail) {
  return {
    id: mail.id,
    _id: mail.id,
    from: mail.sender,
    to: mail.recipient,
    subject: mail.subject || "",
    raw_size: mail.raw_size,
    message_id: mail.message_id || "",
    created_at: mail.created_at,
  };
}

function apiKeyRow(row) {
  return {
    id: row.id,
    name: row.name,
    key_prefix: row.key_prefix,
    created_at: row.created_at,
    last_used_at: row.last_used_at,
    revoked_at: row.revoked_at,
    active: !row.revoked_at,
  };
}

function hasChanges(result) {
  return Number(result?.meta?.changes || 0) > 0;
}

function hasOwner(userId) {
  return userId !== null && userId !== undefined && userId !== "";
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
  const leftText = String(left || "");
  const rightText = String(right || "");
  let diff = leftText.length ^ rightText.length;
  const length = Math.max(leftText.length, rightText.length);

  for (let index = 0; index < length; index += 1) {
    diff |= (leftText.charCodeAt(index) || 0) ^ (rightText.charCodeAt(index) || 0);
  }

  return diff === 0;
}

function createMailId() {
  return `mail_${Date.now().toString(36)}_${randomHex(8)}`;
}

function createAddressName() {
  return `nv${randomHex(5)}`;
}

function createRedeemCode() {
  return `SM-${randomHex(4)}-${randomHex(4)}-${randomHex(4)}`.toUpperCase();
}

function createApiKey() {
  return `smk_${randomHex(32)}`;
}

function randomHex(length) {
  const bytes = new Uint8Array(Math.ceil(length / 2));
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("").slice(0, length);
}

function normalizeUsername(value) {
  const username = String(value || "").trim().toLowerCase();

  if (!/^[a-z0-9._-]{3,32}$/.test(username)) {
    throw httpError("invalid_username", 400);
  }

  return username;
}

function normalizePassword(value) {
  const password = String(value || "");

  if (password.length < 6 || password.length > 128) {
    throw httpError("invalid_password", 400);
  }

  return password;
}

function normalizeApiKeyName(value) {
  const name = String(value || "").trim();

  if (name.length < 1 || name.length > 40) {
    throw httpError("invalid_api_key_name", 400);
  }

  return name;
}

function isValidApiKey(value) {
  return /^smk_[a-f0-9]{32}$/.test(String(value || "").trim());
}

function normalizeRedeemCode(value) {
  const code = String(value || "").trim().toUpperCase();

  if (!/^[A-Z0-9-]{4,64}$/.test(code)) {
    throw httpError("invalid_redeem_code", 400);
  }

  return code;
}

function normalizeNullableDate(value) {
  if (!value) {
    return null;
  }

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    throw httpError("invalid_expires_at", 400);
  }

  return date.toISOString();
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

function getDefaultDomain(env) {
  return Array.from(getAllowedDomains(env))[0] || "";
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

function getMaxBatchCreate(env) {
  const value = Number(env.MAX_BATCH_CREATE || DEFAULT_MAX_BATCH_CREATE);
  return Number.isFinite(value) && value > 0 ? Math.min(500, Math.floor(value)) : DEFAULT_MAX_BATCH_CREATE;
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

function parsePositiveInt(value, errorMessage, min, max) {
  const parsed = Number.parseInt(value, 10);

  if (!Number.isFinite(parsed) || parsed < min || parsed > max) {
    throw httpError(errorMessage, 400);
  }

  return parsed;
}

function isValidMailId(id) {
  return /^[A-Za-z0-9_.:-]{1,128}$/.test(id);
}

function ensureBindings(env) {
  if (!env.MAIL_DB) {
    throw httpError("missing_mail_db_binding", 500);
  }
  if (!env.MAIL_RAW && !env.MAIL_KV) {
    throw httpError("missing_mail_storage_binding", 500);
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

function html(markup) {
  return new Response(markup, {
    headers: HTML_HEADERS,
  });
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

function getAppHtml(env) {
  const appConfig = JSON.stringify({
    domains: Array.from(getAllowedDomains(env)),
    defaultDomain: getDefaultDomain(env),
  }).replace(/</g, "\\u003c");

  return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Small Mailbox</title>
  <style>
    :root {
      color-scheme: dark;
      --bg: #09110f;
      --bg-soft: #0e1a17;
      --panel: rgba(16, 31, 27, 0.78);
      --panel-strong: #13231f;
      --line: rgba(186, 255, 231, 0.14);
      --line-strong: rgba(186, 255, 231, 0.28);
      --text: #edf8f3;
      --muted: #99aca5;
      --faint: #64766f;
      --primary: #69e6bd;
      --primary-strong: #22c596;
      --danger: #ff827d;
      --warn: #f5c56b;
      --shadow: 0 24px 70px rgba(0, 0, 0, 0.34);
      --radius-xl: 28px;
      --radius-lg: 20px;
      --radius-md: 14px;
      --radius-sm: 10px;
      font-family: Aptos, "Microsoft YaHei UI", "Segoe UI", sans-serif;
    }

    * { box-sizing: border-box; }

    body {
      margin: 0;
      min-height: 100vh;
      background:
        radial-gradient(circle at top left, rgba(105, 230, 189, 0.16), transparent 34rem),
        linear-gradient(145deg, #07100d 0%, var(--bg) 48%, #0b1512 100%);
      color: var(--text);
      text-wrap: pretty;
    }

    button, input, select {
      font: inherit;
    }

    button {
      border: 0;
      cursor: pointer;
    }

    .shell {
      width: min(1220px, calc(100% - 32px));
      margin: 0 auto;
      padding: 32px 0;
    }

    .hero {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 20px;
      align-items: end;
      margin-bottom: 22px;
    }

    .eyebrow {
      color: var(--primary);
      font-size: 12px;
      font-weight: 800;
      letter-spacing: .22em;
      text-transform: uppercase;
      margin-bottom: 12px;
    }

    h1, h2, h3, p {
      margin: 0;
    }

    h1 {
      max-width: 760px;
      font-size: clamp(34px, 5vw, 64px);
      line-height: 0.96;
      letter-spacing: -0.06em;
    }

    .hero p {
      max-width: 720px;
      margin-top: 16px;
      color: var(--muted);
      font-size: 16px;
      line-height: 1.8;
    }

    .status-card {
      min-width: 236px;
      padding: 18px;
      border: 1px solid var(--line);
      border-radius: var(--radius-lg);
      background: rgba(105, 230, 189, 0.08);
      box-shadow: var(--shadow);
    }

    .status-card span {
      display: block;
      color: var(--faint);
      font-size: 12px;
      margin-bottom: 10px;
    }

    .status-card strong {
      font-size: 30px;
      letter-spacing: -0.04em;
    }

    .layout {
      display: grid;
      grid-template-columns: 360px minmax(0, 1fr);
      gap: 18px;
      align-items: start;
    }

    .panel {
      border: 1px solid var(--line);
      border-radius: var(--radius-xl);
      background: var(--panel);
      box-shadow: var(--shadow);
      backdrop-filter: blur(18px);
      overflow: hidden;
    }

    .panel-header {
      padding: 20px 20px 0;
      display: flex;
      justify-content: space-between;
      gap: 16px;
      align-items: center;
    }

    .panel-title {
      font-size: 18px;
      letter-spacing: -0.02em;
    }

    .panel-body {
      padding: 20px;
    }

    .tabs {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 8px;
      padding: 8px;
      margin: 0 20px 4px;
      border: 1px solid var(--line);
      border-radius: 999px;
      background: rgba(255, 255, 255, 0.03);
    }

    .tab {
      color: var(--muted);
      border-radius: 999px;
      padding: 10px 12px;
      background: transparent;
      transition: background .16s ease, color .16s ease;
    }

    .tab.active {
      color: #062019;
      background: var(--primary);
    }

    .form {
      display: grid;
      gap: 12px;
    }

    label {
      display: grid;
      gap: 8px;
      color: var(--muted);
      font-size: 13px;
    }

    input, select {
      width: 100%;
      color: var(--text);
      border: 1px solid var(--line);
      border-radius: var(--radius-md);
      background: rgba(4, 12, 10, 0.66);
      outline: none;
      padding: 12px 13px;
      transition: border-color .16s ease, box-shadow .16s ease, background .16s ease;
    }

    input:focus, select:focus {
      border-color: var(--primary);
      box-shadow: 0 0 0 4px rgba(105, 230, 189, 0.13);
      background: rgba(5, 15, 12, 0.92);
    }

    .button {
      min-height: 44px;
      border-radius: var(--radius-md);
      color: #062019;
      background: linear-gradient(180deg, var(--primary), var(--primary-strong));
      font-weight: 800;
      transition: transform .16s ease, filter .16s ease;
    }

    .button:hover { filter: brightness(1.06); }
    .button:active { transform: translateY(1px); }
    .button:disabled {
      cursor: not-allowed;
      opacity: .52;
      filter: grayscale(.4);
    }

    .button.secondary {
      color: var(--text);
      border: 1px solid var(--line);
      background: rgba(255, 255, 255, 0.04);
    }

    .button.danger {
      color: #2b0c0a;
      background: var(--danger);
    }

    .stack {
      display: grid;
      gap: 14px;
    }

    .split {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 12px;
    }

    .profile {
      display: grid;
      gap: 14px;
    }

    .metric {
      border: 1px solid var(--line);
      border-radius: var(--radius-lg);
      padding: 16px;
      background: rgba(255, 255, 255, 0.035);
    }

    .metric span {
      display: block;
      color: var(--muted);
      font-size: 12px;
      margin-bottom: 8px;
    }

    .metric strong {
      font-size: 28px;
      letter-spacing: -0.03em;
    }

    .workspace {
      display: grid;
      grid-template-columns: minmax(240px, 330px) minmax(0, 1fr);
      min-height: 680px;
    }

    .address-column {
      border-right: 1px solid var(--line);
      min-width: 0;
    }

    .mail-column {
      min-width: 0;
      display: grid;
      grid-template-rows: auto minmax(0, 1fr);
    }

    .list {
      display: grid;
      gap: 8px;
      padding: 20px;
      max-height: 600px;
      overflow: auto;
    }

    .item {
      width: 100%;
      text-align: left;
      color: var(--text);
      border: 1px solid var(--line);
      border-radius: var(--radius-md);
      background: rgba(255, 255, 255, 0.035);
      padding: 12px;
      transition: border-color .16s ease, transform .16s ease, background .16s ease;
    }

    .item:hover {
      border-color: var(--line-strong);
      background: rgba(255, 255, 255, 0.055);
    }

    .item.active {
      border-color: var(--primary);
      background: rgba(105, 230, 189, 0.11);
    }

    .item strong {
      display: block;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      margin-bottom: 6px;
    }

    .item span {
      color: var(--muted);
      font-size: 12px;
    }

    .item-actions {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 10px;
      margin-top: 10px;
    }

    .button.mini {
      min-height: 34px;
      padding: 0 12px;
      font-size: 12px;
    }

    .mail-list {
      display: grid;
      gap: 10px;
      padding: 20px;
      border-bottom: 1px solid var(--line);
      max-height: 270px;
      overflow: auto;
    }

    .mail-detail {
      min-height: 0;
      padding: 20px;
      overflow: auto;
    }

    .code-box {
      display: none;
      margin-bottom: 14px;
      border: 1px solid rgba(105, 230, 189, 0.36);
      border-radius: var(--radius-lg);
      padding: 16px;
      background: rgba(105, 230, 189, 0.1);
    }

    .code-box.visible {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
    }

    .code-box strong {
      font-size: 28px;
      letter-spacing: .04em;
    }

    pre {
      margin: 0;
      white-space: pre-wrap;
      word-break: break-word;
      color: #d7e8e1;
      border: 1px solid var(--line);
      border-radius: var(--radius-lg);
      background: rgba(2, 7, 6, 0.68);
      padding: 16px;
      font-family: "Cascadia Mono", "SFMono-Regular", Consolas, monospace;
      font-size: 12px;
      line-height: 1.7;
    }

    .hint {
      color: var(--faint);
      font-size: 12px;
      line-height: 1.6;
    }

    .empty {
      color: var(--muted);
      border: 1px dashed var(--line-strong);
      border-radius: var(--radius-lg);
      padding: 18px;
      line-height: 1.7;
      background: rgba(255, 255, 255, 0.025);
    }

    .hidden {
      display: none !important;
    }

    .toast {
      position: fixed;
      right: 22px;
      bottom: 22px;
      max-width: 360px;
      color: var(--text);
      border: 1px solid var(--line);
      border-radius: 16px;
      background: rgba(8, 18, 15, 0.94);
      box-shadow: var(--shadow);
      padding: 14px 16px;
      opacity: 0;
      pointer-events: none;
      transform: translateY(10px);
      transition: opacity .18s ease, transform .18s ease;
    }

    .toast.visible {
      opacity: 1;
      transform: translateY(0);
    }

    .admin-box {
      margin-top: 14px;
      border-top: 1px solid var(--line);
      padding-top: 14px;
    }

    .result-box {
      max-height: 150px;
      overflow: auto;
      border: 1px solid var(--line);
      border-radius: var(--radius-md);
      background: rgba(255, 255, 255, 0.035);
      padding: 10px;
      color: var(--muted);
      font-size: 12px;
      line-height: 1.7;
      white-space: pre-wrap;
      word-break: break-word;
    }

    @media (max-width: 980px) {
      .hero, .layout, .workspace {
        grid-template-columns: 1fr;
      }

      .address-column {
        border-right: 0;
        border-bottom: 1px solid var(--line);
      }
    }

    @media (max-width: 620px) {
      .shell {
        width: min(100% - 20px, 1220px);
        padding: 18px 0;
      }

      .split {
        grid-template-columns: 1fr;
      }

      .panel-body, .panel-header, .list, .mail-list, .mail-detail {
        padding: 16px;
      }
    }

    @media (prefers-reduced-motion: reduce) {
      *, *::before, *::after {
        transition: none !important;
      }
    }
  </style>
</head>
<body>
  <div class="shell">
    <header class="hero">
      <div>
        <div class="eyebrow">Small Mailbox</div>
        <h1>把无限前缀域名邮箱，变成可售卖的批量额度。</h1>
        <p>用户注册账号后，用兑换码充值次数。每创建一个邮箱消耗 1 次，可以批量随机生成，也可以手动创建 001、002、jsbxbx 这类自定义前缀。</p>
      </div>
      <div class="status-card">
        <span>当前额度</span>
        <strong id="heroCredits">未登录</strong>
      </div>
    </header>

    <main class="layout">
      <section class="panel" id="authPanel">
        <div class="panel-header">
          <h2 class="panel-title">账号入口</h2>
        </div>
        <div class="tabs">
          <button class="tab active" id="loginTab" type="button">登录</button>
          <button class="tab" id="registerTab" type="button">注册</button>
        </div>
        <div class="panel-body">
          <form class="form" id="loginForm">
            <label>账号
              <input name="username" autocomplete="username" placeholder="tyreamon">
            </label>
            <label>密码
              <input name="password" type="password" autocomplete="current-password" placeholder="至少 6 位">
            </label>
            <button class="button" type="submit">登录控制台</button>
          </form>
          <form class="form hidden" id="registerForm">
            <label>账号
              <input name="username" autocomplete="username" placeholder="给买家自己的账号">
            </label>
            <label>密码
              <input name="password" type="password" autocomplete="new-password" placeholder="至少 6 位">
            </label>
            <button class="button" type="submit">创建账号</button>
            <p class="hint">注册默认开启；如果你想关闭公开注册，把环境变量 ALLOW_REGISTRATION 设置为 false。</p>
          </form>
        </div>
      </section>

      <section class="panel hidden" id="accountPanel">
        <div class="panel-header">
          <h2 class="panel-title">账户与额度</h2>
          <button class="button secondary" id="logoutButton" type="button">退出</button>
        </div>
        <div class="panel-body profile">
          <div class="split">
            <div class="metric">
              <span>账号</span>
              <strong id="profileName">-</strong>
            </div>
            <div class="metric">
              <span>可创建次数</span>
              <strong id="profileCredits">0</strong>
            </div>
          </div>
          <form class="form" id="redeemForm">
            <label>兑换码
              <input name="code" placeholder="SM-XXXX-XXXX-XXXX">
            </label>
            <button class="button" type="submit">兑换次数</button>
          </form>

          <div class="admin-box">
            <h3 class="panel-title">脚本 API 密钥</h3>
            <p class="hint">给 nvidia-register 这类脚本用：把这里生成的密钥填到脚本 .env 的 EMAIL_AUTH，它只能消耗并读取当前账号自己的邮箱池。</p>
            <form class="form" id="apiKeyForm">
              <label>密钥名称
                <input name="name" placeholder="nvidia-register">
              </label>
              <button class="button secondary" type="submit">生成用户 API Key</button>
            </form>
            <div class="result-box hidden" id="apiKeyResult"></div>
            <div class="stack" id="apiKeyList"></div>
          </div>

          <div class="admin-box">
            <h3 class="panel-title">管理员发码</h3>
            <p class="hint">用 EMAIL_AUTH 管理员密钥生成兑换码，例如 50 次或 100 次，发给买家后让他自己注册并兑换。</p>
            <form class="form" id="adminCodeForm">
              <label>管理员密钥
                <input name="auth" type="password" placeholder="EMAIL_AUTH">
              </label>
              <div class="split">
                <label>次数
                  <input name="credits" type="number" min="1" value="50">
                </label>
                <label>可用人数
                  <input name="maxUses" type="number" min="1" value="1">
                </label>
              </div>
              <button class="button secondary" type="submit">生成兑换码</button>
            </form>
            <div class="result-box hidden" id="adminResult"></div>
          </div>
        </div>
      </section>

      <section class="panel workspace">
        <div class="address-column">
          <div class="panel-header">
            <h2 class="panel-title">邮箱地址</h2>
          </div>
          <div class="panel-body stack" id="createForms">
            <form class="form" id="singleAddressForm">
              <div class="split">
                <label>前缀
                  <input name="name" placeholder="001 / jsbxbx / 留空随机">
                </label>
                <label>域名
                  <select name="domain" id="singleDomain"></select>
                </label>
              </div>
              <button class="button" type="submit">创建 1 个邮箱</button>
            </form>
            <form class="form" id="batchAddressForm">
              <div class="split">
                <label>数量
                  <input name="count" type="number" min="1" value="50">
                </label>
                <label>域名
                  <select name="domain" id="batchDomain"></select>
                </label>
              </div>
              <div class="split">
                <label>批量前缀
                  <input name="prefix" placeholder="nv 留空则随机">
                </label>
                <label>起始编号
                  <input name="startAt" type="number" min="0" value="1">
                </label>
              </div>
              <button class="button secondary" type="submit">批量创建</button>
            </form>
          </div>
          <div class="list" id="addressList">
            <div class="empty">登录后会显示你拥有的邮箱。</div>
          </div>
        </div>

        <div class="mail-column">
          <div class="mail-list" id="mailList">
            <div class="empty">选择一个邮箱后查看收件箱。</div>
          </div>
          <div class="mail-detail">
            <div class="code-box" id="codeBox">
              <div>
                <span class="hint">识别到验证码</span>
                <strong id="codeText"></strong>
              </div>
              <button class="button secondary" id="copyCodeButton" type="button">复制</button>
            </div>
            <pre id="mailRaw">邮件原文会显示在这里。</pre>
          </div>
        </div>
      </section>
    </main>
  </div>

  <div class="toast" id="toast"></div>

  <script>
    window.APP_CONFIG = ${appConfig};

    const state = {
      token: localStorage.getItem("small_mailbox_token") || "",
      user: null,
      domains: window.APP_CONFIG.domains || [],
      apiKeys: [],
      addresses: [],
      selectedAddress: "",
      mails: [],
      selectedMail: null,
      authMode: "login"
    };

    const nodes = {
      authPanel: document.getElementById("authPanel"),
      accountPanel: document.getElementById("accountPanel"),
      loginTab: document.getElementById("loginTab"),
      registerTab: document.getElementById("registerTab"),
      loginForm: document.getElementById("loginForm"),
      registerForm: document.getElementById("registerForm"),
      logoutButton: document.getElementById("logoutButton"),
      profileName: document.getElementById("profileName"),
      profileCredits: document.getElementById("profileCredits"),
      heroCredits: document.getElementById("heroCredits"),
      redeemForm: document.getElementById("redeemForm"),
      apiKeyForm: document.getElementById("apiKeyForm"),
      apiKeyList: document.getElementById("apiKeyList"),
      apiKeyResult: document.getElementById("apiKeyResult"),
      adminCodeForm: document.getElementById("adminCodeForm"),
      adminResult: document.getElementById("adminResult"),
      singleAddressForm: document.getElementById("singleAddressForm"),
      batchAddressForm: document.getElementById("batchAddressForm"),
      singleDomain: document.getElementById("singleDomain"),
      batchDomain: document.getElementById("batchDomain"),
      addressList: document.getElementById("addressList"),
      mailList: document.getElementById("mailList"),
      mailRaw: document.getElementById("mailRaw"),
      codeBox: document.getElementById("codeBox"),
      codeText: document.getElementById("codeText"),
      copyCodeButton: document.getElementById("copyCodeButton"),
      toast: document.getElementById("toast")
    };

    function escapeHtml(value) {
      return String(value || "").replace(/[&<>"']/g, function (char) {
        return {
          "&": "&amp;",
          "<": "&lt;",
          ">": "&gt;",
          '"': "&quot;",
          "'": "&#039;"
        }[char];
      });
    }

    async function api(path, options) {
      const requestOptions = options || {};
      const headers = Object.assign({ "content-type": "application/json" }, requestOptions.headers || {});

      if (state.token) {
        headers.authorization = "Bearer " + state.token;
      }

      const response = await fetch(path, Object.assign({}, requestOptions, { headers }));
      const data = await response.json().catch(function () { return {}; });

      if (!response.ok) {
        throw new Error(data.error || "request_failed");
      }

      return data;
    }

    function toast(message) {
      nodes.toast.textContent = message;
      nodes.toast.classList.add("visible");
      setTimeout(function () {
        nodes.toast.classList.remove("visible");
      }, 2600);
    }

    function setBusy(form, busy) {
      Array.from(form.querySelectorAll("button, input, select")).forEach(function (node) {
        node.disabled = busy;
      });
    }

    function formJson(form) {
      return Object.fromEntries(new FormData(form).entries());
    }

    function setAuthMode(mode) {
      state.authMode = mode;
      nodes.loginTab.classList.toggle("active", mode === "login");
      nodes.registerTab.classList.toggle("active", mode === "register");
      nodes.loginForm.classList.toggle("hidden", mode !== "login");
      nodes.registerForm.classList.toggle("hidden", mode !== "register");
    }

    function renderDomains() {
      const domains = state.domains.length ? state.domains : [window.APP_CONFIG.defaultDomain].filter(Boolean);
      const html = domains.map(function (domain) {
        return '<option value="' + escapeHtml(domain) + '">' + escapeHtml(domain) + '</option>';
      }).join("");
      nodes.singleDomain.innerHTML = html;
      nodes.batchDomain.innerHTML = html;
    }

    function renderAccount() {
      const loggedIn = Boolean(state.user);
      nodes.authPanel.classList.toggle("hidden", loggedIn);
      nodes.accountPanel.classList.toggle("hidden", !loggedIn);
      nodes.profileName.textContent = loggedIn ? state.user.username : "-";
      nodes.profileCredits.textContent = loggedIn ? state.user.credits : "0";
      nodes.heroCredits.textContent = loggedIn ? String(state.user.credits) : "未登录";
    }

    function renderAddresses() {
      if (!state.user) {
        nodes.addressList.innerHTML = '<div class="empty">登录后会显示你拥有的邮箱。</div>';
        return;
      }

      if (!state.addresses.length) {
        nodes.addressList.innerHTML = '<div class="empty">还没有邮箱。先兑换次数，再创建 001、002 或随机地址。</div>';
        return;
      }

      nodes.addressList.innerHTML = state.addresses.map(function (address) {
        const active = address.address === state.selectedAddress ? " active" : "";
        return '<button class="item' + active + '" data-address="' + escapeHtml(address.address) + '" type="button">' +
          '<strong>' + escapeHtml(address.address) + '</strong>' +
          '<span>' + Number(address.mail_count || 0) + ' 封邮件 · ' + escapeHtml(address.last_mail_at || "暂无来信") + '</span>' +
          '</button>';
      }).join("");
    }

    function renderApiKeys() {
      if (!state.user) {
        nodes.apiKeyList.innerHTML = "";
        nodes.apiKeyResult.classList.add("hidden");
        return;
      }

      const activeKeys = state.apiKeys.filter(function (key) { return key.active; });
      if (!activeKeys.length) {
        nodes.apiKeyList.innerHTML = '<div class="empty">还没有用户 API Key。生成后可直接给脚本使用。</div>';
        return;
      }

      nodes.apiKeyList.innerHTML = activeKeys.map(function (key) {
        return '<div class="item">' +
          '<strong>' + escapeHtml(key.name || "default") + '</strong>' +
          '<span>' + escapeHtml(key.key_prefix) + '•••• · 创建于 ' + escapeHtml(key.created_at || "") + '</span>' +
          '<div class="item-actions">' +
          '<span>最近使用：' + escapeHtml(key.last_used_at || "从未") + '</span>' +
          '<button class="button secondary mini" data-revoke-key="' + escapeHtml(key.id) + '" type="button">吊销</button>' +
          '</div>' +
          '</div>';
      }).join("");
    }

    function renderMails() {
      if (!state.selectedAddress) {
        nodes.mailList.innerHTML = '<div class="empty">选择一个邮箱后查看收件箱。</div>';
        nodes.mailRaw.textContent = "邮件原文会显示在这里。";
        nodes.codeBox.classList.remove("visible");
        return;
      }

      if (!state.mails.length) {
        nodes.mailList.innerHTML = '<div class="empty">' + escapeHtml(state.selectedAddress) + ' 暂时没有邮件。</div>';
        nodes.mailRaw.textContent = "等待来信后，点击邮件即可查看 raw 原文。";
        nodes.codeBox.classList.remove("visible");
        return;
      }

      nodes.mailList.innerHTML = state.mails.map(function (mail) {
        const active = state.selectedMail && state.selectedMail.id === mail.id ? " active" : "";
        return '<button class="item' + active + '" data-mail-id="' + escapeHtml(mail.id) + '" type="button">' +
          '<strong>' + escapeHtml(mail.subject || "(无主题)") + '</strong>' +
          '<span>' + escapeHtml(mail.from || "") + ' · ' + escapeHtml(mail.created_at || "") + '</span>' +
          '</button>';
      }).join("");
    }

    function renderMailDetail(mail) {
      if (!mail) {
        nodes.mailRaw.textContent = "邮件原文会显示在这里。";
        nodes.codeBox.classList.remove("visible");
        return;
      }

      nodes.mailRaw.textContent = mail.raw || "";
      const code = extractVerificationCode(mail.raw || "");
      nodes.codeText.textContent = code;
      nodes.codeBox.classList.toggle("visible", Boolean(code));
    }

    function extractVerificationCode(raw) {
      const match = raw.match(/\\b\\d{3}[-–]\\d{3}\\b/);
      return match ? match[0].replace("–", "-") : "";
    }

    async function loadMe() {
      const data = await api("/app/api/me");
      state.user = data.user;
      state.domains = data.domains || state.domains;
      renderDomains();
      renderAccount();
      await loadAddresses();
      await loadApiKeys();
    }

    async function loadApiKeys() {
      const data = await api("/app/api/api_keys");
      state.apiKeys = data.results || data.data || [];
      renderApiKeys();
    }

    async function loadAddresses() {
      const data = await api("/app/api/addresses");
      state.addresses = data.results || data.data || [];
      if (!state.selectedAddress && state.addresses.length) {
        state.selectedAddress = state.addresses[0].address;
      }
      renderAddresses();
      if (state.selectedAddress) {
        await loadMails(state.selectedAddress);
      } else {
        renderMails();
      }
    }

    async function loadMails(address) {
      state.selectedAddress = address;
      const data = await api("/app/api/mails?limit=20&offset=0&address=" + encodeURIComponent(address));
      state.mails = data.results || data.data || [];
      state.selectedMail = null;
      renderAddresses();
      renderMails();
    }

    async function openMail(id) {
      const data = await api("/app/api/mail/" + encodeURIComponent(id));
      state.selectedMail = data;
      renderMails();
      renderMailDetail(data);
    }

    async function copyText(value) {
      await navigator.clipboard.writeText(value);
      toast("已复制");
    }

    async function authSubmit(form, endpoint) {
      setBusy(form, true);
      try {
        const data = await api(endpoint, {
          method: "POST",
          body: JSON.stringify(formJson(form))
        });
        state.token = data.token;
        state.user = data.user;
        localStorage.setItem("small_mailbox_token", state.token);
        renderAccount();
        await loadAddresses();
        await loadApiKeys();
        toast("已进入控制台");
      } catch (error) {
        toast(error.message);
      } finally {
        setBusy(form, false);
      }
    }

    nodes.loginTab.addEventListener("click", function () { setAuthMode("login"); });
    nodes.registerTab.addEventListener("click", function () { setAuthMode("register"); });

    nodes.loginForm.addEventListener("submit", function (event) {
      event.preventDefault();
      authSubmit(nodes.loginForm, "/app/api/login");
    });

    nodes.registerForm.addEventListener("submit", function (event) {
      event.preventDefault();
      authSubmit(nodes.registerForm, "/app/api/register");
    });

    nodes.logoutButton.addEventListener("click", function () {
      localStorage.removeItem("small_mailbox_token");
      state.token = "";
      state.user = null;
      state.apiKeys = [];
      state.addresses = [];
      state.mails = [];
      state.selectedAddress = "";
      state.selectedMail = null;
      renderAccount();
      renderApiKeys();
      renderAddresses();
      renderMails();
      toast("已退出");
    });

    nodes.redeemForm.addEventListener("submit", async function (event) {
      event.preventDefault();
      setBusy(nodes.redeemForm, true);
      try {
        const data = await api("/app/api/redeem", {
          method: "POST",
          body: JSON.stringify(formJson(nodes.redeemForm))
        });
        state.user = data.user;
        renderAccount();
        nodes.redeemForm.reset();
        toast("兑换成功，增加 " + data.credits_added + " 次");
      } catch (error) {
        toast(error.message);
      } finally {
        setBusy(nodes.redeemForm, false);
      }
    });

    nodes.apiKeyForm.addEventListener("submit", async function (event) {
      event.preventDefault();
      setBusy(nodes.apiKeyForm, true);
      try {
        const data = await api("/app/api/api_keys", {
          method: "POST",
          body: JSON.stringify(formJson(nodes.apiKeyForm))
        });
        const domain = nodes.singleDomain.value || window.APP_CONFIG.defaultDomain || "";
        const envText = "EMAIL_API=" + location.origin + "\\n" +
          "EMAIL_AUTH=" + data.api_key + "\\n" +
          "EMAIL_DOMAIN=" + domain;
        nodes.apiKeyResult.classList.remove("hidden");
        nodes.apiKeyResult.textContent = envText;
        await copyText(data.api_key);
        await loadApiKeys();
        nodes.apiKeyForm.reset();
        toast("用户 API Key 已生成并复制");
      } catch (error) {
        toast(error.message);
      } finally {
        setBusy(nodes.apiKeyForm, false);
      }
    });

    nodes.apiKeyList.addEventListener("click", async function (event) {
      const button = event.target.closest("[data-revoke-key]");
      if (!button) return;
      try {
        await api("/app/api/api_keys/revoke", {
          method: "POST",
          body: JSON.stringify({ id: Number(button.dataset.revokeKey) })
        });
        await loadApiKeys();
        toast("API Key 已吊销");
      } catch (error) {
        toast(error.message);
      }
    });

    nodes.adminCodeForm.addEventListener("submit", async function (event) {
      event.preventDefault();
      setBusy(nodes.adminCodeForm, true);
      try {
        const values = formJson(nodes.adminCodeForm);
        const data = await api("/admin/redeem_codes", {
          method: "POST",
          headers: { "x-admin-auth": values.auth },
          body: JSON.stringify({
            credits: Number(values.credits),
            maxUses: Number(values.maxUses)
          })
        });
        nodes.adminResult.classList.remove("hidden");
        nodes.adminResult.innerHTML = '兑换码：<strong>' + escapeHtml(data.code) + '</strong><br>次数：' + data.credits + '<br>可用人数：' + data.max_uses;
        await copyText(data.code);
      } catch (error) {
        toast(error.message);
      } finally {
        setBusy(nodes.adminCodeForm, false);
      }
    });

    nodes.singleAddressForm.addEventListener("submit", async function (event) {
      event.preventDefault();
      setBusy(nodes.singleAddressForm, true);
      try {
        const values = formJson(nodes.singleAddressForm);
        const data = await api("/app/api/addresses", {
          method: "POST",
          body: JSON.stringify(values)
        });
        state.user = data.user;
        state.selectedAddress = data.address;
        renderAccount();
        await loadAddresses();
        nodes.singleAddressForm.reset();
        renderDomains();
        toast("邮箱已创建：" + data.address);
      } catch (error) {
        toast(error.message);
      } finally {
        setBusy(nodes.singleAddressForm, false);
      }
    });

    nodes.batchAddressForm.addEventListener("submit", async function (event) {
      event.preventDefault();
      setBusy(nodes.batchAddressForm, true);
      try {
        const values = formJson(nodes.batchAddressForm);
        const data = await api("/app/api/addresses/batch", {
          method: "POST",
          body: JSON.stringify({
            count: Number(values.count),
            domain: values.domain,
            prefix: values.prefix,
            startAt: Number(values.startAt)
          })
        });
        state.user = data.user;
        renderAccount();
        await loadAddresses();
        toast("批量创建完成：" + data.addresses.length + " 个");
      } catch (error) {
        toast(error.message);
      } finally {
        setBusy(nodes.batchAddressForm, false);
      }
    });

    nodes.addressList.addEventListener("click", async function (event) {
      const button = event.target.closest("[data-address]");
      if (!button) return;
      try {
        await loadMails(button.dataset.address);
      } catch (error) {
        toast(error.message);
      }
    });

    nodes.mailList.addEventListener("click", async function (event) {
      const button = event.target.closest("[data-mail-id]");
      if (!button) return;
      try {
        await openMail(button.dataset.mailId);
      } catch (error) {
        toast(error.message);
      }
    });

    nodes.copyCodeButton.addEventListener("click", function () {
      if (nodes.codeText.textContent) {
        copyText(nodes.codeText.textContent);
      }
    });

    renderDomains();
    renderAccount();
    renderApiKeys();
    renderAddresses();
    renderMails();

    if (state.token) {
      loadMe().catch(function () {
        localStorage.removeItem("small_mailbox_token");
        state.token = "";
        state.user = null;
        renderAccount();
        toast("登录已过期，请重新登录");
      });
    }
  </script>
</body>
</html>`;
}
