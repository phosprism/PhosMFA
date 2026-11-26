import {
  SESSION_MAX_AGE_SECONDS,
  signJson,
  verifySignedJson,
  signValue,
  verifySignedValue,
  hmacSha256,
  sha256Bytes,
  cookie,
  clearCookie,
  parseCookies,
  canAddSecrets,
  parseCsv,
  assertDiscordConfig,
  json,
  html,
  toBytes,
  hexToBytes,
  base64UrlEncode,
  base64UrlDecode,
  timingSafeEqual,
  getVaultRaw,
} from "./util.mjs";
import {
  COOKIE_SESSION,
  buildSession,
  handleAdminApi,
  handleMfaApi,
  loadUser,
  offlineKeyFor,
  requireFullAccess,
  securitySummary,
  sessionCookie,
  upsertUserOnLogin,
} from "./security.mjs";
const COOKIE_OAUTH_STATE = "mfa_oauth_state";
// ブラウザや iPhone がページの指定なしに探しに来るアイコン
const WELL_KNOWN_ICONS = {
  "/favicon.ico": "/icons/favicon.ico",
  "/apple-touch-icon.png": "/icons/apple-touch-icon.png",
  "/apple-touch-icon-precomposed.png": "/icons/apple-touch-icon.png",
};
const OAUTH_STATE_MAX_AGE_SECONDS = 60 * 10;

export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);

      const wellKnownIcon = WELL_KNOWN_ICONS[url.pathname];
      if (wellKnownIcon) return env.ASSETS.fetch(new Request(new URL(wellKnownIcon, url.origin), request));

      if (url.pathname === "/login") return renderLogin(request, env);
      if (url.pathname === "/auth/discord") return redirectToDiscord(request, env);
      if (url.pathname === "/auth/discord/callback") return handleDiscordCallback(request, env);
      if (url.pathname === "/logout") return logout();

      const session = await getSession(request, env);
      if (!session) {
        if (url.pathname.startsWith("/api/")) return json({ error: "unauthorized" }, 401);
        return Response.redirect(`${url.origin}/login`, 302);
      }
      if (!isSessionAllowed(session, env)) return revokeSession(request);

      // 管理者のロック・2段階認証リセットで epoch が変わると、それ以前のセッションは使えなくなる
      const user = await loadUser(env, session.id);
      if (!user || session.epoch !== user.session_epoch) return revokeSession(request);

      if (url.pathname === "/api/me") return currentUser(request, session, user, env);
      if (url.pathname.startsWith("/api/mfa/")) {
        return handleMfaApi(request, env, session, user, url.pathname.slice("/api/mfa".length));
      }

      if (url.pathname.startsWith("/api/")) {
        const denied = await requireFullAccess(request, env, session, user);
        if (denied) return denied;
      }

      if (url.pathname.startsWith("/api/admin/")) {
        return handleAdminApi(request, env, session, user, url.pathname.slice("/api/admin".length));
      }
      if (url.pathname === "/api/accounts" && request.method === "GET") return listAccounts(env, user);
      if (url.pathname === "/api/accounts" && request.method === "POST") return createAccount(request, env, session);

      const deleteMatch = url.pathname.match(/^\/api\/accounts\/(\d+)$/);
      if (deleteMatch && request.method === "DELETE") {
        return deleteAccount(Number(deleteMatch[1]), env, session);
      }
      if (deleteMatch && request.method === "PATCH") {
        return updateAccount(Number(deleteMatch[1]), request, env, session);
      }
      if (url.pathname.startsWith("/api/")) return json({ error: "not_found" }, 404);

      return env.ASSETS.fetch(request);
    } catch (error) {
      console.error(error);
      return json({ error: "server_error" }, 500);
    }
  },
};

async function listAccounts(env, user) {
  // 管理者が非表示にしたアカウントは、シードごと返さない
  const { results } = await env.DB.prepare(
    `SELECT a.id, a.service_name, a.account_name, a.role_name, a.encrypted_secret, a.iv, a.algorithm, a.digits, a.period
       FROM totp_accounts a
      WHERE a.deleted_at IS NULL
        AND NOT EXISTS (
          SELECT 1 FROM account_visibility v
           WHERE v.account_id = a.id AND v.discord_id = ? AND v.hidden = 1
        )
      ORDER BY a.sort_order ASC, a.service_name ASC, a.account_name ASC, a.id ASC`,
  )
    .bind(user.discord_id)
    .all();

  const accounts = [];
  for (const row of results) {
    const secret = await decryptSecret(row.encrypted_secret, row.iv, env);
    const otp = normalizeOtpParams(row);
    accounts.push({
      id: row.id,
      service: row.service_name,
      account: row.account_name,
      role: row.role_name || "未分類",
      secret,
      ...otp,
      token: await generateTotp(secret, Date.now(), otp),
    });
  }

  return json({ accounts, serverTime: Date.now(), offlineKey: await offlineKeyFor(env, user) });
}

async function createAccount(request, env, session) {
  if (!canAddSecrets(session.id, env)) return json({ error: "forbidden" }, 403);

  const body = await request.json();
  const serviceName = String(body.service || "").trim();
  const accountName = String(body.account || "").trim();
  const roleName = String(body.role || "").trim();
  let parsed;
  try {
    parsed = parseSecretInput(String(body.secret || ""), body);
  } catch (error) {
    return json({ error: "invalid_otp_parameters" }, 400);
  }
  const { secret, otp } = parsed;

  if (!serviceName || !accountName || !secret) {
    return json({ error: "missing_required_fields" }, 400);
  }

  try {
    await generateTotp(secret, Date.now(), otp);
  } catch (error) {
    return json({ error: "invalid_secret" }, 400);
  }
  const encrypted = await encryptSecret(secret, env);

  const result = await env.DB.prepare(
    `INSERT INTO totp_accounts
      (service_name, account_name, role_name, encrypted_secret, iv, algorithm, digits, period, created_by_discord_id, sort_order)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, (SELECT COALESCE(MAX(sort_order), 0) + 1 FROM totp_accounts))`,
  )
    .bind(
      serviceName,
      accountName,
      roleName || null,
      encrypted.ciphertext,
      encrypted.iv,
      otp.algorithm,
      otp.digits,
      otp.period,
      session.id,
    )
    .run();

  return json({ id: result.meta.last_row_id }, 201);
}

// シードを空で送ったときは、今のシードをそのまま使う
async function updateAccount(id, request, env, session) {
  if (!canAddSecrets(session.id, env)) return json({ error: "forbidden" }, 403);

  const current = await env.DB.prepare(
    "SELECT encrypted_secret, iv FROM totp_accounts WHERE id = ? AND deleted_at IS NULL",
  )
    .bind(id)
    .first();
  if (!current) return json({ error: "not_found" }, 404);

  const body = await request.json();
  const serviceName = String(body.service || "").trim();
  const accountName = String(body.account || "").trim();
  const roleName = String(body.role || "").trim();
  if (!serviceName || !accountName) return json({ error: "missing_required_fields" }, 400);

  let secret;
  let otp;
  try {
    const parsed = parseSecretInput(String(body.secret || ""), body);
    otp = parsed.secret ? parsed.otp : normalizeOtpParams(body, { strict: true });
    secret = parsed.secret || null;
  } catch (error) {
    return json({ error: "invalid_otp_parameters" }, 400);
  }

  try {
    await generateTotp(secret || (await decryptSecret(current.encrypted_secret, current.iv, env)), Date.now(), otp);
  } catch (error) {
    return json({ error: "invalid_secret" }, 400);
  }
  const encrypted = secret ? await encryptSecret(secret, env) : { ciphertext: current.encrypted_secret, iv: current.iv };

  await env.DB.prepare(
    `UPDATE totp_accounts
        SET service_name = ?, account_name = ?, role_name = ?,
            encrypted_secret = ?, iv = ?, algorithm = ?, digits = ?, period = ?,
            updated_by_discord_id = ?, updated_at = CURRENT_TIMESTAMP
      WHERE id = ? AND deleted_at IS NULL`,
  )
    .bind(
      serviceName,
      accountName,
      roleName || null,
      encrypted.ciphertext,
      encrypted.iv,
      otp.algorithm,
      otp.digits,
      otp.period,
      session.id,
      id,
    )
    .run();

  return json({ ok: true });
}

async function deleteAccount(id, env, session) {
  if (!canAddSecrets(session.id, env)) return json({ error: "forbidden" }, 403);

  await env.DB.prepare(
    `UPDATE totp_accounts
        SET deleted_at = CURRENT_TIMESTAMP,
            updated_by_discord_id = ?
      WHERE id = ? AND deleted_at IS NULL`,
  )
    .bind(session.id, id)
    .run();

  return json({ ok: true });
}

async function renderLogin(request, env) {
  const session = await getSession(request, env);
  if (session) {
    if (isSessionAllowed(session, env)) return Response.redirect(new URL("/", request.url), 302);
    const response = renderLoginPage();
    response.headers.append("Set-Cookie", clearCookie(COOKIE_SESSION));
    return response;
  }

  return renderLoginPage();
}

function renderLoginPage() {
  return html(`<!doctype html>
<html lang="ja">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="theme-color" content="#0f1b31">
    <link rel="icon" href="/icons/favicon.ico" sizes="any">
    <link rel="icon" href="/icons/favicon-32.png" type="image/png" sizes="32x32">
    <link rel="apple-touch-icon" href="/icons/apple-touch-icon.png">
    <link rel="manifest" href="/manifest.webmanifest">
    <meta name="apple-mobile-web-app-title" content="PhosMFA">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="default">
    <title>Discordログイン - PhosMFA</title>
    <style>
      body { align-items: center; background: #f5f7fb; color: #172033; display: flex; font-family: system-ui, sans-serif; min-height: 100vh; margin: 0; padding: 24px; }
      main { background: #fff; border: 1px solid #d9e0ea; border-radius: 8px; box-shadow: 0 16px 42px rgba(20,35,65,.12); margin: auto; max-width: 520px; padding: 32px; }
      h1 { margin: 0 0 12px; }
      p { color: #667085; line-height: 1.7; }
      a { align-items: center; background: #5865f2; border-radius: 8px; color: #fff; display: inline-flex; font-weight: 800; min-height: 44px; padding: 0 18px; text-decoration: none; }
    </style>
  </head>
  <body>
    <main>
      <h1>PhosMFA</h1>
      <p>このページは許可されたDiscordユーザーだけが利用できます。</p>
      <a href="/auth/discord">Discordで続行</a>
    </main>
  </body>
</html>`);
}

async function redirectToDiscord(request, env) {
  assertDiscordConfig(env);

  const url = new URL(request.url);
  const state = crypto.randomUUID();
  const signedState = await signValue(state, env.SESSION_SECRET);
  const params = new URLSearchParams({
    response_type: "code",
    client_id: env.DISCORD_CLIENT_ID,
    scope: "identify guilds",
    state,
    redirect_uri: redirectUri(request, env),
    prompt: "none",
  });

  return new Response(null, {
    status: 302,
    headers: {
      Location: `https://discord.com/oauth2/authorize?${params}`,
      "Set-Cookie": cookie(COOKIE_OAUTH_STATE, signedState, url.protocol === "https:", OAUTH_STATE_MAX_AGE_SECONDS),
    },
  });
}

async function handleDiscordCallback(request, env) {
  assertDiscordConfig(env);

  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const signedState = parseCookies(request.headers.get("Cookie") || "")[COOKIE_OAUTH_STATE];
  const verifiedState = signedState ? await verifySignedValue(signedState, env.SESSION_SECRET) : "";

  if (!code || !state || verifiedState !== state) {
    return new Response("Discord login state is invalid. Please try again.", { status: 400 });
  }

  const token = await exchangeDiscordCode(code, request, env);
  const [user, guilds] = await Promise.all([
    discordFetch("/users/@me", token.access_token),
    discordFetch("/users/@me/guilds", token.access_token),
  ]);

  const allowedUsers = parseCsv(env.DISCORD_ALLOWED_USER_IDS || "");
  const userAllowed = allowedUsers.size === 0 || allowedUsers.has(user.id);
  const guildAllowed = !env.DISCORD_REQUIRED_GUILD_ID || guilds.some((guild) => guild.id === env.DISCORD_REQUIRED_GUILD_ID);

  if (!userAllowed || !guildAllowed) {
    return html("<h1>アクセスできません</h1><p>必要な Discord の権限を確認できませんでした。</p>", 403);
  }

  // Discord のログインだけでは 2段階認証は未完了 (mfa: false)。パスコードかパスキーの確認で mfa: true になる。
  const appUser = await upsertUserOnLogin(env, user, request);
  const session = buildSession({ id: user.id, username: user.username, globalName: user.global_name }, appUser, false);
  const headers = new Headers({ Location: "/" });
  headers.append("Set-Cookie", await sessionCookie(session, request, env));
  headers.append("Set-Cookie", clearCookie(COOKIE_OAUTH_STATE));

  return new Response(null, { status: 302, headers });
}

function logout() {
  return new Response(null, {
    status: 302,
    headers: {
      Location: "/login",
      "Set-Cookie": clearCookie(COOKIE_SESSION),
    },
  });
}

async function currentUser(request, session, user, env) {
  return json({
    authenticated: true,
    serverTime: Date.now(),
    user: {
      id: session.id,
      username: session.username,
      globalName: session.globalName,
      canAddSecrets: canAddSecrets(session.id, env),
    },
    security: await securitySummary(request, env, session, user),
  });
}

function revokeSession(request) {
  const url = new URL(request.url);
  if (url.pathname.startsWith("/api/")) {
    const response = json({ error: "unauthorized" }, 401);
    response.headers.append("Set-Cookie", clearCookie(COOKIE_SESSION));
    return response;
  }

  const headers = new Headers({ Location: "/login" });
  headers.append("Set-Cookie", clearCookie(COOKIE_SESSION));
  return new Response(null, { status: 302, headers });
}

function isSessionAllowed(session, env) {
  const allowedUsers = parseCsv(env.DISCORD_ALLOWED_USER_IDS || "");
  return allowedUsers.size === 0 || allowedUsers.has(session.id);
}

async function exchangeDiscordCode(code, request, env) {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: redirectUri(request, env),
  });

  const response = await fetch("https://discord.com/api/oauth2/token", {
    method: "POST",
    headers: {
      Authorization: `Basic ${btoa(`${env.DISCORD_CLIENT_ID}:${env.DISCORD_CLIENT_SECRET}`)}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body,
  });

  if (!response.ok) throw new Error(`Discord token exchange failed: ${response.status}`);
  return response.json();
}

async function discordFetch(resource, accessToken) {
  const response = await fetch(`https://discord.com/api/v10${resource}`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });

  if (!response.ok) throw new Error(`Discord API request failed: ${resource} ${response.status}`);
  return response.json();
}

function redirectUri(request, env) {
  if (env.DISCORD_REDIRECT_URI) return env.DISCORD_REDIRECT_URI;
  return `${new URL(request.url).origin}/auth/discord/callback`;
}

async function getSession(request, env) {
  const signed = parseCookies(request.headers.get("Cookie") || "")[COOKIE_SESSION];
  if (!signed) return null;

  const session = await verifySignedJson(signed, env.SESSION_SECRET);
  if (!session || session.exp < Math.floor(Date.now() / 1000)) return null;
  return session;
}

async function encryptSecret(secret, env) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await getVaultKey(env);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(secret)),
  );
  return { ciphertext, iv };
}

async function decryptSecret(ciphertext, iv, env) {
  const key = await getVaultKey(env);
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: toBytes(iv) },
    key,
    toBytes(ciphertext),
  );
  return new TextDecoder().decode(plain);
}

async function getVaultKey(env) {
  if (!env.VAULT_ENCRYPTION_KEY) throw new Error("VAULT_ENCRYPTION_KEY is required.");
  const raw = await getVaultRaw(env);
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
}

const OTP_HASHES = { SHA1: "SHA-1", SHA256: "SHA-256", SHA512: "SHA-512" };
const OTP_DEFAULTS = { algorithm: "SHA1", digits: 6, period: 30 };

function normalizeOtpParams(raw = {}, { strict = false } = {}) {
  const algorithmInput = String(raw.algorithm ?? "").trim().toUpperCase().replace(/-/g, "");
  const digitsInput = raw.digits === undefined || raw.digits === null || raw.digits === "" ? NaN : Number(raw.digits);
  const periodInput = raw.period === undefined || raw.period === null || raw.period === "" ? NaN : Number(raw.period);

  const algorithm = algorithmInput in OTP_HASHES ? algorithmInput : null;
  const digits = Number.isInteger(digitsInput) && digitsInput >= 6 && digitsInput <= 8 ? digitsInput : null;
  const period = Number.isInteger(periodInput) && periodInput >= 10 && periodInput <= 300 ? periodInput : null;

  if (strict) {
    if (algorithmInput && !algorithm) throw new Error("Unsupported algorithm.");
    if (!Number.isNaN(digitsInput) && !digits) throw new Error("Unsupported digits.");
    if (!Number.isNaN(periodInput) && !period) throw new Error("Unsupported period.");
  }

  return {
    algorithm: algorithm || OTP_DEFAULTS.algorithm,
    digits: digits || OTP_DEFAULTS.digits,
    period: period || OTP_DEFAULTS.period,
  };
}

async function generateTotp(secret, timestamp = Date.now(), params = OTP_DEFAULTS) {
  const { algorithm, digits, period } = normalizeOtpParams(params);
  const key = await crypto.subtle.importKey(
    "raw",
    base32ToBytes(secret),
    { name: "HMAC", hash: OTP_HASHES[algorithm] },
    false,
    ["sign"],
  );
  const counter = Math.floor(timestamp / 1000 / period);
  const buffer = new ArrayBuffer(8);
  const view = new DataView(buffer);
  view.setUint32(0, Math.floor(counter / 0x100000000));
  view.setUint32(4, counter >>> 0);
  const hash = new Uint8Array(await crypto.subtle.sign("HMAC", key, buffer));
  const offset = hash[hash.length - 1] & 0x0f;
  const binary =
    ((hash[offset] & 0x7f) << 24) |
    (hash[offset + 1] << 16) |
    (hash[offset + 2] << 8) |
    hash[offset + 3];
  return String(binary % 10 ** digits).padStart(digits, "0");
}

function parseSecretInput(value, fields = {}) {
  const trimmed = value.trim();
  if (!trimmed) return { secret: "", otp: normalizeOtpParams() };

  if (trimmed.startsWith("otpauth://")) {
    const url = new URL(trimmed);
    if (url.hostname.toLowerCase() !== "totp") throw new Error("Only TOTP is supported.");
    const otp = normalizeOtpParams(
      {
        algorithm: url.searchParams.get("algorithm") ?? fields.algorithm,
        digits: url.searchParams.get("digits") ?? fields.digits,
        period: url.searchParams.get("period") ?? fields.period,
      },
      { strict: true },
    );
    return { secret: (url.searchParams.get("secret") || "").replace(/\s+/g, "").toUpperCase(), otp };
  }
  return {
    secret: trimmed.replace(/\s+/g, "").toUpperCase(),
    otp: normalizeOtpParams(fields, { strict: true }),
  };
}

function base32ToBytes(secret) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = secret.replace(/=+$/, "").replace(/\s+/g, "").toUpperCase();
  let bits = "";
  for (const char of clean) {
    const value = alphabet.indexOf(char);
    if (value === -1) throw new Error("Invalid base32 secret.");
    bits += value.toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(Number.parseInt(bits.slice(i, i + 8), 2));
  }
  return new Uint8Array(bytes);
}
