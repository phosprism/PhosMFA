// Discord ログイン後の2段階認証 (パスコード / パスキー)、開いたときのロック、アカウントロック、管理者 API。
// 画面側の表示に関係なく、ここで権限を判定する。
import {
  SESSION_MAX_AGE_SECONDS,
  base64UrlEncode,
  canAddSecrets,
  cookie,
  getVaultRaw,
  hmacSha256Bytes,
  json,
  signJson,
  timingSafeEqual,
  verifySignedJson,
} from "./util.mjs";
import { SUPPORTED_ALGORITHMS, WebAuthnError, verifyAuthentication, verifyRegistration } from "./webauthn.mjs";

export const COOKIE_SESSION = "mfa_session";
export const UNLOCK_HEADER = "X-PhosMFA-Unlock";
export const MAX_FAILED_ATTEMPTS = 5;
const UNLOCK_TOKEN_TTL_SECONDS = 60 * 60 * 12;
const CHALLENGE_TTL_MS = 5 * 60 * 1000;
const MAX_PASSKEYS = 10;

// ---------------------------------------------------------------------------
// ユーザーとセッション
// ---------------------------------------------------------------------------

export async function loadUser(env, discordId) {
  return env.DB.prepare("SELECT * FROM app_users WHERE discord_id = ?").bind(discordId).first();
}

export async function upsertUserOnLogin(env, discordUser, request) {
  await env.DB.prepare(
    `INSERT INTO app_users (discord_id, username, global_name, last_login_at)
     VALUES (?, ?, ?, CURRENT_TIMESTAMP)
     ON CONFLICT (discord_id) DO UPDATE SET
       username = excluded.username,
       global_name = excluded.global_name,
       last_login_at = CURRENT_TIMESTAMP,
       updated_at = CURRENT_TIMESTAMP`,
  )
    .bind(discordUser.id, discordUser.username || "", discordUser.global_name || "")
    .run();
  await logEvent(env, request, discordUser.id, "discord_login");
  return loadUser(env, discordUser.id);
}

export function buildSession({ id, username, globalName }, user, mfa) {
  return {
    id,
    username,
    globalName: globalName || "",
    epoch: user.session_epoch,
    mfa: Boolean(mfa),
    exp: Math.floor(Date.now() / 1000) + SESSION_MAX_AGE_SECONDS,
  };
}

export async function sessionCookie(session, request, env) {
  const signed = await signJson(session, env.SESSION_SECRET);
  return cookie(COOKIE_SESSION, signed, new URL(request.url).protocol === "https:");
}

// 2段階認証が通っていて、開いたときのロックも解除済みなら null。そうでなければ返すべきレスポンス。
export async function requireFullAccess(request, env, session, user) {
  if (user.locked_at) return json({ error: "locked" }, 423);
  if (!user.passcode_hash) return json({ error: "mfa_setup_required" }, 401);
  if (!session.mfa) return json({ error: "mfa_required" }, 401);
  if (user.unlock_on_open === 1 && !(await hasValidUnlock(request, env, user))) {
    return json({ error: "unlock_required" }, 401);
  }
  return null;
}

export async function securitySummary(request, env, session, user) {
  const passkeyCount = await countPasskeys(env, user.discord_id);
  const unlocked = user.unlock_on_open === 1 ? await hasValidUnlock(request, env, user) : true;
  let stage = "ready";
  if (user.locked_at) stage = "locked";
  else if (!user.passcode_hash) stage = "setup";
  else if (!session.mfa) stage = "verify";
  else if (user.unlock_on_open === null) stage = "setup";
  else if (user.unlock_on_open === 1 && !unlocked) stage = "unlock";

  return {
    stage,
    hasPasscode: Boolean(user.passcode_hash),
    passcodeLength: user.passcode_length || null,
    passkeyCount,
    unlockOnOpen: user.unlock_on_open === null ? null : user.unlock_on_open === 1,
    remainingAttempts: Math.max(0, MAX_FAILED_ATTEMPTS - user.failed_attempts),
    lockReason: user.locked_at ? user.lock_reason : null,
    isAdmin: canAddSecrets(user.discord_id, env),
  };
}

// 開いたときのロックが有効な人だけ、オフライン用キャッシュの鍵を渡す。
// セッションを無効化 (epoch を変更) すると鍵も変わり、端末に残ったキャッシュは復号できなくなる。
export async function offlineKeyFor(env, user) {
  if (user.unlock_on_open !== 1) return null;
  return base64UrlEncode(await hmacSha256Bytes(await pepper(env, "offline-cache"), `${user.discord_id}|${user.session_epoch}`));
}

// ---------------------------------------------------------------------------
// /api/mfa/*
// ---------------------------------------------------------------------------

export async function handleMfaApi(request, env, session, user, path) {
  const method = request.method;
  if (user.locked_at) return json({ error: "locked" }, 423);

  if (path === "/passcode/setup" && method === "POST") return setupPasscode(request, env, session, user);
  if (path === "/passcode/verify" && method === "POST") return verifyPasscodeRequest(request, env, session, user);
  if (path === "/passkey/auth/options" && method === "POST") return passkeyAuthOptions(request, env, user);
  if (path === "/passkey/auth" && method === "POST") return passkeyAuth(request, env, session, user);

  // ここから先はログイン済み (2段階認証済み) のときだけ。初回設定中 (選択前) も含む。
  const denied = await requireSettingsAccess(request, env, session, user);
  if (denied) return denied;

  if (path === "/passcode/change" && method === "POST") return changePasscode(request, env, session, user);
  if (path === "/passkey/register/options" && method === "POST") return passkeyRegisterOptions(request, env, user);
  if (path === "/passkey/register" && method === "POST") return passkeyRegister(request, env, user);
  if (path === "/passkeys" && method === "GET") return listPasskeys(env, user);
  const passkeyMatch = path.match(/^\/passkeys\/([A-Za-z0-9_-]{1,512})$/);
  if (passkeyMatch && method === "DELETE") return deletePasskey(request, env, user, passkeyMatch[1]);
  if (path === "/preferences" && method === "POST") return updatePreferences(request, env, user);

  return json({ error: "not_found" }, 404);
}

async function requireSettingsAccess(request, env, session, user) {
  if (!user.passcode_hash) return json({ error: "mfa_setup_required" }, 401);
  if (!session.mfa) return json({ error: "mfa_required" }, 401);
  if (user.unlock_on_open === 1 && !(await hasValidUnlock(request, env, user))) {
    return json({ error: "unlock_required" }, 401);
  }
  return null;
}

async function setupPasscode(request, env, session, user) {
  if (user.passcode_hash) return json({ error: "already_configured" }, 409);
  const body = await readJson(request);
  const passcode = String(body.passcode || "");
  const problem = passcodeProblem(passcode);
  if (problem) return json({ error: problem }, 400);

  const { hash, salt } = await hashPasscode(env, user.discord_id, passcode);
  const result = await env.DB.prepare(
    `UPDATE app_users
        SET passcode_hash = ?, passcode_salt = ?, passcode_length = ?, failed_attempts = 0,
            last_verified_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
      WHERE discord_id = ? AND passcode_hash IS NULL AND session_epoch = ?`,
  )
    .bind(hash, salt, passcode.length, user.discord_id, user.session_epoch)
    .run();
  if (!result.meta.changes) return json({ error: "already_configured" }, 409);

  await logEvent(env, request, user.discord_id, "passcode_set");
  return verifiedResponse(request, env, session, user);
}

async function verifyPasscodeRequest(request, env, session, user) {
  if (!user.passcode_hash) return json({ error: "mfa_setup_required" }, 401);
  const body = await readJson(request);
  const ok = await checkPasscode(env, user, String(body.passcode || ""));
  if (!ok) return recordFailure(request, env, user, "passcode");

  await recordSuccess(request, env, user, "passcode");
  return verifiedResponse(request, env, session, user);
}

async function changePasscode(request, env, session, user) {
  const body = await readJson(request);
  const ok = await checkPasscode(env, user, String(body.current || ""));
  if (!ok) return recordFailure(request, env, user, "passcode_change");

  const passcode = String(body.passcode || "");
  const problem = passcodeProblem(passcode);
  if (problem) return json({ error: problem }, 400);

  const { hash, salt } = await hashPasscode(env, user.discord_id, passcode);
  await env.DB.prepare(
    `UPDATE app_users
        SET passcode_hash = ?, passcode_salt = ?, passcode_length = ?, failed_attempts = 0,
            updated_at = CURRENT_TIMESTAMP
      WHERE discord_id = ?`,
  )
    .bind(hash, salt, passcode.length, user.discord_id)
    .run();
  await logEvent(env, request, user.discord_id, "passcode_changed");
  return json({ ok: true });
}

async function passkeyAuthOptions(request, env, user) {
  if (!user.passcode_hash) return json({ error: "mfa_setup_required" }, 401);
  const { results } = await env.DB.prepare("SELECT credential_id, transports FROM passkeys WHERE discord_id = ?")
    .bind(user.discord_id)
    .all();
  if (!results.length) return json({ error: "no_passkeys" }, 404);

  const challenge = await issueChallenge(env, user, "auth");
  return json({
    challenge,
    rpId: rpIdFor(request),
    timeout: 60000,
    userVerification: "required",
    allowCredentials: results.map((row) => ({
      type: "public-key",
      id: row.credential_id,
      transports: parseTransports(row.transports),
    })),
  });
}

async function passkeyAuth(request, env, session, user) {
  const body = await readJson(request);
  const credential = body.credential || {};
  const challenge = await consumeChallenge(env, user, "auth");
  if (!challenge) return json({ error: "challenge_expired" }, 400);

  const credentialId = String(credential.id || "");
  const passkey = await env.DB.prepare("SELECT * FROM passkeys WHERE credential_id = ? AND discord_id = ?")
    .bind(credentialId, user.discord_id)
    .first();
  if (!passkey) return recordFailure(request, env, user, "passkey");

  try {
    const { signCount } = await verifyAuthentication({
      credential,
      expectedChallenge: challenge,
      expectedOrigin: new URL(request.url).origin,
      rpId: rpIdFor(request),
      jwk: JSON.parse(passkey.public_key_jwk),
      alg: passkey.algorithm,
      storedSignCount: passkey.sign_count,
    });
    await env.DB.prepare(
      "UPDATE passkeys SET sign_count = ?, last_used_at = CURRENT_TIMESTAMP WHERE credential_id = ?",
    )
      .bind(signCount, credentialId)
      .run();
  } catch (error) {
    if (!(error instanceof WebAuthnError)) throw error;
    return recordFailure(request, env, user, "passkey", error.code);
  }

  await recordSuccess(request, env, user, "passkey");
  return verifiedResponse(request, env, session, user);
}

async function passkeyRegisterOptions(request, env, user) {
  const { results } = await env.DB.prepare("SELECT credential_id, transports FROM passkeys WHERE discord_id = ?")
    .bind(user.discord_id)
    .all();
  if (results.length >= MAX_PASSKEYS) return json({ error: "too_many_passkeys" }, 400);

  const challenge = await issueChallenge(env, user, "register");
  const name = user.username || user.discord_id;
  return json({
    challenge,
    rp: { name: "PhosMFA", id: rpIdFor(request) },
    user: {
      id: base64UrlEncode(new TextEncoder().encode(user.discord_id)),
      name,
      displayName: user.global_name || name,
    },
    pubKeyCredParams: SUPPORTED_ALGORITHMS.map((alg) => ({ type: "public-key", alg })),
    authenticatorSelection: { residentKey: "preferred", userVerification: "required" },
    attestation: "none",
    timeout: 120000,
    excludeCredentials: results.map((row) => ({
      type: "public-key",
      id: row.credential_id,
      transports: parseTransports(row.transports),
    })),
  });
}

async function passkeyRegister(request, env, user) {
  const body = await readJson(request);
  const challenge = await consumeChallenge(env, user, "register");
  if (!challenge) return json({ error: "challenge_expired" }, 400);

  let registered;
  try {
    registered = await verifyRegistration({
      credential: body.credential || {},
      expectedChallenge: challenge,
      expectedOrigin: new URL(request.url).origin,
      rpId: rpIdFor(request),
    });
  } catch (error) {
    if (!(error instanceof WebAuthnError)) throw error;
    return json({ error: "passkey_invalid", detail: error.code }, 400);
  }

  const name = String(body.name || "").trim().slice(0, 60) || defaultPasskeyName(request);
  try {
    await env.DB.prepare(
      `INSERT INTO passkeys (credential_id, discord_id, public_key_jwk, algorithm, sign_count, transports, name)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    )
      .bind(
        registered.credentialId,
        user.discord_id,
        JSON.stringify(registered.jwk),
        registered.alg,
        registered.signCount,
        JSON.stringify(registered.transports),
        name,
      )
      .run();
  } catch (error) {
    return json({ error: "passkey_already_registered" }, 409);
  }

  await logEvent(env, request, user.discord_id, "passkey_added", name);
  return json({ ok: true });
}

async function listPasskeys(env, user) {
  const { results } = await env.DB.prepare(
    `SELECT credential_id, name, created_at, last_used_at
       FROM passkeys WHERE discord_id = ? ORDER BY created_at ASC`,
  )
    .bind(user.discord_id)
    .all();
  return json({
    passkeys: results.map((row) => ({
      id: row.credential_id,
      name: row.name,
      createdAt: row.created_at,
      lastUsedAt: row.last_used_at,
    })),
  });
}

async function deletePasskey(request, env, user, credentialId) {
  const result = await env.DB.prepare("DELETE FROM passkeys WHERE credential_id = ? AND discord_id = ?")
    .bind(credentialId, user.discord_id)
    .run();
  if (!result.meta.changes) return json({ error: "not_found" }, 404);
  await logEvent(env, request, user.discord_id, "passkey_removed");
  return json({ ok: true });
}

async function updatePreferences(request, env, user) {
  const body = await readJson(request);
  if (typeof body.unlockOnOpen !== "boolean") return json({ error: "invalid_preferences" }, 400);
  await env.DB.prepare("UPDATE app_users SET unlock_on_open = ?, updated_at = CURRENT_TIMESTAMP WHERE discord_id = ?")
    .bind(body.unlockOnOpen ? 1 : 0, user.discord_id)
    .run();
  await logEvent(env, request, user.discord_id, "unlock_on_open", body.unlockOnOpen ? "on" : "off");
  const updated = { ...user, unlock_on_open: body.unlockOnOpen ? 1 : 0 };
  return json({ ok: true, unlockToken: await issueUnlockToken(env, updated) });
}

async function verifiedResponse(request, env, session, user) {
  const fresh = await loadUser(env, user.discord_id);
  const response = json({ ok: true, unlockToken: await issueUnlockToken(env, fresh) });
  response.headers.append("Set-Cookie", await sessionCookie({ ...session, epoch: fresh.session_epoch, mfa: true }, request, env));
  return response;
}

async function recordFailure(request, env, user, method, detail = "") {
  const row = await env.DB.prepare(
    `UPDATE app_users
        SET failed_attempts = failed_attempts + 1, last_failed_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
      WHERE discord_id = ?
      RETURNING failed_attempts`,
  )
    .bind(user.discord_id)
    .first();
  const attempts = row?.failed_attempts ?? MAX_FAILED_ATTEMPTS;
  await logEvent(env, request, user.discord_id, `${method}_failed`, detail || `${attempts}/${MAX_FAILED_ATTEMPTS}`);

  if (attempts >= MAX_FAILED_ATTEMPTS) {
    await env.DB.prepare(
      `UPDATE app_users
          SET locked_at = CURRENT_TIMESTAMP, lock_reason = 'too_many_attempts', locked_by_discord_id = NULL,
              updated_at = CURRENT_TIMESTAMP
        WHERE discord_id = ? AND locked_at IS NULL`,
    )
      .bind(user.discord_id)
      .run();
    await logEvent(env, request, user.discord_id, "locked", "too_many_attempts");
    return json({ error: "locked", remainingAttempts: 0 }, 423);
  }

  return json({ error: method === "passkey" ? "invalid_passkey" : "invalid_passcode", remainingAttempts: MAX_FAILED_ATTEMPTS - attempts }, 401);
}

async function recordSuccess(request, env, user, method) {
  await env.DB.prepare(
    `UPDATE app_users
        SET failed_attempts = 0, last_verified_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
      WHERE discord_id = ?`,
  )
    .bind(user.discord_id)
    .run();
  await logEvent(env, request, user.discord_id, "verified", method);
}

// ---------------------------------------------------------------------------
// パスコード
// ---------------------------------------------------------------------------

function passcodeProblem(passcode) {
  if (!/^(\d{4}|\d{6})$/.test(passcode)) return "passcode_format";
  if (/^(\d)\1+$/.test(passcode)) return "passcode_too_simple";
  const digits = [...passcode].map(Number);
  const ascending = digits.every((digit, i) => i === 0 || digit === (digits[i - 1] + 1) % 10);
  const descending = digits.every((digit, i) => i === 0 || digit === (digits[i - 1] + 9) % 10);
  if (ascending || descending) return "passcode_too_simple";
  return "";
}

// 4〜6桁は総当たりに弱いので、DB だけ漏れても解析できないよう、サーバーの秘密鍵 (pepper) を混ぜて HMAC する。
// 総当たりそのものは 5回でのロックで防ぐ。
async function hashPasscode(env, discordId, passcode, salt = base64UrlEncode(crypto.getRandomValues(new Uint8Array(16)))) {
  const hash = await hmacSha256Bytes(await pepper(env, "passcode"), `${salt}|${discordId}|${passcode}`);
  return { hash: base64UrlEncode(hash), salt };
}

async function checkPasscode(env, user, passcode) {
  if (!user.passcode_hash || !/^\d{4,6}$/.test(passcode)) return false;
  const { hash } = await hashPasscode(env, user.discord_id, passcode, user.passcode_salt);
  return timingSafeEqual(hash, user.passcode_hash);
}

async function pepper(env, purpose) {
  return hmacSha256Bytes(await getVaultRaw(env), `phos-mfa/${purpose}/v1`);
}

// ---------------------------------------------------------------------------
// 開いたときのロック解除トークン (ページのメモリにだけ置く。再読み込みで消える)
// ---------------------------------------------------------------------------

async function issueUnlockToken(env, user) {
  return signJson(
    { kind: "unlock", id: user.discord_id, epoch: user.session_epoch, exp: Math.floor(Date.now() / 1000) + UNLOCK_TOKEN_TTL_SECONDS },
    env.SESSION_SECRET,
  );
}

async function hasValidUnlock(request, env, user) {
  const token = request.headers.get(UNLOCK_HEADER);
  if (!token) return false;
  const payload = await verifySignedJson(token, env.SESSION_SECRET);
  return Boolean(
    payload &&
      payload.kind === "unlock" &&
      payload.id === user.discord_id &&
      payload.epoch === user.session_epoch &&
      payload.exp > Math.floor(Date.now() / 1000),
  );
}

// ---------------------------------------------------------------------------
// パスキーのチャレンジ (1回限り。DB に置いて使ったら消す)
// ---------------------------------------------------------------------------

async function issueChallenge(env, user, purpose) {
  const challenge = base64UrlEncode(crypto.getRandomValues(new Uint8Array(32)));
  await env.DB.prepare(
    `UPDATE app_users
        SET pending_challenge = ?, pending_challenge_purpose = ?, pending_challenge_expires_at = ?
      WHERE discord_id = ?`,
  )
    .bind(challenge, purpose, Date.now() + CHALLENGE_TTL_MS, user.discord_id)
    .run();
  return challenge;
}

async function consumeChallenge(env, user, purpose) {
  if (!user.pending_challenge) return "";
  // 読んだ値と一致するときだけ消す。同じチャレンジを2回使おうとすると2回目は changes = 0 になる。
  const result = await env.DB.prepare(
    `UPDATE app_users
        SET pending_challenge = NULL, pending_challenge_purpose = NULL, pending_challenge_expires_at = NULL
      WHERE discord_id = ? AND pending_challenge = ?`,
  )
    .bind(user.discord_id, user.pending_challenge)
    .run();
  if (!result.meta.changes) return "";
  if (user.pending_challenge_purpose !== purpose) return "";
  if (!user.pending_challenge_expires_at || user.pending_challenge_expires_at < Date.now()) return "";
  return user.pending_challenge;
}

// ---------------------------------------------------------------------------
// /api/admin/*
// ---------------------------------------------------------------------------

export async function handleAdminApi(request, env, session, user, path) {
  if (!canAddSecrets(user.discord_id, env)) return json({ error: "forbidden" }, 403);

  if (path === "/users" && request.method === "GET") return adminListUsers(env);

  const eventsMatch = path.match(/^\/users\/(\d{1,25})\/events$/);
  if (eventsMatch && request.method === "GET") return adminUserEvents(env, eventsMatch[1]);

  const actionMatch = path.match(/^\/users\/(\d{1,25})\/(unlock|reset|lock)$/);
  if (actionMatch && request.method === "POST") {
    const [, targetId, action] = actionMatch;
    const target = await loadUser(env, targetId);
    if (!target) return json({ error: "not_found" }, 404);
    if (action === "lock" && targetId === user.discord_id) return json({ error: "cannot_lock_self" }, 400);

    if (action === "unlock") {
      await env.DB.prepare(
        `UPDATE app_users
            SET locked_at = NULL, lock_reason = NULL, locked_by_discord_id = NULL, failed_attempts = 0,
                updated_at = CURRENT_TIMESTAMP
          WHERE discord_id = ?`,
      )
        .bind(targetId)
        .run();
    } else if (action === "lock") {
      await env.DB.prepare(
        `UPDATE app_users
            SET locked_at = CURRENT_TIMESTAMP, lock_reason = 'admin', locked_by_discord_id = ?,
                session_epoch = session_epoch + 1, updated_at = CURRENT_TIMESTAMP
          WHERE discord_id = ?`,
      )
        .bind(user.discord_id, targetId)
        .run();
    } else {
      await env.DB.batch([
        env.DB.prepare(
          `UPDATE app_users
              SET passcode_hash = NULL, passcode_salt = NULL, passcode_length = NULL, unlock_on_open = NULL,
                  failed_attempts = 0, locked_at = NULL, lock_reason = NULL, locked_by_discord_id = NULL,
                  pending_challenge = NULL, pending_challenge_purpose = NULL, pending_challenge_expires_at = NULL,
                  session_epoch = session_epoch + 1, updated_at = CURRENT_TIMESTAMP
            WHERE discord_id = ?`,
        ).bind(targetId),
        env.DB.prepare("DELETE FROM passkeys WHERE discord_id = ?").bind(targetId),
      ]);
    }

    await logEvent(env, request, targetId, `admin_${action}`, "", user.discord_id);
    return json({ ok: true });
  }

  return json({ error: "not_found" }, 404);
}

async function adminListUsers(env) {
  const { results } = await env.DB.prepare(
    `SELECT u.discord_id, u.username, u.global_name, u.passcode_hash IS NOT NULL AS has_passcode,
            u.unlock_on_open, u.failed_attempts, u.locked_at, u.lock_reason, u.locked_by_discord_id,
            u.last_login_at, u.last_verified_at, u.last_failed_at, u.created_at,
            (SELECT COUNT(*) FROM passkeys p WHERE p.discord_id = u.discord_id) AS passkey_count
       FROM app_users u
      ORDER BY (u.locked_at IS NULL) ASC, u.last_login_at DESC`,
  ).all();

  return json({
    serverTime: Date.now(),
    users: results.map((row) => ({
      id: row.discord_id,
      username: row.username,
      globalName: row.global_name,
      hasPasscode: Boolean(row.has_passcode),
      passkeyCount: row.passkey_count,
      unlockOnOpen: row.unlock_on_open === null ? null : row.unlock_on_open === 1,
      failedAttempts: row.failed_attempts,
      lockedAt: row.locked_at,
      lockReason: row.lock_reason,
      lockedBy: row.locked_by_discord_id,
      lastLoginAt: row.last_login_at,
      lastVerifiedAt: row.last_verified_at,
      lastFailedAt: row.last_failed_at,
      createdAt: row.created_at,
      isAdmin: canAddSecrets(row.discord_id, env),
    })),
  });
}

async function adminUserEvents(env, discordId) {
  const { results } = await env.DB.prepare(
    `SELECT event, detail, actor_discord_id, ip, country, created_at
       FROM security_events WHERE discord_id = ? ORDER BY id DESC LIMIT 50`,
  )
    .bind(discordId)
    .all();
  return json({
    events: results.map((row) => ({
      event: row.event,
      detail: row.detail,
      actor: row.actor_discord_id,
      ip: row.ip,
      country: row.country,
      createdAt: row.created_at,
    })),
  });
}

// ---------------------------------------------------------------------------
// 共通
// ---------------------------------------------------------------------------

async function logEvent(env, request, discordId, event, detail = "", actorId = null) {
  await env.DB.prepare(
    `INSERT INTO security_events (discord_id, event, detail, actor_discord_id, ip, country)
     VALUES (?, ?, ?, ?, ?, ?)`,
  )
    .bind(
      discordId,
      event,
      detail || null,
      actorId,
      request.headers.get("CF-Connecting-IP") || null,
      request.cf?.country || null,
    )
    .run();
}

async function countPasskeys(env, discordId) {
  const row = await env.DB.prepare("SELECT COUNT(*) AS n FROM passkeys WHERE discord_id = ?").bind(discordId).first();
  return row?.n || 0;
}

function rpIdFor(request) {
  return new URL(request.url).hostname;
}

function parseTransports(value) {
  try {
    const parsed = JSON.parse(value || "[]");
    return Array.isArray(parsed) ? parsed : [];
  } catch (error) {
    return [];
  }
}

function defaultPasskeyName(request) {
  const ua = request.headers.get("User-Agent") || "";
  if (/iPhone|iPad/.test(ua)) return "iPhone / iPad";
  if (/Android/.test(ua)) return "Android";
  if (/Macintosh/.test(ua)) return "Mac";
  if (/Windows/.test(ua)) return "Windows";
  return "パスキー";
}

async function readJson(request) {
  try {
    const body = await request.json();
    return body && typeof body === "object" ? body : {};
  } catch (error) {
    return {};
  }
}
