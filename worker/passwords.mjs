// パスワード管理 (テスト中のため管理者だけ)。
// 暗号化・復号はすべてブラウザの中で行う。マスターパスワードから PBKDF2-SHA256 で鍵を作り、
// AES-256-GCM で暗号化したものだけを受け取って保存する。サーバーは中身を読めない。
import { canAddSecrets, json } from "./util.mjs";
import { logEvent } from "./security.mjs";

export const PASSWORD_KDF_ITERATIONS = 600000;
const MAX_ITERATIONS = 5000000;
const MAX_CIPHERTEXT_LENGTH = 24000;
const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;

export async function handlePasswordsApi(request, env, session, path) {
  if (!canAddSecrets(session.id, env)) return json({ error: "forbidden" }, 403);

  if (path === "" && request.method === "GET") return listPasswords(env);
  if (path === "/vault" && request.method === "POST") return createVault(request, env, session);
  if (path === "" && request.method === "POST") return createEntry(request, env, session);

  const match = path.match(/^\/(\d+)$/);
  if (match && request.method === "PATCH") return updateEntry(Number(match[1]), request, env, session);
  if (match && request.method === "DELETE") return deleteEntry(Number(match[1]), request, env, session);

  return json({ error: "not_found" }, 404);
}

async function listPasswords(env) {
  const vault = await env.DB.prepare(
    "SELECT kdf, iterations, salt, verifier_iv, verifier_ciphertext FROM password_vault WHERE id = 1",
  ).first();
  const { results } = await env.DB.prepare(
    `SELECT id, iv, ciphertext, created_at, updated_at
       FROM password_entries
      WHERE deleted_at IS NULL
      ORDER BY id ASC`,
  ).all();

  return json({
    vault: vault
      ? {
          kdf: vault.kdf,
          iterations: vault.iterations,
          salt: vault.salt,
          verifierIv: vault.verifier_iv,
          verifierCiphertext: vault.verifier_ciphertext,
        }
      : null,
    entries: results.map((row) => ({
      id: row.id,
      iv: row.iv,
      ciphertext: row.ciphertext,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    })),
  });
}

async function createVault(request, env, session) {
  const body = await readJson(request);
  const iterations = Number(body.iterations);
  if (
    !Number.isInteger(iterations) ||
    iterations < PASSWORD_KDF_ITERATIONS ||
    iterations > MAX_ITERATIONS ||
    !isBase64(body.salt, 16, 16) ||
    !isBase64(body.verifierIv, 12, 12) ||
    !isBase64(body.verifierCiphertext, 17, 256)
  ) {
    return json({ error: "invalid_vault" }, 400);
  }

  // 1行だけ。先に誰かが作っていたら上書きしない
  const result = await env.DB.prepare(
    `INSERT INTO password_vault (id, kdf, iterations, salt, verifier_iv, verifier_ciphertext, created_by_discord_id)
     VALUES (1, 'PBKDF2-SHA256', ?, ?, ?, ?, ?)
     ON CONFLICT (id) DO NOTHING`,
  )
    .bind(iterations, body.salt, body.verifierIv, body.verifierCiphertext, session.id)
    .run();
  if (!result.meta.changes) return json({ error: "vault_exists" }, 409);

  await logEvent(env, request, session.id, "password_vault_created");
  return json({ ok: true }, 201);
}

async function createEntry(request, env, session) {
  const body = await readJson(request);
  if (!(await vaultExists(env))) return json({ error: "vault_missing" }, 409);
  if (!isEncryptedEntry(body)) return json({ error: "invalid_entry" }, 400);

  const result = await env.DB.prepare(
    `INSERT INTO password_entries (iv, ciphertext, created_by_discord_id)
     VALUES (?, ?, ?)`,
  )
    .bind(body.iv, body.ciphertext, session.id)
    .run();

  const id = result.meta.last_row_id;
  await logEvent(env, request, session.id, "password_entry_created", `#${id}`);
  return json({ id }, 201);
}

async function updateEntry(id, request, env, session) {
  const body = await readJson(request);
  if (!isEncryptedEntry(body)) return json({ error: "invalid_entry" }, 400);

  const result = await env.DB.prepare(
    `UPDATE password_entries
        SET iv = ?, ciphertext = ?, updated_by_discord_id = ?, updated_at = CURRENT_TIMESTAMP
      WHERE id = ? AND deleted_at IS NULL`,
  )
    .bind(body.iv, body.ciphertext, session.id, id)
    .run();
  if (!result.meta.changes) return json({ error: "not_found" }, 404);

  await logEvent(env, request, session.id, "password_entry_updated", `#${id}`);
  return json({ ok: true });
}

async function deleteEntry(id, request, env, session) {
  const result = await env.DB.prepare(
    `UPDATE password_entries
        SET deleted_at = CURRENT_TIMESTAMP, updated_by_discord_id = ?
      WHERE id = ? AND deleted_at IS NULL`,
  )
    .bind(session.id, id)
    .run();
  if (!result.meta.changes) return json({ error: "not_found" }, 404);

  await logEvent(env, request, session.id, "password_entry_deleted", `#${id}`);
  return json({ ok: true });
}

async function vaultExists(env) {
  return Boolean(await env.DB.prepare("SELECT 1 AS ok FROM password_vault WHERE id = 1").first());
}

async function readJson(request) {
  try {
    const body = await request.json();
    return body && typeof body === "object" ? body : {};
  } catch (error) {
    return {};
  }
}

function isEncryptedEntry(body) {
  return isBase64(body.iv, 12, 12) && isBase64(body.ciphertext, 17, MAX_CIPHERTEXT_LENGTH);
}

// base64 の文字列で、デコードしたバイト数が min〜max に収まるか
function isBase64(value, min, max) {
  if (typeof value !== "string" || value.length % 4 !== 0 || !BASE64.test(value)) return false;
  const padding = value.endsWith("==") ? 2 : value.endsWith("=") ? 1 : 0;
  const bytes = (value.length / 4) * 3 - padding;
  return bytes >= min && bytes <= max;
}
