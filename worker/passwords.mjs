// パスワード管理 (テスト中のため管理者だけ)。
// 鍵: サーバーの秘密鍵 (VAULT_ENCRYPTION_KEY) → PBKDF2-SHA256 (60万回) → AES-256-GCM。
// 名前・URL・ID・パスワード・メモをまとめて JSON にし、暗号化してから D1 に保存する。
// D1 だけが漏れても、秘密鍵がなければ中身は読めない。
import { canAddSecrets, getVaultRaw, hmacSha256Bytes, json } from "./util.mjs";
import { logEvent } from "./security.mjs";

export const PASSWORD_KDF_ITERATIONS = 600000;
const KDF_NAME = "PBKDF2-SHA256-SERVER";
const VERIFIER = "PhosMFA password vault v1";
const LIMITS = { title: 200, url: 2000, username: 500, password: 1000, note: 4000 };

// 60万回の計算は重いので、作った鍵は Worker のメモリに置いて使い回す (salt ごと)
const keyCache = new Map();

export async function handlePasswordsApi(request, env, session, path) {
  if (!canAddSecrets(session.id, env)) return json({ error: "forbidden" }, 403);

  if (path === "" && request.method === "GET") return listPasswords(env);
  if (path === "" && request.method === "POST") return createEntry(request, env, session);

  const match = path.match(/^\/(\d+)$/);
  if (match && request.method === "PATCH") return updateEntry(Number(match[1]), request, env, session);
  if (match && request.method === "DELETE") return deleteEntry(Number(match[1]), request, env, session);

  return json({ error: "not_found" }, 404);
}

async function listPasswords(env) {
  const key = await vaultKey(env);
  const { results } = await env.DB.prepare(
    `SELECT id, iv, ciphertext, updated_at
       FROM password_entries
      WHERE deleted_at IS NULL
      ORDER BY id ASC`,
  ).all();

  const entries = [];
  for (const row of results) {
    try {
      entries.push({ id: row.id, updatedAt: row.updated_at, ...normalizeEntry(JSON.parse(await decrypt(key, row.iv, row.ciphertext))) });
    } catch (error) {
      entries.push({ id: row.id, updatedAt: row.updated_at, broken: true });
    }
  }
  return json({ entries });
}

async function createEntry(request, env, session) {
  const entry = await readEntry(request);
  if (!entry) return json({ error: "invalid_entry" }, 400);

  const encrypted = await encrypt(await vaultKey(env), JSON.stringify({ v: 1, ...entry }));
  const result = await env.DB.prepare(
    `INSERT INTO password_entries (iv, ciphertext, created_by_discord_id)
     VALUES (?, ?, ?)`,
  )
    .bind(encrypted.iv, encrypted.ciphertext, session.id)
    .run();

  const id = result.meta.last_row_id;
  await logEvent(env, request, session.id, "password_entry_created", `#${id}`);
  return json({ id }, 201);
}

async function updateEntry(id, request, env, session) {
  const entry = await readEntry(request);
  if (!entry) return json({ error: "invalid_entry" }, 400);

  const encrypted = await encrypt(await vaultKey(env), JSON.stringify({ v: 1, ...entry }));
  const result = await env.DB.prepare(
    `UPDATE password_entries
        SET iv = ?, ciphertext = ?, updated_by_discord_id = ?, updated_at = CURRENT_TIMESTAMP
      WHERE id = ? AND deleted_at IS NULL`,
  )
    .bind(encrypted.iv, encrypted.ciphertext, session.id, id)
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

async function readEntry(request) {
  let body;
  try {
    body = await request.json();
  } catch (error) {
    return null;
  }
  if (!body || typeof body !== "object") return null;
  const entry = normalizeEntry(body);
  if (!entry.title.trim()) return null;
  for (const [field, max] of Object.entries(LIMITS)) {
    if (entry[field].length > max) return null;
  }
  entry.title = entry.title.trim();
  entry.url = entry.url.trim();
  return entry;
}

function normalizeEntry(data) {
  const text = (value) => (typeof value === "string" ? value : "");
  return {
    title: text(data.title),
    url: text(data.url),
    username: text(data.username),
    password: text(data.password),
    note: text(data.note),
  };
}

// salt は初めて使うときにサーバーで作り、password_vault に1行だけ持つ
async function vaultKey(env) {
  let vault = await env.DB.prepare("SELECT salt, iterations, verifier_iv, verifier_ciphertext FROM password_vault WHERE id = 1").first();
  if (!vault) {
    const salt = bytesToBase64(crypto.getRandomValues(new Uint8Array(16)));
    const key = await deriveKey(env, salt, PASSWORD_KDF_ITERATIONS);
    const verifier = await encrypt(key, VERIFIER);
    await env.DB.prepare(
      `INSERT INTO password_vault (id, kdf, iterations, salt, verifier_iv, verifier_ciphertext, created_by_discord_id)
       VALUES (1, ?, ?, ?, ?, ?, 'server')
       ON CONFLICT (id) DO NOTHING`,
    )
      .bind(KDF_NAME, PASSWORD_KDF_ITERATIONS, salt, verifier.iv, verifier.ciphertext)
      .run();
    // 同時に作られたときは、先に入った方を使う
    vault = await env.DB.prepare("SELECT salt, iterations, verifier_iv, verifier_ciphertext FROM password_vault WHERE id = 1").first();
  }

  const key = await deriveKey(env, vault.salt, vault.iterations);
  // 秘密鍵が変わっていたら、読めないデータを増やさないように止める
  try {
    if ((await decrypt(key, vault.verifier_iv, vault.verifier_ciphertext)) !== VERIFIER) throw new Error("mismatch");
  } catch (error) {
    keyCache.delete(`${vault.salt}:${vault.iterations}`);
    throw new Error("Password vault key does not match.");
  }
  return key;
}

async function deriveKey(env, salt, iterations) {
  const cacheKey = `${salt}:${iterations}`;
  // 別のリクエストの Promise を待つと Workers で止まることがあるので、できあがった鍵だけを置く
  const cached = keyCache.get(cacheKey);
  if (cached) return cached;

  // シードの暗号化と同じ秘密鍵から、用途を分けた材料を作る
  const material = await hmacSha256Bytes(await getVaultRaw(env), "phosmfa-password-vault-v1");
  const base = await crypto.subtle.importKey("raw", material, "PBKDF2", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt: base64ToBytes(salt), iterations },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
  keyCache.set(cacheKey, key);
  return key;
}

async function encrypt(key, text) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(text)));
  return { iv: bytesToBase64(iv), ciphertext: bytesToBase64(ciphertext) };
}

async function decrypt(key, iv, ciphertext) {
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: base64ToBytes(iv) }, key, base64ToBytes(ciphertext));
  return new TextDecoder().decode(plain);
}

function bytesToBase64(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64ToBytes(value) {
  return Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
}
