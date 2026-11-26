export const SESSION_MAX_AGE_SECONDS = 60 * 60 * 24 * 30;

export async function signJson(payload, secret) {
  return signValue(base64UrlEncode(new TextEncoder().encode(JSON.stringify(payload))), secret);
}

export async function verifySignedJson(value, secret) {
  const payload = await verifySignedValue(value, secret);
  if (!payload) return null;
  try {
    return JSON.parse(new TextDecoder().decode(base64UrlDecode(payload)));
  } catch (error) {
    return null;
  }
}

export async function signValue(value, secret) {
  const signature = await hmacSha256(value, secret);
  return `${value}.${base64UrlEncode(signature)}`;
}

export async function verifySignedValue(value, secret) {
  const [payload, signature] = value.split(".");
  if (!payload || !signature) return "";
  const expected = base64UrlEncode(await hmacSha256(payload, secret));
  return timingSafeEqual(signature, expected) ? payload : "";
}

export async function hmacSha256(value, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value)));
}

export async function sha256Bytes(value) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)));
}

export function cookie(name, value, secure, maxAge = SESSION_MAX_AGE_SECONDS) {
  return `${name}=${value}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge};${secure ? " Secure;" : ""}`;
}

export function clearCookie(name) {
  return `${name}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0`;
}

export function parseCookies(header) {
  const cookies = {};
  for (const part of header.split(";")) {
    const [key, ...valueParts] = part.trim().split("=");
    const value = valueParts.join("=");
    if (key && value) cookies[key] = value;
  }
  return cookies;
}

export function canAddSecrets(userId, env) {
  const managers = parseCsv(env.DISCORD_SECRET_MANAGER_USER_IDS || "");
  if (managers.size > 0) return managers.has(userId);
  return parseCsv(env.DISCORD_ALLOWED_USER_IDS || "").has(userId);
}

export function parseCsv(value) {
  return new Set(
    value
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean),
  );
}

export function assertDiscordConfig(env) {
  if (!env.DISCORD_CLIENT_ID || !env.DISCORD_CLIENT_SECRET) {
    throw new Error("Discord OAuth is not configured.");
  }
}

export function json(payload, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" },
  });
}

export function html(markup, status = 200) {
  return new Response(markup, {
    status,
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}

export function toBytes(value) {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  return new Uint8Array(value);
}

export function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

export function base64UrlEncode(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function base64UrlDecode(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  const binary = atob(base64);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

export function timingSafeEqual(left, right) {
  if (left.length !== right.length) return false;
  let result = 0;
  for (let i = 0; i < left.length; i += 1) {
    result |= left.charCodeAt(i) ^ right.charCodeAt(i);
  }
  return result === 0;
}

export async function getVaultRaw(env) {
  if (!env.VAULT_ENCRYPTION_KEY) throw new Error("VAULT_ENCRYPTION_KEY is required.");
  return /^[0-9a-f]{64}$/i.test(env.VAULT_ENCRYPTION_KEY)
    ? hexToBytes(env.VAULT_ENCRYPTION_KEY)
    : sha256Bytes(env.VAULT_ENCRYPTION_KEY);
}

export async function hmacSha256Bytes(keyBytes, value) {
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value)));
}
