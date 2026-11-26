// 最小限の WebAuthn (パスキー) 検証。外部ライブラリなしで Workers の WebCrypto だけを使う。
// 対応アルゴリズム: ES256 (-7), RS256 (-257)。attestation は "none" で受け取り、証明書チェーンは検証しない。
import { base64UrlDecode, base64UrlEncode } from "./util.mjs";

export const SUPPORTED_ALGORITHMS = [-7, -257];

const FLAG_USER_PRESENT = 0x01;
const FLAG_USER_VERIFIED = 0x04;
const FLAG_ATTESTED_DATA = 0x40;

export async function verifyRegistration({ credential, expectedChallenge, expectedOrigin, rpId }) {
  const response = credential?.response || {};
  const clientData = parseClientData(response.clientDataJSON, "webauthn.create", expectedChallenge, expectedOrigin);
  void clientData;

  const attestation = decodeCbor(base64UrlDecode(String(response.attestationObject || "")));
  if (!(attestation.authData instanceof Uint8Array)) throw new WebAuthnError("attestation_invalid");

  const authData = parseAuthenticatorData(attestation.authData);
  await assertRpIdHash(authData.rpIdHash, rpId);
  assertFlags(authData.flags);
  if (!(authData.flags & FLAG_ATTESTED_DATA) || !authData.credentialId || !authData.publicKey) {
    throw new WebAuthnError("attested_data_missing");
  }

  const credentialId = base64UrlEncode(authData.credentialId);
  if (credential.id && credential.id !== credentialId) throw new WebAuthnError("credential_id_mismatch");

  const { jwk, alg } = coseToJwk(authData.publicKey);
  // 公開鍵として読み込めるか確認しておく
  await importPublicKey(jwk, alg);

  const transports = Array.isArray(response.transports)
    ? response.transports.filter((item) => typeof item === "string").slice(0, 8)
    : [];

  return { credentialId, jwk, alg, signCount: authData.signCount, transports };
}

export async function verifyAuthentication({ credential, expectedChallenge, expectedOrigin, rpId, jwk, alg, storedSignCount }) {
  const response = credential?.response || {};
  const clientDataBytes = base64UrlDecode(String(response.clientDataJSON || ""));
  parseClientData(response.clientDataJSON, "webauthn.get", expectedChallenge, expectedOrigin);

  const authDataBytes = base64UrlDecode(String(response.authenticatorData || ""));
  const authData = parseAuthenticatorData(authDataBytes);
  await assertRpIdHash(authData.rpIdHash, rpId);
  assertFlags(authData.flags);

  const clientDataHash = new Uint8Array(await crypto.subtle.digest("SHA-256", clientDataBytes));
  const signedData = concatBytes(authDataBytes, clientDataHash);
  const signature = base64UrlDecode(String(response.signature || ""));
  const key = await importPublicKey(jwk, alg);

  let valid;
  if (alg === -7) {
    valid = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, derToRawEcdsa(signature, 32), signedData);
  } else {
    valid = await crypto.subtle.verify({ name: "RSASSA-PKCS1-v1_5" }, key, signature, signedData);
  }
  if (!valid) throw new WebAuthnError("signature_invalid");

  // 署名カウンタが巻き戻った場合は鍵の複製を疑う (同期型パスキーは常に 0 なので対象外)
  if (authData.signCount > 0 || storedSignCount > 0) {
    if (authData.signCount <= storedSignCount) throw new WebAuthnError("sign_count_invalid");
  }

  return { signCount: authData.signCount };
}

export class WebAuthnError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

function parseClientData(encoded, expectedType, expectedChallenge, expectedOrigin) {
  let clientData;
  try {
    clientData = JSON.parse(new TextDecoder().decode(base64UrlDecode(String(encoded || ""))));
  } catch (error) {
    throw new WebAuthnError("client_data_invalid");
  }
  if (clientData.type !== expectedType) throw new WebAuthnError("client_data_type_invalid");
  if (!expectedChallenge || clientData.challenge !== expectedChallenge) throw new WebAuthnError("challenge_mismatch");
  if (clientData.origin !== expectedOrigin) throw new WebAuthnError("origin_mismatch");
  if (clientData.crossOrigin === true) throw new WebAuthnError("cross_origin");
  return clientData;
}

async function assertRpIdHash(rpIdHash, rpId) {
  const expected = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(rpId)));
  if (!bytesEqual(rpIdHash, expected)) throw new WebAuthnError("rp_id_mismatch");
}

function assertFlags(flags) {
  if (!(flags & FLAG_USER_PRESENT)) throw new WebAuthnError("user_not_present");
  if (!(flags & FLAG_USER_VERIFIED)) throw new WebAuthnError("user_not_verified");
}

export function parseAuthenticatorData(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length < 37) throw new WebAuthnError("auth_data_invalid");
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const result = {
    rpIdHash: bytes.slice(0, 32),
    flags: bytes[32],
    signCount: view.getUint32(33),
    credentialId: null,
    publicKey: null,
  };

  if (result.flags & FLAG_ATTESTED_DATA) {
    let offset = 37 + 16; // aaguid
    const idLength = view.getUint16(offset);
    offset += 2;
    result.credentialId = bytes.slice(offset, offset + idLength);
    offset += idLength;
    const decoded = decodeCborItem(bytes, offset);
    result.publicKey = decoded.value;
  }
  return result;
}

export function coseToJwk(cose) {
  if (!(cose instanceof Map)) throw new WebAuthnError("cose_invalid");
  const kty = cose.get(1);
  const alg = cose.get(3);

  if (alg === -7 && kty === 2) {
    if (cose.get(-1) !== 1) throw new WebAuthnError("unsupported_curve");
    const x = cose.get(-2);
    const y = cose.get(-3);
    if (!(x instanceof Uint8Array) || !(y instanceof Uint8Array)) throw new WebAuthnError("cose_invalid");
    return { alg, jwk: { kty: "EC", crv: "P-256", x: base64UrlEncode(x), y: base64UrlEncode(y) } };
  }

  if (alg === -257 && kty === 3) {
    const n = cose.get(-1);
    const e = cose.get(-2);
    if (!(n instanceof Uint8Array) || !(e instanceof Uint8Array)) throw new WebAuthnError("cose_invalid");
    return { alg, jwk: { kty: "RSA", alg: "RS256", n: base64UrlEncode(n), e: base64UrlEncode(e) } };
  }

  throw new WebAuthnError("unsupported_algorithm");
}

function importPublicKey(jwk, alg) {
  if (alg === -7) {
    return crypto.subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  }
  if (alg === -257) {
    return crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
  }
  throw new WebAuthnError("unsupported_algorithm");
}

// ECDSA 署名は DER (SEQUENCE { INTEGER r, INTEGER s }) で届くので、WebCrypto 用の r||s に変換する
export function derToRawEcdsa(der, size) {
  let offset = 0;
  if (der[offset++] !== 0x30) throw new WebAuthnError("signature_invalid");
  offset += der[offset] & 0x80 ? 1 + (der[offset] & 0x7f) : 1;
  const readInteger = () => {
    if (der[offset++] !== 0x02) throw new WebAuthnError("signature_invalid");
    const length = der[offset++];
    let value = der.slice(offset, offset + length);
    offset += length;
    while (value.length > size && value[0] === 0) value = value.slice(1);
    if (value.length > size) throw new WebAuthnError("signature_invalid");
    const padded = new Uint8Array(size);
    padded.set(value, size - value.length);
    return padded;
  };
  return concatBytes(readInteger(), readInteger());
}

// --- CBOR (RFC 8949) の必要最小限のデコーダ ---

export function decodeCbor(bytes) {
  const { value, offset } = decodeCborItem(bytes, 0);
  if (offset !== bytes.length) throw new WebAuthnError("cbor_trailing_bytes");
  if (value instanceof Map) {
    const object = {};
    for (const [key, item] of value) object[key] = item;
    return object;
  }
  return value;
}

function decodeCborItem(bytes, start, depth = 0) {
  if (depth > 16) throw new WebAuthnError("cbor_too_deep");
  let offset = start;
  if (offset >= bytes.length) throw new WebAuthnError("cbor_truncated");
  const initial = bytes[offset++];
  const major = initial >> 5;
  const info = initial & 0x1f;

  const readLength = () => {
    if (info < 24) return info;
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    if (info === 24) return bytes[offset++];
    if (info === 25) {
      const value = view.getUint16(offset);
      offset += 2;
      return value;
    }
    if (info === 26) {
      const value = view.getUint32(offset);
      offset += 4;
      return value;
    }
    if (info === 27) {
      const value = Number(view.getBigUint64(offset));
      offset += 8;
      return value;
    }
    throw new WebAuthnError("cbor_unsupported");
  };

  switch (major) {
    case 0:
      return { value: readLength(), offset };
    case 1:
      return { value: -1 - readLength(), offset };
    case 2: {
      const length = readLength();
      if (offset + length > bytes.length) throw new WebAuthnError("cbor_truncated");
      return { value: bytes.slice(offset, offset + length), offset: offset + length };
    }
    case 3: {
      const length = readLength();
      if (offset + length > bytes.length) throw new WebAuthnError("cbor_truncated");
      return { value: new TextDecoder().decode(bytes.slice(offset, offset + length)), offset: offset + length };
    }
    case 4: {
      const length = readLength();
      const items = [];
      for (let i = 0; i < length; i += 1) {
        const item = decodeCborItem(bytes, offset, depth + 1);
        items.push(item.value);
        offset = item.offset;
      }
      return { value: items, offset };
    }
    case 5: {
      const length = readLength();
      const map = new Map();
      for (let i = 0; i < length; i += 1) {
        const key = decodeCborItem(bytes, offset, depth + 1);
        const item = decodeCborItem(bytes, key.offset, depth + 1);
        map.set(key.value, item.value);
        offset = item.offset;
      }
      return { value: map, offset };
    }
    case 7:
      if (info === 20) return { value: false, offset };
      if (info === 21) return { value: true, offset };
      if (info === 22) return { value: null, offset };
      throw new WebAuthnError("cbor_unsupported");
    default:
      throw new WebAuthnError("cbor_unsupported");
  }
}

function concatBytes(...parts) {
  const result = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

function bytesEqual(left, right) {
  if (left.length !== right.length) return false;
  let diff = 0;
  for (let i = 0; i < left.length; i += 1) diff |= left[i] ^ right[i];
  return diff === 0;
}
