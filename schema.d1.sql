CREATE TABLE IF NOT EXISTS totp_accounts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  service_name TEXT NOT NULL,
  account_name TEXT NOT NULL,
  role_name TEXT,
  encrypted_secret BLOB NOT NULL,
  iv BLOB NOT NULL,
  algorithm TEXT NOT NULL DEFAULT 'SHA1',
  digits INTEGER NOT NULL DEFAULT 6,
  period INTEGER NOT NULL DEFAULT 30,
  created_by_discord_id TEXT NOT NULL,
  updated_by_discord_id TEXT,
  deleted_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_totp_accounts_service_name ON totp_accounts (service_name);
CREATE INDEX IF NOT EXISTS idx_totp_accounts_account_name ON totp_accounts (account_name);
CREATE INDEX IF NOT EXISTS idx_totp_accounts_created_by ON totp_accounts (created_by_discord_id);
CREATE INDEX IF NOT EXISTS idx_totp_accounts_deleted_at ON totp_accounts (deleted_at);

-- Discord ログイン後の2段階認証 (パスコード / パスキー)、アカウントロック、管理者向けの履歴。

CREATE TABLE IF NOT EXISTS app_users (
  discord_id TEXT PRIMARY KEY,
  username TEXT NOT NULL DEFAULT '',
  global_name TEXT NOT NULL DEFAULT '',
  passcode_hash TEXT,
  passcode_salt TEXT,
  passcode_length INTEGER,
  unlock_on_open INTEGER,            -- NULL: 未選択 / 0: 開いたときに求めない / 1: 求める
  failed_attempts INTEGER NOT NULL DEFAULT 0,
  locked_at TEXT,
  lock_reason TEXT,                  -- too_many_attempts / admin
  locked_by_discord_id TEXT,
  session_epoch INTEGER NOT NULL DEFAULT 0,  -- 増やすと既存セッションをすべて無効化
  pending_challenge TEXT,
  pending_challenge_purpose TEXT,
  pending_challenge_expires_at INTEGER,
  last_login_at TEXT,
  last_verified_at TEXT,
  last_failed_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS passkeys (
  credential_id TEXT PRIMARY KEY,
  discord_id TEXT NOT NULL,
  public_key_jwk TEXT NOT NULL,
  algorithm INTEGER NOT NULL,
  sign_count INTEGER NOT NULL DEFAULT 0,
  transports TEXT,
  name TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_used_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_passkeys_discord_id ON passkeys (discord_id);

CREATE TABLE IF NOT EXISTS security_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  discord_id TEXT NOT NULL,
  event TEXT NOT NULL,
  detail TEXT,
  actor_discord_id TEXT,
  ip TEXT,
  country TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_security_events_user ON security_events (discord_id, id);
