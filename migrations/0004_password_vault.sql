-- パスワード管理 (テスト中・管理者だけ)。
-- ID・パスワードはブラウザの中で暗号化してから送るので、ここには暗号文しか入らない。
-- 鍵: チームで共有するマスターパスワード → PBKDF2-SHA256 (60万回) → AES-256-GCM

-- マスターパスワードから鍵を作るための設定。1行だけ持つ
CREATE TABLE IF NOT EXISTS password_vault (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  kdf TEXT NOT NULL DEFAULT 'PBKDF2-SHA256',
  iterations INTEGER NOT NULL,
  salt TEXT NOT NULL,                 -- base64 (16バイト)
  verifier_iv TEXT NOT NULL,          -- マスターパスワードが合っているかを確かめるための暗号文
  verifier_ciphertext TEXT NOT NULL,
  created_by_discord_id TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 名前・URL・ID・パスワード・メモをまとめて JSON にし、暗号化したもの
CREATE TABLE IF NOT EXISTS password_entries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  iv TEXT NOT NULL,                   -- base64 (12バイト)
  ciphertext TEXT NOT NULL,           -- base64 (AES-256-GCM)
  created_by_discord_id TEXT NOT NULL,
  updated_by_discord_id TEXT,
  deleted_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_password_entries_deleted_at ON password_entries (deleted_at);
