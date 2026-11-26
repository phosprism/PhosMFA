-- 管理者が決めるアカウントの並び順と、利用者ごとの表示・非表示。

ALTER TABLE totp_accounts ADD COLUMN sort_order INTEGER NOT NULL DEFAULT 0;

-- 今の表示順 (サービス名 → アカウント名) をそのまま初期値にする
UPDATE totp_accounts
   SET sort_order = (
     SELECT COUNT(*)
       FROM totp_accounts other
      WHERE other.service_name < totp_accounts.service_name
         OR (other.service_name = totp_accounts.service_name AND other.account_name < totp_accounts.account_name)
         OR (other.service_name = totp_accounts.service_name AND other.account_name = totp_accounts.account_name AND other.id < totp_accounts.id)
   ) + 1;

CREATE INDEX IF NOT EXISTS idx_totp_accounts_sort_order ON totp_accounts (sort_order);

-- 非表示にした組み合わせだけを持つ (行がなければ表示)
CREATE TABLE IF NOT EXISTS account_visibility (
  discord_id TEXT NOT NULL,
  account_id INTEGER NOT NULL,
  hidden INTEGER NOT NULL DEFAULT 1,
  updated_by_discord_id TEXT,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (discord_id, account_id)
);
