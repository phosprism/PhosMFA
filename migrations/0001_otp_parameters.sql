-- アカウントごとの TOTP パラメータ (RFC 6238)。既存行は SHA1 / 6桁 / 30秒 のまま動く。
ALTER TABLE totp_accounts ADD COLUMN algorithm TEXT NOT NULL DEFAULT 'SHA1';
ALTER TABLE totp_accounts ADD COLUMN digits INTEGER NOT NULL DEFAULT 6;
ALTER TABLE totp_accounts ADD COLUMN period INTEGER NOT NULL DEFAULT 30;
