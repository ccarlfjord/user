DROP TABLE IF EXISTS verification_tokens;

ALTER TABLE users ADD COLUMN IF NOT EXISTS username TEXT;

DROP TABLE IF EXISTS signing_keys;
