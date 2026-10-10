-- Reverses 000003: restores the 000001 schema shape. The username values
-- themselves are gone — the up dropped the column — so this restores only the
-- columns and constraints. Fails on rows left with a NULL username.
DROP TABLE IF EXISTS verification_tokens;

ALTER TABLE users ADD COLUMN IF NOT EXISTS username TEXT;
ALTER TABLE users ALTER COLUMN username SET NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS users_username_key ON users (username);

DROP TABLE IF EXISTS signing_keys;