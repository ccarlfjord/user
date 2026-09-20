CREATE TABLE IF NOT EXISTS signing_keys (
	name TEXT NOT NULL PRIMARY KEY,
	value BYTEA NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE users DROP COLUMN IF EXISTS username;

CREATE TABLE IF NOT EXISTS verification_tokens (
	token_hash BYTEA NOT NULL PRIMARY KEY,
	user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	expires_at TIMESTAMPTZ NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS verification_tokens_user_id_idx ON verification_tokens (user_id);
