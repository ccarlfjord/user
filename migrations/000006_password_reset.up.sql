-- Password reset tokens let an account holder who has forgotten their
-- password prove control of the account's email address and set a new one.
-- Like verification and refresh tokens, only the SHA-256 hash is stored, so a
-- database leak does not expose usable tokens; the row goes with its user via
-- ON DELETE CASCADE.
CREATE TABLE IF NOT EXISTS password_reset_tokens (
	token_hash BYTEA NOT NULL PRIMARY KEY,
	user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	expires_at TIMESTAMPTZ NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS password_reset_tokens_user_id_idx ON password_reset_tokens (user_id);
