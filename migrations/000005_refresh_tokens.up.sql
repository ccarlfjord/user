-- Refresh tokens let a client mint a new short-lived session without holding
-- the password, and outlive the session itself so a client that was offline
-- longer than the session TTL can still come back. Only the SHA-256 hash is
-- stored, so a database leak does not expose usable tokens. The row records
-- the account's session generation at issue, so a password change retires
-- every refresh token minted before it exactly as it retires sessions.
CREATE TABLE IF NOT EXISTS refresh_tokens (
	token_hash    BYTEA NOT NULL PRIMARY KEY,
	user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	session_epoch INTEGER NOT NULL,
	expires_at    TIMESTAMPTZ NOT NULL,
	created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS refresh_tokens_user_id_idx ON refresh_tokens (user_id);