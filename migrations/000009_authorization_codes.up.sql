-- Authorization codes are the short-lived, single-use grants an /authorize
-- consent hands to a relying party for exchange at /token. Only the SHA-256
-- hash of the code is stored, so a database leak does not expose usable
-- grants. The row carries exactly the request parameters the token endpoint
-- must bind the exchange to: the redirect_uri (which the exchange must echo
-- verbatim), the granted scope, the ID-token nonce, and the PKCE challenge —
-- the raw challenge rather than its hash, since the verifier is hashed at
-- exchange time. session_epoch is the account's session generation at issue,
-- so a password change after consent retires any code not yet redeemed, the
-- same way it retires sessions and refresh tokens. A consumed code is deleted
-- atomically on use (ConsumeAuthorizationCode), so a replayed code loses to
-- the concurrent exchange; the table holds only outstanding codes and is kept
-- small by the expiry purge.
CREATE TABLE IF NOT EXISTS authorization_codes (
	code_hash      BYTEA NOT NULL PRIMARY KEY,
	client_id      TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
	user_id        UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	redirect_uri   TEXT NOT NULL,
	scope          TEXT NOT NULL,
	nonce          TEXT NOT NULL DEFAULT '',
	code_challenge TEXT NOT NULL DEFAULT '',
	session_epoch  INTEGER NOT NULL,
	expires_at     TIMESTAMPTZ NOT NULL,
	created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS authorization_codes_user_id_idx ON authorization_codes (user_id);
