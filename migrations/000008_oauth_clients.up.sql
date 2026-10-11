-- OAuth clients are the relying parties this provider may send users back
-- to. client_id is public and random (a random UUID string, not a secret);
-- the client_secret_hash is the only credential, stored as a SHA-256 hash
-- (the secret is server-generated randomness, not a password, so it gets the
-- same cheap hash as every server-minted token rather than the argon2id in
-- users.hashed_password), and is NULL for public clients (SPAs and native
-- apps, which authenticate nothing and must use PKCE). is_public records that
-- distinction explicitly so /token does not have to infer it from a NULL
-- column. redirect_uris are stored as exact strings, compared verbatim at
-- redirect time — no wildcards, no pattern matching, no trailing-slash
-- tolerance. allowed_scopes is the grant ceiling for the client; a request
-- for anything outside it is rejected at /authorize, so token exchange never
-- has to widen a grant.
CREATE TABLE IF NOT EXISTS oauth_clients (
	client_id          TEXT NOT NULL PRIMARY KEY,
	client_secret_hash BYTEA,
	is_public          BOOLEAN NOT NULL DEFAULT FALSE,
	name               TEXT NOT NULL,
	redirect_uris      TEXT[] NOT NULL,
	allowed_scopes     TEXT[] NOT NULL,
	active             BOOLEAN NOT NULL DEFAULT TRUE,
	created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
	-- A client that cannot redirect anywhere is unusable: /authorize would
	-- have no safe place to send the user back to. cardinality() rather than
	-- array_length(): array_length of an empty array is NULL and NULL > 0
	-- evaluates to NULL, which satisfies a CHECK — cardinality returns 0.
	CONSTRAINT oauth_clients_redirect_uris_not_empty CHECK (cardinality(redirect_uris) > 0),
	-- A confidential client is one that holds a secret; a public client must
	-- not have one to leak.
	CONSTRAINT oauth_clients_secret_matches_type CHECK (
		(is_public AND client_secret_hash IS NULL)
		OR (NOT is_public AND client_secret_hash IS NOT NULL)
	)
);
