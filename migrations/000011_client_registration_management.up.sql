-- RFC 7592 client registration management lets a client read and update its
-- own registration. registration_access_token_hash is the SHA-256 hash of the
-- registration access token returned once at /register; it authenticates
-- GET/PUT/DELETE on /register/{client_id}, so a database leak exposes no
-- usable credential (the same cheap hash every server-minted token gets). It
-- is nullable because clients registered before this migration hold none and
-- cannot self-manage. The other three columns store metadata /register
-- previously echoed and discarded, so a management read can answer with what
-- the client actually registered rather than re-guessing the defaults.
ALTER TABLE oauth_clients
	ADD COLUMN IF NOT EXISTS registration_access_token_hash BYTEA,
	ADD COLUMN IF NOT EXISTS token_endpoint_auth_method TEXT NOT NULL DEFAULT 'client_secret_basic',
	ADD COLUMN IF NOT EXISTS grant_types TEXT[] NOT NULL DEFAULT '{authorization_code}',
	ADD COLUMN IF NOT EXISTS response_types TEXT[] NOT NULL DEFAULT '{code}';

-- Backfill the stored method to match is_public for rows that predate the
-- column: the default is the confidential method, but a public client must
-- read `none` or the CHECK added below rejects it.
UPDATE oauth_clients
SET token_endpoint_auth_method = 'none'
WHERE is_public AND token_endpoint_auth_method <> 'none';

-- The stored method must agree with is_public: `none` is the only public
-- method, the two secret methods the only confidential ones. The 000008
-- secret/type CHECK already ties is_public to a present-or-absent secret.
ALTER TABLE oauth_clients
	ADD CONSTRAINT oauth_clients_auth_method_matches_type CHECK (
		(token_endpoint_auth_method = 'none') = is_public
	),
	ADD CONSTRAINT oauth_clients_auth_method_known CHECK (
		token_endpoint_auth_method IN ('none', 'client_secret_basic', 'client_secret_post')
	),
	ADD CONSTRAINT oauth_clients_grant_types_not_empty CHECK (cardinality(grant_types) > 0),
	ADD CONSTRAINT oauth_clients_response_types_not_empty CHECK (cardinality(response_types) > 0);
