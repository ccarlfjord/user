-- Registration tokens gate dynamic client registration (RFC 7591). Open
-- registration would let anyone mint a client and put its name on the consent
-- page, so /register demands an initial access token: one is minted for a
-- relying party out-of-band (hand SQL until an admin path exists), handed to
-- the integrator, and burned on use. Only the SHA-256 hash is stored, and a
-- token is single-use by deletion (ConsumeRegistrationToken) like every other
-- bearer credential here — a token can never quietly grant a second client.
CREATE TABLE IF NOT EXISTS registration_tokens (
	token_hash BYTEA NOT NULL PRIMARY KEY,
	expires_at TIMESTAMPTZ NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
