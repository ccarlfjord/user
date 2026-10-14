ALTER TABLE oauth_clients
	DROP CONSTRAINT IF EXISTS oauth_clients_auth_method_matches_type,
	DROP CONSTRAINT IF EXISTS oauth_clients_auth_method_known,
	DROP CONSTRAINT IF EXISTS oauth_clients_grant_types_not_empty,
	DROP CONSTRAINT IF EXISTS oauth_clients_response_types_not_empty,
	DROP COLUMN IF EXISTS registration_access_token_hash,
	DROP COLUMN IF EXISTS token_endpoint_auth_method,
	DROP COLUMN IF EXISTS grant_types,
	DROP COLUMN IF EXISTS response_types;
