-- name: CreateClient :one
INSERT INTO oauth_clients(
    client_id, client_secret_hash, is_public, name, redirect_uris, allowed_scopes,
    token_endpoint_auth_method, grant_types, response_types, registration_access_token_hash, active
)
VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
RETURNING *;

-- name: GetClientById :one
SELECT * FROM oauth_clients WHERE client_id = $1;

-- GetClientByRegistrationToken resolves the client a management request names
-- and authenticates it in one lookup: a token that belongs to a different
-- client matches no row, so the caller cannot manage a client it was not
-- registered as.
-- name: GetClientByRegistrationToken :one
SELECT * FROM oauth_clients
WHERE client_id = $1 AND registration_access_token_hash = $2;

-- name: UpdateClient :one
UPDATE oauth_clients
SET client_secret_hash = $2,
    is_public = $3,
    name = $4,
    redirect_uris = $5,
    allowed_scopes = $6,
    token_endpoint_auth_method = $7,
    grant_types = $8,
    response_types = $9,
    registration_access_token_hash = $10
WHERE client_id = $1
RETURNING *;

-- name: DeleteClient :execrows
DELETE FROM oauth_clients WHERE client_id = $1;
