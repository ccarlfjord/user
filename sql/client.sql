-- name: CreateClient :one
INSERT INTO oauth_clients(client_id, client_secret_hash, is_public, name, redirect_uris, allowed_scopes, active)
VALUES($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: GetClientById :one
SELECT * FROM oauth_clients WHERE client_id = $1;

-- name: DeleteClient :execrows
DELETE FROM oauth_clients WHERE client_id = $1;
