-- name: CreateAuthorizationCode :exec
INSERT INTO authorization_codes(code_hash, client_id, user_id, redirect_uri, scope, nonce, code_challenge, session_epoch, expires_at)
VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9);

-- name: ConsumeAuthorizationCode :one
DELETE FROM authorization_codes WHERE code_hash = $1
RETURNING code_hash, client_id, user_id, redirect_uri, scope, nonce, code_challenge, session_epoch, expires_at, created_at;

-- name: DeleteExpiredAuthorizationCodes :execrows
DELETE FROM authorization_codes WHERE expires_at < now();
