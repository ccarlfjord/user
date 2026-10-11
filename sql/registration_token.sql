-- name: CreateRegistrationToken :exec
INSERT INTO registration_tokens(token_hash, expires_at) VALUES($1, $2);

-- name: ConsumeRegistrationToken :one
DELETE FROM registration_tokens WHERE token_hash = $1
RETURNING token_hash, expires_at, created_at;

-- name: DeleteExpiredRegistrationTokens :execrows
DELETE FROM registration_tokens WHERE expires_at < now();
