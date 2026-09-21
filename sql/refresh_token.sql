-- name: CreateRefreshToken :exec
INSERT INTO refresh_tokens(token_hash, user_id, session_epoch, expires_at) VALUES($1, $2, $3, $4);

-- name: ConsumeRefreshToken :one
DELETE FROM refresh_tokens WHERE token_hash = $1
RETURNING token_hash, user_id, session_epoch, expires_at, created_at;
-- name: DeleteExpiredRefreshTokens :execrows
DELETE FROM refresh_tokens WHERE expires_at < now();
