-- name: CreatePasswordResetToken :exec
INSERT INTO password_reset_tokens(token_hash, user_id, expires_at) VALUES($1, $2, $3);

-- name: ConsumePasswordResetToken :one
DELETE FROM password_reset_tokens WHERE token_hash = $1
RETURNING token_hash, user_id, expires_at, created_at;

-- name: DeletePasswordResetTokensForUser :exec
DELETE FROM password_reset_tokens WHERE user_id = $1;

-- name: DeleteExpiredPasswordResetTokens :execrows
DELETE FROM password_reset_tokens WHERE expires_at < now();
