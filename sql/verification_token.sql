-- name: CreateVerificationToken :exec
INSERT INTO verification_tokens(token_hash, user_id, expires_at) VALUES($1, $2, $3);

-- name: GetVerificationToken :one
SELECT token_hash, user_id, expires_at, created_at FROM verification_tokens WHERE token_hash = $1;

-- name: DeleteVerificationToken :exec
DELETE FROM verification_tokens WHERE token_hash = $1;

-- name: DeleteVerificationTokensForUser :exec
DELETE FROM verification_tokens WHERE user_id = $1;
