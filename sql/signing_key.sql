-- name: ListSigningKeys :many
SELECT * FROM signing_keys ORDER BY created_at DESC, name DESC;

-- name: CreateSigningKey :exec
INSERT INTO signing_keys(name, value) VALUES($1, $2)
ON CONFLICT (name) DO NOTHING;
