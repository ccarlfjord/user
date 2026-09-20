-- name: GetOrCreateSigningKey :one
INSERT INTO signing_keys(name, value) VALUES($1, $2)
ON CONFLICT (name) DO UPDATE SET value = signing_keys.value
RETURNING *;
