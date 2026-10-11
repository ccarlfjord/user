-- name: GetSigningKey :one
SELECT * FROM signing_keys WHERE name = $1;

-- name: CreateSigningKey :exec
INSERT INTO signing_keys(name, value) VALUES($1, $2)
ON CONFLICT (name) DO NOTHING;
