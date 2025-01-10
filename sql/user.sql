-- name: GetUserById :one
SELECT * FROM users WHERE id = $1;

-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = $1;

-- name: GetUsers :many
SELECT * FROM users;

-- name: DeleteUser :exec
DELETE FROM users WHERE id = $1;

-- name: ActivateUser :exec
UPDATE users SET active = TRUE WHERE id = $1;

-- name: DeactivateUser :exec
UPDATE users SET active = FALSE WHERE id = $1;

-- name: SetAdmin :exec
UPDATE users SET admin = TRUE WHERE id = $1;

-- name: DisableAdmin :exec
UPDATE users SET admin = FALSE WHERE id = $1;

-- name: CreateUser :one
INSERT INTO users(id, username, email, hashed_password, salt, active, admin) VALUES( $1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: StoreUser :one
UPDATE users SET (username, email, hashed_password, salt, active, admin) = ($2, $3, $4, $5, $6, $7) WHERE id = $1
RETURNING *;

