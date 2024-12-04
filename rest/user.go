package rest

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/ccarlfjord/user-service/argon2"
	"github.com/ccarlfjord/user-service/repository"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// getUser returns a user from JSON payload
func (c *controller) getUser(w http.ResponseWriter, r *http.Request) {
	validateContentTypeJSON(w, r)

	var request struct {
		Email string `json:"email"`
	}

	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		slog.Error(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	u, err := c.db.GetUserByEmail(r.Context(), request.Email)
	if err == pgx.ErrNoRows {
		slog.Debug("user not found", "user", request.Email)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if err != nil {
		slog.Error(err.Error())
	}
	JSON(w, http.StatusOK, u)
}

// getUserByID returns a user by ID
func (c *controller) getUserByID(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	uuid, err := uuid.Parse(id)
	if err != nil {
		slog.Error(err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	user, err := c.db.GetUserById(r.Context(), uuid)
	u := User{
		ID:       user.ID,
		Email:    user.Email,
		Username: user.Username,
		Active:   user.Active,
		Admin:    user.Admin,
	}

	if err != nil {
		slog.Error(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	json, err := json.Marshal(u)
	if err != nil {
		slog.Error(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Write(json)
}

type CreateUserRequest struct {
	Email    string `json:"email"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// createUser creates a new user
func (c *controller) createUser(w http.ResponseWriter, r *http.Request) {
	// Validate content type of request is application/json
	validateContentTypeJSON(w, r)

	// Read JSON from request body
	var req CreateUserRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		slog.Error(err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	salt := argon2.GenerateSalt()

	// If user exists, return 200 and user
	exists, err := c.db.GetUserByEmail(r.Context(), req.Email)
	if err == nil {
		JSON(w, http.StatusOK, exists)
		return
	}

	hashedPassword := argon2.HashPassword(req.Password, salt)
	userParams := repository.CreateUserParams{
		ID:             uuid.New(),
		Username:       req.Username,
		Email:          req.Email,
		HashedPassword: hashedPassword,
		Salt:           salt,
	}

	user, err := c.db.CreateUser(r.Context(), userParams)
	if err != nil {
		slog.Error(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	JSON(w, http.StatusOK, User{
		ID:       user.ID,
		Email:    user.Email,
		Username: user.Username,
		Active:   user.Active,
		Admin:    user.Admin,
	})
}

// deleteUser deletes user on email or ID from request
// ID takes precedence over email
func (c *controller) deleteUser(w http.ResponseWriter, r *http.Request) {
}

// updateUser updates user in database with data from request
func (c *controller) updateUser(w http.ResponseWriter, r *http.Request) {
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}
type LoginResponse struct {
	Session string `json:"session"`
}

func (c *controller) login(w http.ResponseWriter, r *http.Request) {
	validateContentTypeJSON(w, r)
	var request LoginRequest

	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	user, err := c.db.GetUserByEmail(r.Context(), request.Email)
	if err != nil {
		slog.Error(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if user.HashedPassword == nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Validate password
	err = argon2.Validate(request.Password, user.HashedPassword, user.Salt)
	if err == nil {
		now := time.Now()
		expiresAt := now.Add(1 * time.Hour)

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
			Subject:   user.ID.String(),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		})

		sessionToken, err := token.SignedString(c.sessionToken)
		if err != nil {
			slog.Error(err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		JSON(w, http.StatusOK, LoginResponse{
			Session: sessionToken,
		})
		return
	}
	if err != nil {
		slog.Error(err.Error())
	}

	w.WriteHeader(http.StatusForbidden)
}
