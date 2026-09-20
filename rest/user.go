package rest

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/ccarlfjord/argon2"
	"github.com/ccarlfjord/user/internal/repository"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// getUser returns a user from JSON payload. It is intentionally not routed:
// exposing an unauthenticated lookup by email would let clients enumerate
// registered accounts.
func (c *controller) getUser(w http.ResponseWriter, r *http.Request) {
	if !validateContentTypeJSON(w, r) {
		return
	}

	var request struct {
		Email string `json:"email"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		slog.Error(err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	user, err := c.db.GetUserByEmail(r.Context(), request.Email)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			slog.Error(err.Error())
		}
		w.WriteHeader(http.StatusNotFound)
		return
	}

	JSON(w, http.StatusOK, publicUser(user))
}

// getUserByID returns a user by ID
func (c *controller) getUserByID(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	userID, err := uuid.Parse(id)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	user, err := c.db.GetUserById(r.Context(), userID)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			slog.Error(err.Error())
		}
		w.WriteHeader(http.StatusNotFound)
		return
	}

	JSON(w, http.StatusOK, publicUser(user))
}

type CreateUserRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// signupResponse is returned identically for every sign up attempt so that
// responses cannot be used to enumerate registered accounts.
type signupResponse struct {
	Status string `json:"status"`
}

// createUser creates a new user. The response is intentionally identical
// whether the email was free or already registered, to avoid account
// enumeration.
func (c *controller) createUser(w http.ResponseWriter, r *http.Request) {
	if !validateContentTypeJSON(w, r) {
		return
	}

	var req CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		slog.Error(err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if req.Email == "" || len(req.Password) < 8 {
		PlainText(w, http.StatusBadRequest, "invalid request")
		return
	}

	_, err := c.db.GetUserByEmail(r.Context(), req.Email)
	switch {
	case err == nil:
		// Email already registered: return the same response as a new signup.
		JSON(w, http.StatusCreated, signupResponse{Status: "ok"})
		return
	case !errors.Is(err, pgx.ErrNoRows):
		slog.Error(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	salt := argon2.GenerateSalt()
	userParams := repository.CreateUserParams{
		ID:             uuid.New(),
		Email:          req.Email,
		HashedPassword: argon2.HashPassword(req.Password, salt),
		Salt:           salt,
	}

	user, err := c.db.CreateUser(r.Context(), userParams)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			// Lost a race against a concurrent signup: same response again.
			JSON(w, http.StatusCreated, signupResponse{Status: "ok"})
			return
		}
		slog.Error(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// No email provider is configured yet, so the verification link is logged
	// to the console instead of being sent. Only the token hash is stored.
	token, err := generateVerificationToken()
	if err != nil {
		slog.Error(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	err = c.db.CreateVerificationToken(r.Context(), repository.CreateVerificationTokenParams{
		TokenHash: hashToken(token),
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	})
	if err != nil {
		slog.Error(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	slog.Info("signup verification link",
		"email", user.Email,
		"url", verificationBaseURL()+"/v1/verify?token="+url.QueryEscape(token),
	)

	JSON(w, http.StatusCreated, signupResponse{Status: "ok"})
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
	if !validateContentTypeJSON(w, r) {
		return
	}

	var request LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	user, err := c.db.GetUserByEmail(r.Context(), request.Email)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			slog.Error(err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		// Unknown account: run a real validation against the dummy hash so the
		// response time matches a wrong-password check, then fail generically.
		_ = argon2.Validate(request.Password, c.dummyHash, c.dummySalt)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if user.HashedPassword == nil {
		_ = argon2.Validate(request.Password, c.dummyHash, c.dummySalt)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if err := argon2.Validate(request.Password, user.HashedPassword, user.Salt); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if !user.Active {
		PlainText(w, http.StatusForbidden, "account not verified")
		return
	}

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
}

func publicUser(user repository.User) User {
	return User{
		ID:     user.ID,
		Email:  user.Email,
		Active: user.Active,
		Admin:  user.Admin,
	}
}

// verify activates an account from the token in the verification link.
func (c *controller) verify(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		PlainText(w, http.StatusBadRequest, "missing token")
		return
	}

	tokenHash := hashToken(token)

	vt, err := c.db.GetVerificationToken(r.Context(), tokenHash)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			slog.Error(err.Error())
		}
		PlainText(w, http.StatusBadRequest, "invalid or expired token")
		return
	}

	if vt.ExpiresAt.Before(time.Now()) {
		if err := c.db.DeleteVerificationTokensForUser(r.Context(), vt.UserID); err != nil {
			slog.Error(err.Error())
		}
		PlainText(w, http.StatusBadRequest, "invalid or expired token")
		return
	}

	if err := c.db.ActivateUser(r.Context(), vt.UserID); err != nil {
		slog.Error(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if err := c.db.DeleteVerificationTokensForUser(r.Context(), vt.UserID); err != nil {
		slog.Error(err.Error())
	}

	PlainText(w, http.StatusOK, "Account verified. You can now log in.")
}

func generateVerificationToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// hashToken returns the SHA-256 hash stored for a verification token. Only the
// hash is persisted, so a database leak does not expose usable tokens.
func hashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// verificationBaseURL is the public base URL used to build verification links.
func verificationBaseURL() string {
	if base := os.Getenv("PUBLIC_BASE_URL"); base != "" {
		return strings.TrimRight(base, "/")
	}
	return "http://localhost:8080"
}
