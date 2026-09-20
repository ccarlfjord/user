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

// getUserByID returns a user by ID. The caller may read their own record;
// reading anyone else's requires admin.
func (c *controller) getUserByID(w http.ResponseWriter, r *http.Request) {
	caller, ok := callerFrom(r.Context())
	if !ok {
		// Only reachable if this handler is wired without requireSession.
		unauthorized(w)
		return
	}

	id := r.PathValue("id")
	userID, err := uuid.Parse(id)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	if !mayAccessUser(caller, userID) {
		// Checked before the lookup, so a denial does not confirm that the
		// target exists.
		w.WriteHeader(http.StatusForbidden)
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

// createUser creates a new user. Both the response and the work performed are
// intentionally identical whether the email was free or already registered, so
// neither the body nor the timing reveals which addresses are registered.
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

	// Derive before looking the address up. A signup attempt must pay the same
	// argon2id cost whatever the lookup returns, or the response time reports
	// whether the address is already registered. The salt and hash are only
	// stored when the address turns out to be free.
	salt := argon2.GenerateSalt()
	hashedPassword := argon2.HashPassword(req.Password, salt)

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

	userParams := repository.CreateUserParams{
		ID:             uuid.New(),
		Email:          req.Email,
		HashedPassword: hashedPassword,
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

// decoySalt and decoyHash stand in when there is no stored credential to check
// against. Every login attempt must pay exactly one argon2id derivation, or the
// response time reveals whether an email is registered. The digest is a fixed
// random value with no known preimage, so it cannot be produced by supplying a
// password; `stored` in login keeps it from admitting anyone even if it were.
var (
	decoySalt = []byte{0x24, 0x5d, 0x07, 0x6e, 0xfd, 0x31, 0x11, 0x87, 0x97, 0x95, 0x48, 0x12, 0x7d, 0x0e, 0x23, 0x29}
	decoyHash = []byte{0x55, 0x6a, 0xb6, 0x0f, 0xb0, 0x7d, 0xb6, 0x97, 0xc2, 0x97, 0x34, 0x9c, 0x55, 0xa4, 0x1c, 0xd4, 0xc7, 0x64, 0x13, 0x3a, 0xa0, 0xd7, 0xc3, 0xe7, 0x65, 0x9c, 0x2d, 0xd4, 0xd2, 0xf5, 0xc9, 0xd4}
)

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
		// Unknown account: user stays zero, so the decoy is used below and the
		// response is identical to a wrong password on a registered account.
	}

	// Select the credential to derive against, then run that derivation once,
	// whatever the outcome. The decoy covers an unknown account and an account
	// with no stored credential (`hashed_password`/`salt` are nullable).
	stored := err == nil && user.HashedPassword != nil && user.Salt != nil
	hash, salt := decoyHash, decoySalt
	if stored {
		hash, salt = user.HashedPassword, user.Salt
	}

	if argon2.Validate(request.Password, hash, salt) != nil || !stored {
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
