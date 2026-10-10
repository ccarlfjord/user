package rest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/ccarlfjord/user/internal/repository"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// userStore is the subset of the repository used by the handlers. It is an
// interface so handlers can be tested without a live database.
type userStore interface {
	GetUserByEmail(ctx context.Context, email string) (repository.User, error)
	GetUserById(ctx context.Context, id uuid.UUID) (repository.User, error)
	CreateUser(ctx context.Context, arg repository.CreateUserParams) (repository.User, error)
	CreateVerificationToken(ctx context.Context, arg repository.CreateVerificationTokenParams) error
	GetVerificationToken(ctx context.Context, tokenHash []byte) (repository.VerificationToken, error)
	DeleteVerificationTokensForUser(ctx context.Context, userID uuid.UUID) error
	ActivateUser(ctx context.Context, id uuid.UUID) error
	UpdateUser(ctx context.Context, arg repository.UpdateUserParams) (repository.User, error)
	DeleteUser(ctx context.Context, id uuid.UUID) (int64, error)
	CreateRefreshToken(ctx context.Context, arg repository.CreateRefreshTokenParams) error
	ConsumeRefreshToken(ctx context.Context, tokenHash []byte) (repository.RefreshToken, error)
	DeleteExpiredRefreshTokens(ctx context.Context) (int64, error)
	DeleteExpiredVerificationTokens(ctx context.Context) (int64, error)
	CreatePasswordResetToken(ctx context.Context, arg repository.CreatePasswordResetTokenParams) error
	ConsumePasswordResetToken(ctx context.Context, tokenHash []byte) (repository.PasswordResetToken, error)
	DeletePasswordResetTokensForUser(ctx context.Context, userID uuid.UUID) error
	DeleteExpiredPasswordResetTokens(ctx context.Context) (int64, error)
}

type controller struct {
	db           userStore
	sessionToken []byte
}

type User struct {
	ID     uuid.UUID `json:"id"`
	Email  string    `json:"email"`
	Active bool      `json:"active"`
	Admin  bool      `json:"admin"`
}

func New(pool *pgxpool.Pool, sessionToken []byte) *controller {
	return &controller{
		db:           repository.New(pool),
		sessionToken: sessionToken,
	}
}

func (c *controller) Run() error {
	// Start the server
	r := http.NewServeMux()
	r.HandleFunc("/v1/user", c.userHandler)
	r.HandleFunc("/v1/user/{id}", c.userByIDHandler)
	r.HandleFunc("/v1/login", c.loginHandler)
	r.HandleFunc("/v1/refresh", c.refreshHandler)
	r.HandleFunc("/v1/verify", c.verifyHandler)
	r.HandleFunc("/v1/password/forgot", c.forgotPasswordHandler)
	r.HandleFunc("/v1/password/reset", c.resetPasswordHandler)
	r.HandleFunc("/signup", c.signupPage)

	go c.purgeExpiredTokens()

	return http.ListenAndServe(":8080", r)
}

// purgeExpiredInterval is how often expired refresh and verification token
// rows are deleted. Tokens are normally consumed on use or deleted with their
// user; the purge only reclaims rows whose owner never came back.
const purgeExpiredInterval = 24 * time.Hour

// purgeExpiredTokens deletes expired refresh and verification tokens on a
// ticker so the tables do not grow without bound. It never stops the server:
// a failed purge retries on the next tick.
func (c *controller) purgeExpiredTokens() {
	run := func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if n, err := c.db.DeleteExpiredRefreshTokens(ctx); err != nil {
			slog.Error("deleting expired refresh tokens", "error", err)
		} else if n > 0 {
			slog.Debug("deleted expired refresh tokens", "count", n)
		}
		if n, err := c.db.DeleteExpiredVerificationTokens(ctx); err != nil {
			slog.Error("deleting expired verification tokens", "error", err)
		} else if n > 0 {
			slog.Debug("deleted expired verification tokens", "count", n)
		}
		if n, err := c.db.DeleteExpiredPasswordResetTokens(ctx); err != nil {
			slog.Error("deleting expired password reset tokens", "error", err)
		} else if n > 0 {
			slog.Debug("deleted expired password reset tokens", "count", n)
		}
	}

	run()
	for range time.NewTicker(purgeExpiredInterval).C {
		run()
	}
}

func (c *controller) signupPage(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "static/signup.html")
}

func (c *controller) verifyHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		c.verify(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Write([]byte("Method not allowed"))
	}
}

func (c *controller) loginHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		c.login(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Write([]byte("Method not allowed"))
	}
}

func (c *controller) refreshHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		c.refresh(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Write([]byte("Method not allowed"))
	}
}

func (c *controller) forgotPasswordHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		c.forgotPassword(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Write([]byte("Method not allowed"))
	}
}

func (c *controller) resetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		c.resetPassword(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Write([]byte("Method not allowed"))
	}
}

func (c *controller) userHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		c.requireSession(c.getUser)(w, r)
	case http.MethodPost:
		c.createUser(w, r)
	case http.MethodDelete:
		c.requireSession(c.deleteUser)(w, r)
	case http.MethodPatch:
		c.requireSession(c.updateUser)(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Write([]byte("Method not allowed"))
	}
}

func (c *controller) userByIDHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		c.requireSession(c.getUserByID)(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Write([]byte("Method not allowed"))
	}
}

// requireSession rejects requests without a valid session token in the
// Authorization header, then resolves the token's subject to a live, active
// account and attaches it to the request context. Authorization — who may act
// on which user — is left to the wrapped handler, which reads the caller with
// callerFrom.
func (c *controller) requireSession(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, ok := bearerToken(r.Header.Get("Authorization"))
		if !ok {
			unauthorized(w)
			return
		}

		claims := new(sessionClaims)
		_, err := jwt.ParseWithClaims(raw, claims, c.sessionKey,
			jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
			jwt.WithExpirationRequired(),
			jwt.WithIssuer(sessionIssuer),
			jwt.WithAudience(sessionAudience),
			jwt.WithIssuedAt(),
		)
		if err != nil {
			slog.Debug("rejected session token", "error", err)
			unauthorized(w)
			return
		}

		userID, err := uuid.Parse(claims.Subject)
		if err != nil {
			slog.Debug("session subject is not a user id", "subject", claims.Subject)
			unauthorized(w)
			return
		}

		// Resolve the subject on every request: a deleted or deactivated
		// account must not keep using a token that has not expired yet, and
		// handlers need the caller's admin flag to authorize the target.
		caller, err := c.db.GetUserById(r.Context(), userID)
		if err != nil {
			if !errors.Is(err, pgx.ErrNoRows) {
				slog.Error(err.Error())
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			unauthorized(w)
			return
		}
		if !caller.Active {
			unauthorized(w)
			return
		}

		// A password change bumps the account's session epoch, retiring every
		// session minted before it: without this a token stolen before the
		// change would stay usable until it expired. Requiring the claim keeps
		// a token from omitting it and comparing equal to a stale generation.
		if claims.SessionEpoch == nil || *claims.SessionEpoch != caller.SessionEpoch {
			slog.Debug("rejected session from a retired session epoch",
				"subject", claims.Subject, "epoch", claims.SessionEpoch)
			unauthorized(w)
			return
		}

		next(w, r.WithContext(context.WithValue(r.Context(), callerKey{}, caller)))
	}
}

// callerKey is the request context key under which requireSession stores the
// authenticated user.
type callerKey struct{}

// callerFrom returns the user attached to the request by requireSession.
func callerFrom(ctx context.Context) (repository.User, bool) {
	caller, ok := ctx.Value(callerKey{}).(repository.User)
	return caller, ok
}

// mayAccessUser reports whether caller may read or modify the account
// identified by target: admins may act on anyone, everyone else only on
// themselves.
func mayAccessUser(caller repository.User, target uuid.UUID) bool {
	return caller.Admin || caller.ID == target
}

// sessionKey returns the HMAC secret only for HS256 tokens. The signing method
// is pinned so a token cannot be verified with an algorithm the caller chose
// (alg confusion / "none").
func (c *controller) sessionKey(t *jwt.Token) (any, error) {
	if m, ok := t.Method.(*jwt.SigningMethodHMAC); !ok || m.Alg() != jwt.SigningMethodHS256.Alg() {
		return nil, fmt.Errorf("unexpected signing method %q", t.Method.Alg())
	}
	return c.sessionToken, nil
}

// bearerToken extracts the token from an Authorization header value.
func bearerToken(header string) (string, bool) {
	scheme, token, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" {
		return "", false
	}
	return token, true
}

func unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	w.WriteHeader(http.StatusUnauthorized)
}

func validateContentTypeJSON(w http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get("Content-Type") != "application/json" {
		PlainText(w, http.StatusBadRequest, "Content-Type must be application/json")
		return false
	}
	return true
}

func JSON(w http.ResponseWriter, status int, body any) {
	b, err := json.Marshal(body)
	if err != nil {
		slog.Error(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

func PlainText(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(status)
	w.Write([]byte(body))
}
