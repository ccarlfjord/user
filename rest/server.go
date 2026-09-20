package rest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/ccarlfjord/user/internal/repository"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
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

func New(conn *pgx.Conn, sessionToken []byte) *controller {
	return &controller{
		db:           repository.New(conn),
		sessionToken: sessionToken,
	}
}

func (c *controller) Run() error {
	// Start the server
	r := http.NewServeMux()
	r.HandleFunc("/v1/user", c.userHandler)
	r.HandleFunc("/v1/user/{id}", c.userByIDHandler)
	r.HandleFunc("/v1/login", c.loginHandler)
	r.HandleFunc("/v1/verify", c.verifyHandler)
	r.HandleFunc("/signup", c.signupPage)

	return http.ListenAndServe(":8080", r)
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

func (c *controller) userHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
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

		claims := new(jwt.RegisteredClaims)
		_, err := jwt.ParseWithClaims(raw, claims, c.sessionKey,
			jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
			jwt.WithExpirationRequired(),
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
