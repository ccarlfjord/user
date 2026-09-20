package rest

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/ccarlfjord/argon2"
	"github.com/ccarlfjord/user/internal/repository"
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
}

type controller struct {
	db           userStore
	sessionToken []byte
	dummyHash    []byte
	dummySalt    []byte
}

type User struct {
	ID     uuid.UUID `json:"id"`
	Email  string    `json:"email"`
	Active bool      `json:"active"`
	Admin  bool      `json:"admin"`
}

func New(conn *pgx.Conn, sessionToken []byte) *controller {
	db := repository.New(conn)

	// A fixed dummy hash lets login run a real (slow) validation even when the
	// account does not exist, so response timing does not reveal account
	// existence.
	dummySalt := argon2.GenerateSalt()

	return &controller{
		db:           db,
		sessionToken: sessionToken,
		dummyHash:    argon2.HashPassword("", dummySalt),
		dummySalt:    dummySalt,
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
		c.deleteUser(w, r)
	case http.MethodPatch:
		c.updateUser(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Write([]byte("Method not allowed"))
	}
}

func (c *controller) userByIDHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		c.getUserByID(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Write([]byte("Method not allowed"))
	}
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
