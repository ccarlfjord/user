package rest

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/ccarlfjord/user-service/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type controller struct {
	db           *repository.Queries
	sessionToken []byte
}

type User struct {
	ID       uuid.UUID `json:"id"`
	Email    string    `json:"email"`
	Username string    `json:"username"`
	Active   bool      `json:"active"`
	Admin    bool      `json:"admin"`
}

func New(conn *pgx.Conn, sessionToken []byte) *controller {
	db := repository.New(conn)
	return &controller{
		db:           db,
		sessionToken: sessionToken,
	}
}

func (c *controller) Run() error {
	// Start the server
	r := http.NewServeMux()
	r.HandleFunc("/v1/user", c.userHandler)
	r.HandleFunc("/v1/user/{id}", c.userByIDHandler)
	r.HandleFunc("/v1/login", c.loginHandler)

	return http.ListenAndServe(":8080", r)
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

func validateContentTypeJSON(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Type") != "application/json" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Content-Type must be application/json"))
	}
}

func JSON(w http.ResponseWriter, status int, body interface{}) {
	json, err := json.Marshal(body)
	if err != nil {
		slog.Error(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(json)
}

func PlainText(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(status)
	w.Write([]byte(body))
}
