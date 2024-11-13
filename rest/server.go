package rest

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/ccarlfjord/user-service/argon2"
	"github.com/ccarlfjord/user-service/repository"
	"github.com/google/uuid"
)

type controller struct {
	db *repository.Queries
}

type User struct {
	ID       uuid.UUID `json:"id"`
	Email    string    `json:"email"`
	Username string    `json:"username"`
	Active   bool      `json:"active"`
	Admin    bool      `json:"admin"`
}

type CreateUserRequest struct {
	Email    string `json:"email"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func New(db *repository.Queries) *controller {
	return &controller{db: db}
}

func (c *controller) Run() error {
	// Start the server
	// Create Gin router
	r := http.NewServeMux()
	r.HandleFunc("/v1/user", c.userHandler)
	r.HandleFunc("/v1/user/{id}", c.userHandlerByID)

	return http.ListenAndServe(":8080", r)
}

func (c *controller) userHandlerByID(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		c.getUserByID(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Write([]byte("Method not allowed"))
	}
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

func (c *controller) createUser(w http.ResponseWriter, r *http.Request) {
	// Check if content type is application/json
	isContentTypeJSON(w, r)

	// Read values from json
	var req CreateUserRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		slog.Error(err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	salt := argon2.GenerateSalt()
	// Check if user exists
	_, err = c.db.GetUserByEmail(r.Context(), req.Email)
	if err == nil {
		w.WriteHeader(http.StatusConflict)
		w.Write([]byte("User already exists"))
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
	u := User{
		ID:       user.ID,
		Email:    user.Email,
		Username: user.Username,
		Active:   user.Active.Bool,
		Admin:    user.Admin.Bool,
	}
	json, err := json.Marshal(u)
	if err != nil {
		slog.Error(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Write(json)
}

func (c *controller) deleteUser(w http.ResponseWriter, r *http.Request) {
}

func (c *controller) updateUser(w http.ResponseWriter, r *http.Request) {
}

func isContentTypeJSON(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Type") != "application/json" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Content-Type must be application/json"))
	}
}
