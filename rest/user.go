package rest

import (
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"net/http"

	"github.com/ccarlfjord/user/argon2"
	"github.com/ccarlfjord/user/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type User struct {
	ID       uuid.UUID `json:"id"`
	Email    string    `json:"email"`
	Username string    `json:"username"`
	Active   bool      `json:"active"`
	Admin    bool      `json:"admin"`
}

// getUser returns a user from JSON payload
func (h *userHandler) getUser(w http.ResponseWriter, r *http.Request) {
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
	u, err := h.db.GetUserByEmail(r.Context(), request.Email)
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
func (h *userHandler) getUserByID(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	uuid, err := uuid.Parse(id)
	if err != nil {
		slog.Error(err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	user, err := h.db.GetUserById(r.Context(), uuid)
	if err != nil {
		slog.Error(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	u := User{
		ID:       user.ID,
		Email:    user.Email,
		Username: user.Username,
		Active:   user.Active,
		Admin:    user.Admin,
	}

	JSON(w, http.StatusOK, u)
}

type NewUserRequest struct {
	Email    string `json:"email"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// newUser creates a new user
func (u *userHandler) newUser(w http.ResponseWriter, r *http.Request) {
	// Validate content type of request is application/json
	validateContentTypeJSON(w, r)

	// Read JSON from request body
	var req NewUserRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		slog.Error(err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	salt := argon2.GenerateSalt()

	// If user exists, return 200 and user
	exists, err := u.db.GetUserByEmail(r.Context(), req.Email)
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

	user, err := u.db.CreateUser(r.Context(), userParams)
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
func (u *userHandler) deleteUser(w http.ResponseWriter, r *http.Request) {
}

// storeUser updates user in database with data from request
func (h *userHandler) storeUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	uuid, err := uuid.Parse(id)
	if err != nil {
		slog.Error(err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	user, err := h.db.GetUserById(r.Context(), uuid)
	fmt.Println(user)
	if err != nil {
		slog.Error(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	userRequest := json.NewDecoder(r.Body).Decode(&User{})
	slog.Info(fmt.Sprintf("%v", userRequest))

	_, err = h.db.StoreUser(r.Context(), repository.StoreUserParams{
		ID:             user.ID,
		Username:       user.Username,
		Email:          user.Email,
		HashedPassword: user.HashedPassword,
		Salt:           user.Salt,
		Active:         user.Active,
		Admin:          user.Admin,
	})
	if err != nil {
		slog.Error(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
	}
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}
type LoginResponse struct {
	Session string `json:"session"`
}

type userHandler struct {
	mux          http.Handler
	db           *repository.Queries
	sessionToken []byte
}

func (h *userHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

func NewUserHandler(db *repository.Queries, sessionToken []byte) *userHandler {
	mux := http.NewServeMux()
	mux.HandleFunc("/ping", PingHandler)
	return &userHandler{
		mux:          mux,
		db:           db,
		sessionToken: sessionToken,
	}
}

func PingHandler(w http.ResponseWriter, r *http.Request) {
	log.Println(r.URL)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("pong\n"))
}
