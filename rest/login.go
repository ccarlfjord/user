package rest

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/ccarlfjord/user/argon2"
	"github.com/ccarlfjord/user/internal/repository"
	"github.com/golang-jwt/jwt/v5"
)

type loginHandler struct {
	db           *repository.Queries
	sessionToken []byte
}

func NewLoginHandler(db *repository.Queries, sessionToken []byte) *loginHandler {
	return &loginHandler{
		db:           db,
		sessionToken: sessionToken,
	}
}

func (h *loginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		h.login(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Write([]byte("Method not allowed"))
	}
}

func (h *loginHandler) login(w http.ResponseWriter, r *http.Request) {
	if err := validateContentTypeJSON(w, r); err != nil {
		return
	}
	var request LoginRequest

	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	user, err := h.db.GetUserByEmail(r.Context(), request.Email)
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

		sessionToken, err := token.SignedString(h.sessionToken)
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

	w.WriteHeader(http.StatusForbidden)
}
