package rest

import (
	"net/http"

	"github.com/ccarlfjord/user/internal/repository"
	"github.com/jackc/pgx/v5"
)

func New(conn *pgx.Conn, sessionToken []byte) http.Handler {
	db := repository.New(conn)
	mux := http.NewServeMux()
	setupRoutes(mux, db, sessionToken)
	return mux
}

type opts struct {
	db           *repository.Queries
	sessionToken []byte
}

func setupRoutes(mux *http.ServeMux, db *repository.Queries, sessionToken []byte) {
	mux.HandleFunc("/v1/signup", 
	mux.Handle("/v1/login", NewLoginHandler(db, sessionToken))
}

// func (c *controller) userByIDHandler(w http.ResponseWriter, r *http.Request) {
// 	switch r.Method {
// 	case http.MethodGet:
// 		c.getUserByID(w, r)
// 	case http.MethodPost:
// 		c.updateUserByID(w, r)
// 	default:
// 		w.WriteHeader(http.StatusMethodNotAllowed)
// 		w.Write([]byte("Method not allowed"))
// 	}
// }

func AuthHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := validateContentTypeJSON(w, r); err != nil {
			return
		}
		if err := isAuthenticated(w, r); err != nil {
			return
		}

		next.ServeHTTP(w, r)
	})
}

// isAuthenticated checks returns an error if the request does not contain a valid Bearer token for the user
func isAuthenticated(w http.ResponseWriter, r *http.Request) error {
	return nil
}
