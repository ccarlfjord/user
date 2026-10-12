package rest

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/ccarlfjord/argon2"
	"github.com/ccarlfjord/user/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// adminRoute returns the wrapped handler for an admin panel route path,
// exactly as Run registers it, so the session and admin gates are exercised.
func adminRoute(c *controller, path string) http.HandlerFunc {
	switch {
	case path == "/admin":
		return c.adminOnly(c.adminPageHandler)
	case path == "/admin/users":
		return c.adminOnly(c.adminUserRowsHandler)
	case strings.HasSuffix(path, "/toggle-active"):
		return c.adminOnly(c.adminToggleActiveHandler)
	case strings.HasSuffix(path, "/toggle-admin"):
		return c.adminOnly(c.adminToggleAdminHandler)
	case strings.HasSuffix(path, "/delete"):
		return c.adminOnly(c.adminDeleteUserHandler)
	case path == "/admin/signing-keys/rotate":
		return c.adminOnly(c.adminRotateSigningKeyHandler)
	default:
		panic("unrouted admin target " + path)
	}
}

// pathIDFromURL returns the {id} segment of /admin/users/{id}/{action}, or "".
func pathIDFromURL(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 4 && parts[0] == "admin" && parts[1] == "users" {
		return parts[2]
	}
	return ""
}

// adminRequest drives an admin route with an authenticated session for caller.
func adminRequest(t *testing.T, c *controller, caller repository.User, method, target string) *httptest.ResponseRecorder {
	t.Helper()

	req := authRequest(t, method, target, caller)
	if id := pathIDFromURL(req.URL.Path); id != "" {
		req.SetPathValue("id", id)
	}
	rec := httptest.NewRecorder()
	adminRoute(c, req.URL.Path)(rec, req)
	return rec
}

// A browser cannot set an Authorization header, so the panel authenticates from
// its session cookie instead.
func TestCookieSessionAuthenticatesAdminPanel(t *testing.T) {
	admin := activeUser(true)
	c := newTestController(fakeStore{
		getUserById: func(_ context.Context, id uuid.UUID) (repository.User, error) {
			if id != admin.ID {
				return repository.User{}, pgx.ErrNoRows
			}
			return admin, nil
		},
		getUsers: func(context.Context) ([]repository.User, error) {
			return []repository.User{admin}, nil
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.AddCookie(&http.Cookie{
		Name:  sessionCookieName,
		Value: signClaims(t, testSigningKey, mintedClaims(admin.ID.String(), admin.SessionEpoch)),
	})
	rec := httptest.NewRecorder()
	adminRoute(c, "/admin")(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
}

func TestAdminLoginSetsSessionCookie(t *testing.T) {
	salt := []byte("0123456789abcdef")
	admin := activeUser(true)
	admin.HashedPassword = argon2.HashPassword("rightpassword", salt)
	admin.Salt = salt

	c := newTestController(fakeStore{
		getUserByEmail: func(context.Context, string) (repository.User, error) {
			return admin, nil
		},
	})

	form := url.Values{"email": {admin.Email}, "password": {"rightpassword"}}
	req := httptest.NewRequest(http.MethodPost, "/admin/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	c.adminLoginHandler(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303: %s", rec.Code, rec.Body.String())
	}

	var session *http.Cookie
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == sessionCookieName {
			session = cookie
		}
	}
	if session == nil || session.Value == "" {
		t.Fatal("no session cookie was set")
	}
	if !session.HttpOnly {
		t.Fatal("session cookie is not HttpOnly")
	}
	if session.SameSite != http.SameSiteLaxMode {
		t.Fatalf("SameSite = %v, want Lax", session.SameSite)
	}
}

func TestAdminLoginRefusesNonAdminAndBadPassword(t *testing.T) {
	salt := []byte("0123456789abcdef")
	nonAdmin := activeUser(false)
	nonAdmin.HashedPassword = argon2.HashPassword("rightpassword", salt)
	nonAdmin.Salt = salt

	c := newTestController(fakeStore{
		getUserByEmail: func(context.Context, string) (repository.User, error) {
			return nonAdmin, nil
		},
	})

	tests := []struct {
		name     string
		password string
	}{
		{"valid non-admin credential", "rightpassword"},
		{"wrong password", "wrongpassword"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			form := url.Values{"email": {nonAdmin.Email}, "password": {tt.password}}
			req := httptest.NewRequest(http.MethodPost, "/admin/login", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := httptest.NewRecorder()
			c.adminLoginHandler(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rec.Code)
			}
			if !strings.Contains(rec.Body.String(), "Invalid email or password") {
				t.Fatalf("body = %q, want the generic refusal", rec.Body.String())
			}
			for _, cookie := range rec.Result().Cookies() {
				if cookie.Name == sessionCookieName && cookie.Value != "" {
					t.Fatal("a session cookie was set for a refused sign-in")
				}
			}
		})
	}
}

func TestAdminPageListsUsersForAdminOnly(t *testing.T) {
	admin := activeUser(true)
	nonAdmin := activeUser(false)
	other := repository.User{ID: uuid.New(), Email: "other@example.com", Active: true}

	c := newTestController(fakeStore{
		getUserById: func(_ context.Context, id uuid.UUID) (repository.User, error) {
			for _, u := range []repository.User{admin, nonAdmin} {
				if u.ID == id {
					return u, nil
				}
			}
			return repository.User{}, pgx.ErrNoRows
		},
		getUsers: func(context.Context) ([]repository.User, error) {
			return []repository.User{admin, other}, nil
		},
	})

	rec := adminRequest(t, c, admin, http.MethodGet, "/admin")
	if rec.Code != http.StatusOK {
		t.Fatalf("admin status = %d, want 200", rec.Code)
	}
	for _, want := range []string{admin.Email, other.Email, "you"} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("admin page missing %q: %s", want, rec.Body.String())
		}
	}

	// A non-admin gets 403 and no data, even though the session is valid.
	rec = adminRequest(t, c, nonAdmin, http.MethodGet, "/admin")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin status = %d, want 403", rec.Code)
	}
	if strings.Contains(rec.Body.String(), other.Email) {
		t.Fatal("non-admin response leaked account data")
	}
}

func TestAdminSearchUsesSearchQuery(t *testing.T) {
	admin := activeUser(true)
	searched := ""
	store := fakeStore{
		getUserById: func(_ context.Context, id uuid.UUID) (repository.User, error) {
			if id != admin.ID {
				return repository.User{}, pgx.ErrNoRows
			}
			return admin, nil
		},
		getUsers: func(context.Context) ([]repository.User, error) {
			t.Fatal("a non-empty query must not list every user")
			return nil, nil
		},
		searchUsers: func(_ context.Context, query string) ([]repository.User, error) {
			searched = query
			return []repository.User{{ID: uuid.New(), Email: "found@example.com", Active: true}}, nil
		},
	}
	c := newTestController(store)

	rec := adminRequest(t, c, admin, http.MethodGet, "/admin/users?q=found")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if searched != "found" {
		t.Fatalf("search query = %q, want %q", searched, "found")
	}
	if !strings.Contains(rec.Body.String(), "found@example.com") {
		t.Fatalf("fragment missing the match: %s", rec.Body.String())
	}

	// An empty query lists every user through GetUsers.
	listed := false
	store.getUsers = func(context.Context) ([]repository.User, error) {
		listed = true
		return nil, nil
	}
	rec = adminRequest(t, newTestController(store), admin, http.MethodGet, "/admin/users")
	if rec.Code != http.StatusOK || !listed {
		t.Fatalf("empty query: status = %d, listed = %v, want 200 and true", rec.Code, listed)
	}
}

// A toggle reads the row, flips one field and writes the rest of the row back
// untouched — including the session epoch, which a role change must not move —
// and answers with the updated row so htmx can swap it in.
func TestAdminToggleActiveFlipsFlag(t *testing.T) {
	admin := activeUser(true)
	target := repository.User{
		ID:             uuid.New(),
		Email:          "other@example.com",
		HashedPassword: []byte("secret-hash"),
		Salt:           []byte("secret-salt"),
		Active:         true,
		Admin:          false,
		SessionEpoch:   3,
	}

	var stored repository.UpdateUserParams
	store := fakeStore{
		getUserById: func(_ context.Context, id uuid.UUID) (repository.User, error) {
			if id != target.ID {
				return admin, nil
			}
			return target, nil
		},
		updateUser: func(_ context.Context, arg repository.UpdateUserParams) (repository.User, error) {
			stored = arg
			return repository.User{
				ID: arg.ID, Email: arg.Email, HashedPassword: arg.HashedPassword, Salt: arg.Salt,
				Active: arg.Active, Admin: arg.Admin, SessionEpoch: arg.SessionEpoch,
			}, nil
		},
	}
	c := newTestController(store)

	rec := adminRequest(t, c, admin, http.MethodPost, "/admin/users/"+target.ID.String()+"/toggle-active")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if stored.Active {
		t.Fatalf("active = true, want the flag flipped to false: %+v", stored)
	}
	if stored.Email != target.Email || !bytes.Equal(stored.HashedPassword, target.HashedPassword) ||
		!bytes.Equal(stored.Salt, target.Salt) || stored.Admin != target.Admin {
		t.Fatalf("toggle disturbed untouched fields: %+v", stored)
	}
	if stored.SessionEpoch != target.SessionEpoch {
		t.Fatalf("session_epoch = %d, want the stored %d", stored.SessionEpoch, target.SessionEpoch)
	}
	if !strings.Contains(rec.Body.String(), "user-"+target.ID.String()) {
		t.Fatalf("response is not the updated row: %s", rec.Body.String())
	}
}

func TestAdminToggleAdminPromotes(t *testing.T) {
	admin := activeUser(true)
	target := repository.User{ID: uuid.New(), Email: "other@example.com", Active: true, Admin: false}

	var stored repository.UpdateUserParams
	store := fakeStore{
		getUserById: func(_ context.Context, id uuid.UUID) (repository.User, error) {
			if id != target.ID {
				return admin, nil
			}
			return target, nil
		},
		updateUser: func(_ context.Context, arg repository.UpdateUserParams) (repository.User, error) {
			stored = arg
			return repository.User{ID: arg.ID, Email: arg.Email, Active: arg.Active, Admin: arg.Admin}, nil
		},
	}
	c := newTestController(store)

	rec := adminRequest(t, c, admin, http.MethodPost, "/admin/users/"+target.ID.String()+"/toggle-admin")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if !stored.Admin {
		t.Fatal("admin flag was not set")
	}
}

func TestAdminDeleteRemovesUser(t *testing.T) {
	admin := activeUser(true)
	target := uuid.New()
	deleted := uuid.Nil
	c := newTestController(fakeStore{
		getUserById: func(_ context.Context, id uuid.UUID) (repository.User, error) {
			if id != admin.ID {
				return repository.User{}, pgx.ErrNoRows
			}
			return admin, nil
		},
		deleteUser: func(_ context.Context, id uuid.UUID) (int64, error) {
			deleted = id
			return 1, nil
		},
	})

	rec := adminRequest(t, c, admin, http.MethodPost, "/admin/users/"+target.String()+"/delete")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if deleted != target {
		t.Fatalf("deleted %s, want %s", deleted, target)
	}
	// An empty body is what removes the row: htmx swaps it over the old one.
	if rec.Body.Len() != 0 {
		t.Fatalf("delete answered a body: %q", rec.Body.String())
	}
}

// The panel never lets an admin change their own access, so a sole admin
// cannot lock themselves out of it.
func TestAdminActionsRefuseSelf(t *testing.T) {
	admin := activeUser(true)
	store := fakeStore{
		getUserById: func(context.Context, uuid.UUID) (repository.User, error) {
			return admin, nil
		},
		updateUser: func(context.Context, repository.UpdateUserParams) (repository.User, error) {
			t.Fatal("a self mutation must not be written")
			return repository.User{}, nil
		},
		deleteUser: func(context.Context, uuid.UUID) (int64, error) {
			t.Fatal("a self mutation must not be deleted")
			return 0, nil
		},
	}
	c := newTestController(store)

	for _, action := range []string{"toggle-active", "toggle-admin", "delete"} {
		t.Run(action, func(t *testing.T) {
			rec := adminRequest(t, c, admin, http.MethodPost, "/admin/users/"+admin.ID.String()+"/"+action)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", rec.Code)
			}
		})
	}

	// And the row rendered for the caller carries no action buttons.
	page := newTestController(fakeStore{
		getUserById: func(_ context.Context, id uuid.UUID) (repository.User, error) {
			if id != admin.ID {
				return repository.User{}, pgx.ErrNoRows
			}
			return admin, nil
		},
		getUsers: func(context.Context) ([]repository.User, error) {
			return []repository.User{admin}, nil
		},
	})
	rec := adminRequest(t, page, admin, http.MethodGet, "/admin")
	if strings.Contains(rec.Body.String(), "toggle-admin") {
		t.Fatal("own row rendered action buttons")
	}
}

func TestAdminActionsHandleMissingAndBrokenIDs(t *testing.T) {
	admin := activeUser(true)
	missing := uuid.New()
	store := fakeStore{
		getUserById: func(_ context.Context, id uuid.UUID) (repository.User, error) {
			if id == admin.ID {
				return admin, nil
			}
			return repository.User{}, pgx.ErrNoRows
		},
		deleteUser: func(context.Context, uuid.UUID) (int64, error) {
			return 0, nil
		},
	}
	c := newTestController(store)

	// A row that is gone answers 404 through the mutation; a delete of a row
	// that is already gone answers 404 from the affected-rows count.
	rec := adminRequest(t, c, admin, http.MethodPost, "/admin/users/"+missing.String()+"/toggle-active")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("toggle-active status = %d, want 404", rec.Code)
	}
	rec = adminRequest(t, c, admin, http.MethodPost, "/admin/users/"+missing.String()+"/delete")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("delete status = %d, want 404", rec.Code)
	}

	// A path value that is not a UUID is refused before any lookup.
	rec = adminRequest(t, c, admin, http.MethodPost, "/admin/users/not-a-uuid/delete")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad id status = %d, want 400", rec.Code)
	}
}

func TestAdminRoutesRequireSession(t *testing.T) {
	c := newTestController(fakeStore{})

	targets := []string{
		"/admin",
		"/admin/users",
		"/admin/users/x/toggle-active",
		"/admin/users/x/toggle-admin",
		"/admin/users/x/delete",
	}

	for _, target := range targets {
		t.Run(target, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, target, nil)
			rec := httptest.NewRecorder()
			adminRoute(c, target)(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", rec.Code)
			}
		})
	}
}
