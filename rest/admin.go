package rest

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/a-h/templ"
	"github.com/ccarlfjord/user/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// adminOnly admits only authenticated admins to the admin panel. It wraps
// requireSession, which attaches the caller the check reads.
func (c *controller) adminOnly(next http.HandlerFunc) http.HandlerFunc {
	return c.requireSession(func(w http.ResponseWriter, r *http.Request) {
		caller, ok := callerFrom(r.Context())
		if !ok || !caller.Admin {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next(w, r)
	})
}

// render writes a templ component with the HTML content type. A render failure
// has already sent the header, so it can only be logged.
func render(w http.ResponseWriter, r *http.Request, component templ.Component) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := component.Render(r.Context(), w); err != nil {
		slog.Error("rendering template", "error", err)
	}
}

// adminPageView lists users, optionally filtered by ?q=.
func (c *controller) adminPageView(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))

	users, err := c.listUsers(r.Context(), q)
	if err != nil {
		slog.Error(err.Error())
		http.Error(w, "failed to load users", http.StatusInternalServerError)
		return
	}

	caller, _ := callerFrom(r.Context())
	render(w, r, adminPage(users, q, caller.ID))
}

// adminUserRows serves the table body on its own for the search field.
func (c *controller) adminUserRows(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))

	users, err := c.listUsers(r.Context(), q)
	if err != nil {
		slog.Error(err.Error())
		http.Error(w, "failed to load users", http.StatusInternalServerError)
		return
	}

	caller, _ := callerFrom(r.Context())
	render(w, r, userRows(users, caller.ID))
}

// listUsers returns all accounts, or those whose email matches q.
func (c *controller) listUsers(ctx context.Context, q string) ([]repository.User, error) {
	if q == "" {
		return c.db.GetUsers(ctx)
	}
	return c.db.SearchUsers(ctx, q)
}

// adminToggleActive flips an account's active flag.
func (c *controller) adminToggleActive(w http.ResponseWriter, r *http.Request) {
	c.adminMutateUser(w, r, func(u *repository.User) { u.Active = !u.Active })
}

// adminToggleAdmin flips an account's admin flag.
func (c *controller) adminToggleAdmin(w http.ResponseWriter, r *http.Request) {
	c.adminMutateUser(w, r, func(u *repository.User) { u.Admin = !u.Admin })
}

// adminMutateUser reads the named account, applies mutate, writes the whole
// row back and returns the updated row fragment for htmx to swap in. A caller
// cannot change their own access from the panel.
func (c *controller) adminMutateUser(w http.ResponseWriter, r *http.Request, mutate func(*repository.User)) {
	caller, ok := callerFrom(r.Context())
	if !ok {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	id, ok := adminPathID(w, r)
	if !ok {
		return
	}
	if id == caller.ID {
		http.Error(w, "you cannot change your own access", http.StatusBadRequest)
		return
	}

	current, err := c.db.GetUserById(r.Context(), id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			http.Error(w, "user not found", http.StatusNotFound)
			return
		}
		slog.Error(err.Error())
		http.Error(w, "failed to load user", http.StatusInternalServerError)
		return
	}

	mutate(&current)

	// UpdateUser rewrites the whole row, so the fields the mutation did not
	// touch are carried over from the stored account — including the session
	// epoch, which a role change must not move.
	updated, err := c.db.UpdateUser(r.Context(), repository.UpdateUserParams{
		ID:             current.ID,
		Email:          current.Email,
		HashedPassword: current.HashedPassword,
		Salt:           current.Salt,
		Active:         current.Active,
		Admin:          current.Admin,
		SessionEpoch:   current.SessionEpoch,
	})
	if err != nil {
		slog.Error(err.Error())
		http.Error(w, "failed to update user", http.StatusInternalServerError)
		return
	}

	render(w, r, userRow(updated, caller.ID))
}

// adminDeleteUser deletes the named account and returns an empty body, which
// htmx swaps in to remove the row. A caller cannot delete themselves here.
func (c *controller) adminDeleteUser(w http.ResponseWriter, r *http.Request) {
	caller, ok := callerFrom(r.Context())
	if !ok {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	id, ok := adminPathID(w, r)
	if !ok {
		return
	}
	if id == caller.ID {
		http.Error(w, "you cannot delete your own account here", http.StatusBadRequest)
		return
	}

	deleted, err := c.db.DeleteUser(r.Context(), id)
	if err != nil {
		slog.Error(err.Error())
		http.Error(w, "failed to delete user", http.StatusInternalServerError)
		return
	}
	if deleted == 0 {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// adminPathID parses the {id} path value, answering 400 when it is not a UUID.
func adminPathID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid user id", http.StatusBadRequest)
		return uuid.Nil, false
	}
	return id, true
}

// sessionCookieName is the cookie the admin panel keeps its session in, so a
// browser navigation can authenticate without an Authorization header.
const sessionCookieName = "session"

// setSessionCookie stores the session token in an HttpOnly cookie. SameSite=Lax
// keeps another origin's form or fetch from carrying it, which is the CSRF
// defence for the panel's state-changing POSTs.
func setSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(sessionTTL.Seconds()),
		HttpOnly: true,
		Secure:   strings.HasPrefix(verificationBaseURL(), "https://"),
		SameSite: http.SameSiteLaxMode,
	})
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   strings.HasPrefix(verificationBaseURL(), "https://"),
		SameSite: http.SameSiteLaxMode,
	})
}

// cookieSession returns the session token carried in the panel cookie.
func cookieSession(r *http.Request) (string, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		return "", false
	}
	return cookie.Value, true
}

// adminLoginView renders the sign-in form, optionally with an error message.
func (c *controller) adminLoginView(w http.ResponseWriter, r *http.Request, message string) {
	render(w, r, adminLoginPage(message))
}

// adminLogin authenticates an admin from the sign-in form and starts a cookie
// session. A valid non-admin credential is refused with the same message as a
// bad password, so the form does not confirm who is an admin.
func (c *controller) adminLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		c.adminLoginView(w, r, "Invalid request.")
		return
	}

	user, err := c.authenticate(r.Context(), r.PostFormValue("email"), r.PostFormValue("password"))
	switch {
	case errors.Is(err, errInvalidCredentials):
		c.adminLoginView(w, r, "Invalid email or password.")
		return
	case err != nil:
		slog.Error(err.Error())
		http.Error(w, "failed to sign in", http.StatusInternalServerError)
		return
	}

	if !user.Active || !user.Admin {
		c.adminLoginView(w, r, "Invalid email or password.")
		return
	}

	token, err := c.mintSession(user)
	if err != nil {
		slog.Error(err.Error())
		http.Error(w, "failed to sign in", http.StatusInternalServerError)
		return
	}

	setSessionCookie(w, token)
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

// adminLogout clears the cookie and returns to the sign-in page.
func (c *controller) adminLogout(w http.ResponseWriter, r *http.Request) {
	clearSessionCookie(w)
	http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
}
