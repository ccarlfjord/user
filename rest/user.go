package rest

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/ccarlfjord/argon2"
	"github.com/ccarlfjord/user/internal/repository"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// sessionIssuer and sessionAudience identify this service in the sessions it
// mints. A token minted for another audience is rejected here even if that
// service shares the signing key, which is a real risk while the key lives in
// a database table any deployment can read.
const (
	sessionIssuer   = "ccarlfjord/user"
	sessionAudience = "user-api"
)

// sessionTTL is how long a minted session stays usable on its own. It is
// deliberately short: the refresh token is what carries a client across a
// longer absence, and every refresh re-checks the account's state.
const sessionTTL = 1 * time.Hour

// refreshTokenTTL is how long a refresh token stays usable. It is much longer
// than a session so a client that was away for hours or days can still come
// back, and it is the only thing that outlives the session.
const refreshTokenTTL = 30 * 24 * time.Hour

// passwordResetTTL is how long a password reset link stays usable. It is kept
// short because the link is a bearer credential for the account.
const passwordResetTTL = 1 * time.Hour

// sessionClaims is what a session token carries. The registered claims say who
// it is for and when it dies; SessionEpoch ties it to the account's current
// session generation, so a password change retires every session minted before
// it. The epoch is a pointer so a token that omits the claim is refused rather
// than read as generation zero.
type sessionClaims struct {
	jwt.RegisteredClaims
	SessionEpoch *int32 `json:"epoch"`
}

// getUser returns the caller's own record, or the account named by the email
// query parameter. Naming another account requires admin; a non-admin's own
// address is resolved from the session, so an address that is not theirs is
// refused before any lookup and the route cannot be used to test whether an
// address is registered.
func (c *controller) getUser(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	if email == "" {
		// No account named: the caller's own record, straight from the session.
		caller, ok := callerFrom(r.Context())
		if !ok {
			// Only reachable if this handler is wired without requireSession.
			unauthorized(w)
			return
		}

		JSON(w, http.StatusOK, publicUser(caller))
		return
	}

	_, target, ok := c.authorizeTarget(w, r, "", email)
	if !ok {
		return
	}

	user, err := c.db.GetUserById(r.Context(), target)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			slog.Error(err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		return
	}

	JSON(w, http.StatusOK, publicUser(user))
}

// getUserByID returns a user by ID. The caller may read their own record;
// reading anyone else's requires admin.
func (c *controller) getUserByID(w http.ResponseWriter, r *http.Request) {
	caller, ok := callerFrom(r.Context())
	if !ok {
		// Only reachable if this handler is wired without requireSession.
		unauthorized(w)
		return
	}

	id := r.PathValue("id")
	userID, err := uuid.Parse(id)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	if !mayAccessUser(caller, userID) {
		// Checked before the lookup, so a denial does not confirm that the
		// target exists.
		w.WriteHeader(http.StatusForbidden)
		return
	}

	user, err := c.db.GetUserById(r.Context(), userID)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			slog.Error(err.Error())
		}
		w.WriteHeader(http.StatusNotFound)
		return
	}

	JSON(w, http.StatusOK, publicUser(user))
}

type CreateUserRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// statusResponse is the generic acknowledgement returned by routes that must
// not reveal whether the named account exists.
type statusResponse struct {
	Status string `json:"status"`
}

// createUser creates a new user. Both the response and the work performed are
// intentionally identical whether the email was free or already registered, so
// neither the body nor the timing reveals which addresses are registered.
func (c *controller) createUser(w http.ResponseWriter, r *http.Request) {
	if !validateContentTypeJSON(w, r) {
		return
	}

	var req CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		slog.Error(err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if req.Email == "" || len(req.Password) < 8 {
		PlainText(w, http.StatusBadRequest, "invalid request")
		return
	}

	// Derive before looking the address up. A signup attempt must pay the same
	// argon2id cost whatever the lookup returns, or the response time reports
	// whether the address is already registered. The salt and hash are only
	// stored when the address turns out to be free.
	salt := argon2.GenerateSalt()
	hashedPassword := argon2.HashPassword(req.Password, salt)

	_, err := c.db.GetUserByEmail(r.Context(), req.Email)
	switch {
	case err == nil:
		// Email already registered: return the same response as a new signup.
		JSON(w, http.StatusCreated, statusResponse{Status: "ok"})
		return
	case !errors.Is(err, pgx.ErrNoRows):
		slog.Error(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	userParams := repository.CreateUserParams{
		ID:             uuid.New(),
		Email:          req.Email,
		HashedPassword: hashedPassword,
		Salt:           salt,
	}

	user, err := c.db.CreateUser(r.Context(), userParams)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			// Lost a race against a concurrent signup: same response again.
			JSON(w, http.StatusCreated, statusResponse{Status: "ok"})
			return
		}
		slog.Error(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// No email provider is configured yet, so the verification link is logged
	// to the console instead of being sent. Only the token hash is stored.
	token, err := generateToken()
	if err != nil {
		slog.Error(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	err = c.db.CreateVerificationToken(r.Context(), repository.CreateVerificationTokenParams{
		TokenHash: hashToken(token),
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	})
	if err != nil {
		slog.Error(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	slog.Info("signup verification link",
		"email", user.Email,
		"url", verificationBaseURL()+"/v1/verify?token="+url.QueryEscape(token),
	)

	JSON(w, http.StatusCreated, statusResponse{Status: "ok"})
}

// deleteUserRequest names the account to delete. ID takes precedence over
// email when both are given.
type deleteUserRequest struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

// deleteUser deletes user on email or ID from request
// ID takes precedence over email. The caller may delete their own account;
// deleting anyone else's requires admin.
func (c *controller) deleteUser(w http.ResponseWriter, r *http.Request) {
	if !validateContentTypeJSON(w, r) {
		return
	}

	var req deleteUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		slog.Error(err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	_, target, ok := c.authorizeTarget(w, r, req.ID, req.Email)
	if !ok {
		return
	}

	deleted, err := c.db.DeleteUser(r.Context(), target)
	if err != nil {
		slog.Error(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if deleted == 0 {
		// Authorized, but no such account.
		w.WriteHeader(http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// updateUserRequest is a partial update: a field is written only when it is
// present in the body, so an omitted field keeps its stored value. A JSON null
// reads as omitted. The account is always named by ID — an email here means
// "change the address", never "pick the account".
type updateUserRequest struct {
	ID       string  `json:"id"`
	Email    *string `json:"email"`
	Password *string `json:"password"`
	Active   *bool   `json:"active"`
	Admin    *bool   `json:"admin"`
}

// updateUser updates user in database with data from request.
// The caller may change their own email and password; every other field, and
// any account but their own, requires admin.
func (c *controller) updateUser(w http.ResponseWriter, r *http.Request) {
	if !validateContentTypeJSON(w, r) {
		return
	}

	var req updateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		slog.Error(err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if req.ID == "" {
		PlainText(w, http.StatusBadRequest, "missing id")
		return
	}

	caller, target, ok := c.authorizeTarget(w, r, req.ID, "")
	if !ok {
		return
	}

	// Refused before the row is read: active and admin are not a caller's to
	// write, not even on their own account.
	if (req.Active != nil || req.Admin != nil) && !caller.Admin {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if req.Email != nil && *req.Email == "" {
		PlainText(w, http.StatusBadRequest, "invalid request")
		return
	}
	if req.Password != nil && len(*req.Password) < 8 {
		PlainText(w, http.StatusBadRequest, "invalid request")
		return
	}

	current, err := c.db.GetUserById(r.Context(), target)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			slog.Error(err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// UpdateUser rewrites the whole row, so the fields the request does not
	// mention are carried over from the stored account.
	if req.Email != nil {
		current.Email = *req.Email
	}
	if req.Password != nil {
		// A new password gets a new salt: keeping the old one would let two
		// accounts that share a password share a digest.
		current.Salt = argon2.GenerateSalt()
		current.HashedPassword = argon2.HashPassword(*req.Password, current.Salt)
		// Bumping the epoch retires every session minted before this moment,
		// so changing a password takes away a token that is already in the
		// wrong hands — including the caller's own, which has to log in again.
		current.SessionEpoch++
	}
	if req.Active != nil {
		current.Active = *req.Active
	}
	if req.Admin != nil {
		current.Admin = *req.Admin
	}

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
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			PlainText(w, http.StatusConflict, "email already registered")
			return
		}
		slog.Error(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	JSON(w, http.StatusOK, publicUser(updated))
}

// authorizeTarget resolves the account named by an ID or an email — ID takes
// precedence — and reports whether the caller may act on it. When it reports
// false the response has already been written.
func (c *controller) authorizeTarget(w http.ResponseWriter, r *http.Request, id, email string) (repository.User, uuid.UUID, bool) {
	caller, ok := callerFrom(r.Context())
	if !ok {
		// Only reachable if this handler is wired without requireSession.
		unauthorized(w)
		return repository.User{}, uuid.Nil, false
	}

	target, ok := c.resolveTarget(w, r, caller, id, email)
	if !ok {
		return repository.User{}, uuid.Nil, false
	}

	if !mayAccessUser(caller, target) {
		// Checked before the lookup, so a denial does not confirm that the
		// target exists.
		w.WriteHeader(http.StatusForbidden)
		return repository.User{}, uuid.Nil, false
	}

	return caller, target, true
}

// resolveTarget turns the id/email pair in a request into the UUID of the
// account it names. A caller that is not an admin is held to their own
// identity before anything is looked up, so asking about an address that is
// not theirs cannot be used to test whether it is registered.
func (c *controller) resolveTarget(w http.ResponseWriter, r *http.Request, caller repository.User, id, email string) (uuid.UUID, bool) {
	if id != "" {
		userID, err := uuid.Parse(id)
		if err != nil {
			PlainText(w, http.StatusBadRequest, "invalid id")
			return uuid.Nil, false
		}
		return userID, true
	}

	if email == "" {
		PlainText(w, http.StatusBadRequest, "missing id or email")
		return uuid.Nil, false
	}

	if !caller.Admin {
		if email != caller.Email {
			w.WriteHeader(http.StatusForbidden)
			return uuid.Nil, false
		}
		return caller.ID, true
	}

	user, err := c.db.GetUserByEmail(r.Context(), email)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			slog.Error(err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return uuid.Nil, false
		}
		w.WriteHeader(http.StatusNotFound)
		return uuid.Nil, false
	}
	return user.ID, true
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// SessionResponse is what a login or a refresh answers with: a short-lived
// session and the longer-lived refresh token that mints the next one.
type SessionResponse struct {
	Session string `json:"session"`
	Refresh string `json:"refresh"`
}

// refreshRequest presents a refresh token for exchange.
type refreshRequest struct {
	Refresh string `json:"refresh"`
}

// decoySalt and decoyHash stand in when there is no stored credential to check
// against. Every login attempt must pay exactly one argon2id derivation, or the
// response time reveals whether an email is registered. The digest is a fixed
// random value with no known preimage, so it cannot be produced by supplying a
// password; `stored` in login keeps it from admitting anyone even if it were.
var (
	decoySalt = []byte{0x24, 0x5d, 0x07, 0x6e, 0xfd, 0x31, 0x11, 0x87, 0x97, 0x95, 0x48, 0x12, 0x7d, 0x0e, 0x23, 0x29}
	decoyHash = []byte{0x55, 0x6a, 0xb6, 0x0f, 0xb0, 0x7d, 0xb6, 0x97, 0xc2, 0x97, 0x34, 0x9c, 0x55, 0xa4, 0x1c, 0xd4, 0xc7, 0x64, 0x13, 0x3a, 0xa0, 0xd7, 0xc3, 0xe7, 0x65, 0x9c, 0x2d, 0xd4, 0xd2, 0xf5, 0xc9, 0xd4}
)

func (c *controller) login(w http.ResponseWriter, r *http.Request) {
	if !validateContentTypeJSON(w, r) {
		return
	}

	var request LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	user, err := c.db.GetUserByEmail(r.Context(), request.Email)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			slog.Error(err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		// Unknown account: user stays zero, so the decoy is used below and the
		// response is identical to a wrong password on a registered account.
	}

	// Select the credential to derive against, then run that derivation once,
	// whatever the outcome. The decoy covers an unknown account and an account
	// with no stored credential (`hashed_password`/`salt` are nullable).
	stored := err == nil && user.HashedPassword != nil && user.Salt != nil
	hash, salt := decoyHash, decoySalt
	if stored {
		hash, salt = user.HashedPassword, user.Salt
	}

	if argon2.Validate(request.Password, hash, salt) != nil || !stored {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if !user.Active {
		PlainText(w, http.StatusForbidden, "account not verified")
		return
	}

	sessionToken, err := c.mintSession(user)
	if err != nil {
		slog.Error(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	refreshToken, err := c.issueRefreshToken(r.Context(), user)
	if err != nil {
		slog.Error(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	JSON(w, http.StatusOK, SessionResponse{
		Session: sessionToken,
		Refresh: refreshToken,
	})
}

// mintSession signs a session token for user at the generation the account is
// in now. Every mint — fresh login or refresh — reads the current epoch, so a
// token handed out here is already retired if the password changes afterwards.
func (c *controller) mintSession(user repository.User) (string, error) {
	now := time.Now()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, sessionClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    sessionIssuer,
			Subject:   user.ID.String(),
			Audience:  jwt.ClaimStrings{sessionAudience},
			ExpiresAt: jwt.NewNumericDate(now.Add(sessionTTL)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
		SessionEpoch: &user.SessionEpoch,
	})

	return token.SignedString(c.sessionToken)
}

// issueRefreshToken stores a new refresh token for user and returns the value
// to hand to the client. Only the hash is persisted; the token itself exists
// just in the response. It carries the account's current session generation
// so a password change retires it along with every session.
func (c *controller) issueRefreshToken(ctx context.Context, user repository.User) (string, error) {
	token, err := generateToken()
	if err != nil {
		return "", err
	}

	err = c.db.CreateRefreshToken(ctx, repository.CreateRefreshTokenParams{
		TokenHash:    hashToken(token),
		UserID:       user.ID,
		SessionEpoch: user.SessionEpoch,
		ExpiresAt:    time.Now().Add(refreshTokenTTL),
	})
	if err != nil {
		return "", err
	}

	return token, nil
}

// refresh exchanges a refresh token for a new session and a new refresh token.
// The presented token is consumed — rotation means a copy that leaked cannot be
// replayed after the legitimate client has used the real one. A token whose
// generation no longer matches the account's is refused, which is how a
// password change retires refresh tokens minted before it.
func (c *controller) refresh(w http.ResponseWriter, r *http.Request) {
	if !validateContentTypeJSON(w, r) {
		return
	}

	var req refreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Refresh == "" {
		PlainText(w, http.StatusBadRequest, "invalid request")
		return
	}

	tokenHash := hashToken(req.Refresh)

	// Consuming the token is the lookup: a single delete that returns the row, so
	// two concurrent refreshes with the same value cannot both succeed. A token
	// that is found is gone whether or not the rest of the request goes on to
	// mint a replacement.
	stored, err := c.db.ConsumeRefreshToken(r.Context(), tokenHash)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			slog.Error(err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		unauthorized(w)
		return
	}

	if stored.ExpiresAt.Before(time.Now()) {
		unauthorized(w)
		return
	}

	user, err := c.db.GetUserById(r.Context(), stored.UserID)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			slog.Error(err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		// The account is gone; the cascade should have removed the token, so
		// this is only reachable if the row outlived its user.
		unauthorized(w)
		return
	}

	if !user.Active || stored.SessionEpoch != user.SessionEpoch {
		slog.Debug("rejected refresh token from a retired session generation",
			"subject", user.ID, "epoch", stored.SessionEpoch, "current", user.SessionEpoch)
		unauthorized(w)
		return
	}

	sessionToken, err := c.mintSession(user)
	if err != nil {
		slog.Error(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	refreshToken, err := c.issueRefreshToken(r.Context(), user)
	if err != nil {
		slog.Error(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	JSON(w, http.StatusOK, SessionResponse{
		Session: sessionToken,
		Refresh: refreshToken,
	})
}

// passwordResetRequest names the account whose password should be reset.
type passwordResetRequest struct {
	Email string `json:"email"`
}

// passwordResetConfirmRequest carries a reset token and the replacement
// password.
type passwordResetConfirmRequest struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}

// forgotPassword starts a password reset. The response is identical whether or
// not the address is registered, and any outstanding token for the account is
// retired first, so only the most recently requested link can be redeemed.
func (c *controller) forgotPassword(w http.ResponseWriter, r *http.Request) {
	if !validateContentTypeJSON(w, r) {
		return
	}

	var req passwordResetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" {
		PlainText(w, http.StatusBadRequest, "invalid request")
		return
	}

	user, err := c.db.GetUserByEmail(r.Context(), req.Email)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			slog.Error(err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		// Unknown address: nothing to issue, but the caller must not be able to
		// tell this apart from a registered one.
		JSON(w, http.StatusAccepted, statusResponse{Status: "ok"})
		return
	}

	if err := c.db.DeletePasswordResetTokensForUser(r.Context(), user.ID); err != nil {
		slog.Error(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	token, err := generateToken()
	if err != nil {
		slog.Error(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	err = c.db.CreatePasswordResetToken(r.Context(), repository.CreatePasswordResetTokenParams{
		TokenHash: hashToken(token),
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(passwordResetTTL),
	})
	if err != nil {
		slog.Error(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// No email provider is configured yet, so the reset token is logged to the
	// console instead of being sent. Only the token hash is stored. Unlike the
	// verification link there is no GET confirm page, so the raw token is logged
	// for a developer to present to POST /v1/password/reset.
	slog.Info("password reset token",
		"email", user.Email,
		"token", token,
	)

	JSON(w, http.StatusAccepted, statusResponse{Status: "ok"})
}

// resetPassword sets a new password from a single-use reset token. Consuming
// the token is the lookup, so a token can be redeemed exactly once even under
// concurrent requests, and the password change bumps the session epoch, which
// retires every session and refresh token minted before it.
func (c *controller) resetPassword(w http.ResponseWriter, r *http.Request) {
	if !validateContentTypeJSON(w, r) {
		return
	}

	var req passwordResetConfirmRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Token == "" {
		PlainText(w, http.StatusBadRequest, "invalid request")
		return
	}
	if len(req.Password) < 8 {
		PlainText(w, http.StatusBadRequest, "invalid request")
		return
	}

	stored, err := c.db.ConsumePasswordResetToken(r.Context(), hashToken(req.Token))
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			slog.Error(err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		PlainText(w, http.StatusBadRequest, "invalid or expired token")
		return
	}

	if stored.ExpiresAt.Before(time.Now()) {
		PlainText(w, http.StatusBadRequest, "invalid or expired token")
		return
	}

	current, err := c.db.GetUserById(r.Context(), stored.UserID)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			slog.Error(err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		// The account is gone; the cascade should have removed the token, so
		// this is only reachable if the row outlived its user.
		PlainText(w, http.StatusBadRequest, "invalid or expired token")
		return
	}

	// A fresh salt, then a whole-row write that bumps the epoch, exactly as the
	// PATCH handler does for a password change.
	salt := argon2.GenerateSalt()
	hashed := argon2.HashPassword(req.Password, salt)

	_, err = c.db.UpdateUser(r.Context(), repository.UpdateUserParams{
		ID:             current.ID,
		Email:          current.Email,
		HashedPassword: hashed,
		Salt:           salt,
		Active:         current.Active,
		Admin:          current.Admin,
		SessionEpoch:   current.SessionEpoch + 1,
	})
	if err != nil {
		slog.Error(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// The consumed token is already gone; this clears any other outstanding one.
	if err := c.db.DeletePasswordResetTokensForUser(r.Context(), current.ID); err != nil {
		slog.Error(err.Error())
	}

	PlainText(w, http.StatusOK, "Password updated. You can now log in.")
}

func publicUser(user repository.User) User {
	return User{
		ID:     user.ID,
		Email:  user.Email,
		Active: user.Active,
		Admin:  user.Admin,
	}
}

// verify activates an account from the token in the verification link.
func (c *controller) verify(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		PlainText(w, http.StatusBadRequest, "missing token")
		return
	}

	tokenHash := hashToken(token)

	vt, err := c.db.GetVerificationToken(r.Context(), tokenHash)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			slog.Error(err.Error())
		}
		PlainText(w, http.StatusBadRequest, "invalid or expired token")
		return
	}

	if vt.ExpiresAt.Before(time.Now()) {
		if err := c.db.DeleteVerificationTokensForUser(r.Context(), vt.UserID); err != nil {
			slog.Error(err.Error())
		}
		PlainText(w, http.StatusBadRequest, "invalid or expired token")
		return
	}

	if err := c.db.ActivateUser(r.Context(), vt.UserID); err != nil {
		slog.Error(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if err := c.db.DeleteVerificationTokensForUser(r.Context(), vt.UserID); err != nil {
		slog.Error(err.Error())
	}

	PlainText(w, http.StatusOK, "Account verified. You can now log in.")
}

// generateToken returns a 256-bit random token, hex encoded. It is used for
// both verification and refresh tokens; only the stored hash ever matters to
// the server.
func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// hashToken returns the SHA-256 hash stored for a bearer-style token. Only the
// hash is persisted, so a database leak does not expose usable tokens.
func hashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// verificationBaseURL is the public base URL used to build verification links.
func verificationBaseURL() string {
	if base := os.Getenv("PUBLIC_BASE_URL"); base != "" {
		return strings.TrimRight(base, "/")
	}
	return "http://localhost:8080"
}
