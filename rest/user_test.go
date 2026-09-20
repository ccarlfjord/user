package rest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ccarlfjord/argon2"
	"github.com/ccarlfjord/user/internal/repository"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type fakeStore struct {
	getUserByEmail                  func(context.Context, string) (repository.User, error)
	getUserById                     func(context.Context, uuid.UUID) (repository.User, error)
	createUser                      func(context.Context, repository.CreateUserParams) (repository.User, error)
	createVerificationToken         func(context.Context, repository.CreateVerificationTokenParams) error
	getVerificationToken            func(context.Context, []byte) (repository.VerificationToken, error)
	deleteVerificationTokensForUser func(context.Context, uuid.UUID) error
	activateUser                    func(context.Context, uuid.UUID) error
	updateUser                      func(context.Context, repository.UpdateUserParams) (repository.User, error)
	deleteUser                      func(context.Context, uuid.UUID) (int64, error)
}

func (f fakeStore) GetUserByEmail(ctx context.Context, email string) (repository.User, error) {
	return f.getUserByEmail(ctx, email)
}

func (f fakeStore) GetUserById(ctx context.Context, id uuid.UUID) (repository.User, error) {
	return f.getUserById(ctx, id)
}

func (f fakeStore) CreateUser(ctx context.Context, arg repository.CreateUserParams) (repository.User, error) {
	return f.createUser(ctx, arg)
}

func (f fakeStore) CreateVerificationToken(ctx context.Context, arg repository.CreateVerificationTokenParams) error {
	return f.createVerificationToken(ctx, arg)
}

func (f fakeStore) GetVerificationToken(ctx context.Context, tokenHash []byte) (repository.VerificationToken, error) {
	return f.getVerificationToken(ctx, tokenHash)
}

func (f fakeStore) DeleteVerificationTokensForUser(ctx context.Context, userID uuid.UUID) error {
	return f.deleteVerificationTokensForUser(ctx, userID)
}

func (f fakeStore) ActivateUser(ctx context.Context, id uuid.UUID) error {
	return f.activateUser(ctx, id)
}

func (f fakeStore) UpdateUser(ctx context.Context, arg repository.UpdateUserParams) (repository.User, error) {
	return f.updateUser(ctx, arg)
}

func (f fakeStore) DeleteUser(ctx context.Context, id uuid.UUID) (int64, error) {
	return f.deleteUser(ctx, id)
}

// testSessionKey is the HMAC key newTestController signs and validates
// sessions with.
const testSessionKey = "test-signing-key"

func newTestController(store userStore) *controller {
	return &controller{
		db:           store,
		sessionToken: []byte(testSessionKey),
	}
}

func doRequest(handler http.HandlerFunc, method, target, contentType, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, bytes.NewBufferString(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	rec := httptest.NewRecorder()
	handler(rec, req)
	return rec
}

const genericSignupBody = `{"status":"ok"}`

func TestCreateUserNewReturnsGenericCreated(t *testing.T) {
	created := false
	var stored repository.CreateUserParams
	store := fakeStore{
		getUserByEmail: func(context.Context, string) (repository.User, error) {
			return repository.User{}, pgx.ErrNoRows
		},
		createUser: func(_ context.Context, arg repository.CreateUserParams) (repository.User, error) {
			created = true
			stored = arg
			return repository.User{ID: arg.ID, Email: arg.Email, Active: arg.Active}, nil
		},
		createVerificationToken: func(context.Context, repository.CreateVerificationTokenParams) error {
			return nil
		},
	}
	c := newTestController(store)

	rec := doRequest(c.createUser, http.MethodPost, "/v1/user", "application/json",
		`{"email":"a@b.com","username":"ab","password":"password1"}`)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201", rec.Code)
	}
	if !created {
		t.Fatal("user was not created")
	}
	if got := rec.Body.String(); got != genericSignupBody {
		t.Fatalf("body = %q, want %q", got, genericSignupBody)
	}
	// The credential handed to the store must be the one the account logs in
	// with: the hash is now derived before the email lookup, so it has to
	// survive that reordering.
	if err := argon2.Validate("password1", stored.HashedPassword, stored.Salt); err != nil {
		t.Fatalf("stored credential does not validate the signup password: %v", err)
	}
	if len(stored.Salt) != 16 {
		t.Fatalf("salt length = %d, want 16", len(stored.Salt))
	}
}

func TestCreateUserExistingReturnsIdenticalResponse(t *testing.T) {
	store := fakeStore{
		getUserByEmail: func(context.Context, string) (repository.User, error) {
			return repository.User{
				ID:             uuid.New(),
				Email:          "a@b.com",
				HashedPassword: []byte("secret-hash"),
				Salt:           []byte("secret-salt"),
			}, nil
		},
	}
	c := newTestController(store)

	rec := doRequest(c.createUser, http.MethodPost, "/v1/user", "application/json",
		`{"email":"a@b.com","username":"ab","password":"password1"}`)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201", rec.Code)
	}
	if got := rec.Body.String(); got != genericSignupBody {
		t.Fatalf("body = %q, want %q", got, genericSignupBody)
	}
	if bytes.Contains(rec.Body.Bytes(), []byte("secret-hash")) || bytes.Contains(rec.Body.Bytes(), []byte("secret-salt")) {
		t.Fatal("response leaked stored password material")
	}
}

func TestCreateUserUniqueRaceReturnsGenericCreated(t *testing.T) {
	store := fakeStore{
		getUserByEmail: func(context.Context, string) (repository.User, error) {
			return repository.User{}, pgx.ErrNoRows
		},
		createUser: func(context.Context, repository.CreateUserParams) (repository.User, error) {
			return repository.User{}, &pgconn.PgError{Code: "23505"}
		},
	}
	c := newTestController(store)

	rec := doRequest(c.createUser, http.MethodPost, "/v1/user", "application/json",
		`{"email":"a@b.com","username":"ab","password":"password1"}`)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201", rec.Code)
	}
	if got := rec.Body.String(); got != genericSignupBody {
		t.Fatalf("body = %q, want %q", got, genericSignupBody)
	}
}

func TestCreateUserBadRequests(t *testing.T) {
	c := newTestController(fakeStore{})

	tests := []struct {
		name        string
		contentType string
		body        string
	}{
		{"bad content type", "text/plain", `{"email":"a@b.com","username":"ab","password":"password1"}`},
		{"short password", "application/json", `{"email":"a@b.com","username":"ab","password":"short"}`},
		{"empty email", "application/json", `{"email":"","username":"ab","password":"password1"}`},
		{"malformed json", "application/json", `{`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := doRequest(c.createUser, http.MethodPost, "/v1/user", tt.contentType, tt.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", rec.Code)
			}
		})
	}
}

func TestLoginFailuresAreIndistinguishable(t *testing.T) {
	knownSalt := []byte("0123456789abcdef")
	store := fakeStore{
		getUserByEmail: func(_ context.Context, email string) (repository.User, error) {
			if email == "unknown@example.com" {
				return repository.User{}, pgx.ErrNoRows
			}
			return repository.User{
				ID:             uuid.New(),
				Email:          email,
				HashedPassword: argon2.HashPassword("rightpassword", knownSalt),
				Salt:           knownSalt,
			}, nil
		},
	}
	c := newTestController(store)

	unknown := doRequest(c.login, http.MethodPost, "/v1/login", "application/json",
		`{"email":"unknown@example.com","password":"whatever"}`)
	wrong := doRequest(c.login, http.MethodPost, "/v1/login", "application/json",
		`{"email":"known@example.com","password":"wrongpassword"}`)

	if unknown.Code != http.StatusUnauthorized || wrong.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d and %d, want 401", unknown.Code, wrong.Code)
	}
	if unknown.Body.String() != wrong.Body.String() {
		t.Fatalf("bodies differ: %q vs %q", unknown.Body.String(), wrong.Body.String())
	}
}

func TestLoginSuccessReturnsSession(t *testing.T) {
	salt := []byte("0123456789abcdef")
	store := fakeStore{
		getUserByEmail: func(context.Context, string) (repository.User, error) {
			return repository.User{
				ID:             uuid.New(),
				HashedPassword: argon2.HashPassword("rightpassword", salt),
				Salt:           salt,
				Active:         true,
			}, nil
		},
	}
	c := newTestController(store)

	rec := doRequest(c.login, http.MethodPost, "/v1/login", "application/json",
		`{"email":"known@example.com","password":"rightpassword"}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp LoginResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Session == "" {
		t.Fatal("expected a session token")
	}
}

func TestLoginMalformedBodyReturnsBadRequest(t *testing.T) {
	c := newTestController(fakeStore{})
	rec := doRequest(c.login, http.MethodPost, "/v1/login", "application/json", `{`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// A row can carry NULL credentials (the columns are nullable), and an active
// account with none must not be loginable with any password.
func TestLoginRejectsAccountsWithoutStoredCredentials(t *testing.T) {
	salt := []byte("0123456789abcdef")
	tests := []struct {
		name string
		user repository.User
	}{
		{"null hash", repository.User{HashedPassword: nil, Salt: salt}},
		{"null salt", repository.User{HashedPassword: argon2.HashPassword("rightpassword", salt), Salt: nil}},
		{"no credential at all", repository.User{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := tt.user
			user.ID = uuid.New()
			user.Active = true
			c := newTestController(fakeStore{
				getUserByEmail: func(context.Context, string) (repository.User, error) {
					return user, nil
				},
			})

			for _, password := range []string{"rightpassword", "password1", "", "decoy"} {
				rec := doRequest(c.login, http.MethodPost, "/v1/login", "application/json",
					`{"email":"a@b.com","password":"`+password+`"}`)
				if rec.Code != http.StatusUnauthorized {
					t.Fatalf("password %q: status = %d, want 401", password, rec.Code)
				}
				if bytes.Contains(rec.Body.Bytes(), []byte("session")) {
					t.Fatalf("password %q: response carried a session", password)
				}
			}
		})
	}
}

func TestLoginRejectsUnverifiedAccount(t *testing.T) {
	salt := []byte("0123456789abcdef")
	c := newTestController(fakeStore{
		getUserByEmail: func(context.Context, string) (repository.User, error) {
			return repository.User{
				ID:             uuid.New(),
				HashedPassword: argon2.HashPassword("rightpassword", salt),
				Salt:           salt,
				Active:         false,
			}, nil
		},
	})

	rec := doRequest(c.login, http.MethodPost, "/v1/login", "application/json",
		`{"email":"a@b.com","password":"rightpassword"}`)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if bytes.Contains(rec.Body.Bytes(), []byte("session")) {
		t.Fatal("response carried a session for an unverified account")
	}
}

func TestGetUserByIDNotFound(t *testing.T) {
	admin := activeUser(true)
	store := fakeStore{
		getUserById: func(_ context.Context, id uuid.UUID) (repository.User, error) {
			if id == admin.ID {
				return admin, nil
			}
			return repository.User{}, pgx.ErrNoRows
		},
	}
	c := newTestController(store)

	// Unknown id: authorized (admin) but the row does not exist.
	missing := httptest.NewRecorder()
	missingReq := authRequest(t, http.MethodGet, "/v1/user/"+uuid.New().String(), admin.ID.String())
	missingReq.SetPathValue("id", uuid.New().String())
	c.userByIDHandler(missing, missingReq)

	// Unparseable id: rejected before any lookup or authorization.
	invalidReq := authRequest(t, http.MethodGet, "/v1/user/not-a-uuid", admin.ID.String())
	invalid := httptest.NewRecorder()
	c.userByIDHandler(invalid, invalidReq)

	if missing.Code != http.StatusNotFound || invalid.Code != http.StatusNotFound {
		t.Fatalf("status = %d and %d, want 404", missing.Code, invalid.Code)
	}
}

func TestVerifyActivatesUser(t *testing.T) {
	activated := false
	cleared := false
	store := fakeStore{
		getVerificationToken: func(context.Context, []byte) (repository.VerificationToken, error) {
			return repository.VerificationToken{
				UserID:    uuid.New(),
				ExpiresAt: time.Now().Add(time.Hour),
			}, nil
		},
		activateUser: func(context.Context, uuid.UUID) error {
			activated = true
			return nil
		},
		deleteVerificationTokensForUser: func(context.Context, uuid.UUID) error {
			cleared = true
			return nil
		},
	}
	c := newTestController(store)

	rec := doRequest(c.verify, http.MethodGet, "/v1/verify?token=abc", "", "")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !activated || !cleared {
		t.Fatalf("activated = %v, cleared = %v, want both true", activated, cleared)
	}
}

func TestVerifyRejectsInvalidOrExpiredToken(t *testing.T) {
	c := newTestController(fakeStore{
		getVerificationToken: func(context.Context, []byte) (repository.VerificationToken, error) {
			return repository.VerificationToken{}, pgx.ErrNoRows
		},
	})

	invalid := doRequest(c.verify, http.MethodGet, "/v1/verify?token=bad", "", "")
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid token status = %d, want 400", invalid.Code)
	}

	expiredStore := fakeStore{
		getVerificationToken: func(context.Context, []byte) (repository.VerificationToken, error) {
			return repository.VerificationToken{
				UserID:    uuid.New(),
				ExpiresAt: time.Now().Add(-time.Hour),
			}, nil
		},
		deleteVerificationTokensForUser: func(context.Context, uuid.UUID) error {
			return nil
		},
	}
	expired := doRequest(newTestController(expiredStore).verify, http.MethodGet, "/v1/verify?token=old", "", "")
	if expired.Code != http.StatusBadRequest {
		t.Fatalf("expired token status = %d, want 400", expired.Code)
	}
}

// signSession issues a token the way login does.
func signSession(t *testing.T, key []byte, sub string, expiresAt *time.Time) string {
	t.Helper()

	claims := jwt.RegisteredClaims{Subject: sub}
	if expiresAt != nil {
		claims.ExpiresAt = jwt.NewNumericDate(*expiresAt)
	}

	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(key)
	if err != nil {
		t.Fatalf("sign session: %v", err)
	}
	return signed
}

// authRequest returns a request carrying a valid session token for sub.
func authRequest(t *testing.T, method, target, sub string) *http.Request {
	t.Helper()

	inAnHour := time.Now().Add(time.Hour)
	req := httptest.NewRequest(method, target, nil)
	req.Header.Set("Authorization", "Bearer "+signSession(t, []byte(testSessionKey), sub, &inAnHour))
	return req
}

// authRequestWithBody returns an authenticated request carrying a body.
func authRequestWithBody(t *testing.T, method, target, sub, contentType, body string) *http.Request {
	t.Helper()

	req := authRequest(t, method, target, sub)
	req.Body = io.NopCloser(strings.NewReader(body))
	req.ContentLength = int64(len(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	return req
}

// activeUser is a live account that a session subject can resolve to.
func activeUser(admin bool) repository.User {
	return repository.User{ID: uuid.New(), Email: "caller@example.com", Active: true, Admin: admin}
}

func TestRequireSessionRejectsInvalidTokens(t *testing.T) {
	c := newTestController(fakeStore{})
	key := []byte(testSessionKey)
	inAnHour := time.Now().Add(time.Hour)
	sub := uuid.New().String()

	// Same key, different algorithm: must not be accepted even though the
	// signature would verify under a non-pinned HMAC check.
	hs512 := func() string {
		token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.RegisteredClaims{
			Subject:   sub,
			ExpiresAt: jwt.NewNumericDate(inAnHour),
		})
		signed, err := token.SignedString(key)
		if err != nil {
			t.Fatalf("sign hs512 token: %v", err)
		}
		return signed
	}()

	none := func() string {
		token := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.RegisteredClaims{
			Subject:   sub,
			ExpiresAt: jwt.NewNumericDate(inAnHour),
		})
		signed, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
		if err != nil {
			t.Fatalf("sign none token: %v", err)
		}
		return signed
	}()

	expired := time.Now().Add(-time.Minute)
	tests := []struct {
		name   string
		header string
	}{
		{"missing header", ""},
		{"scheme without token", "Bearer"},
		{"wrong scheme", "Basic " + signSession(t, key, sub, &inAnHour)},
		{"malformed token", "Bearer not-a-jwt"},
		{"signed with another key", "Bearer " + signSession(t, []byte("other-signing-key"), sub, &inAnHour)},
		{"expired", "Bearer " + signSession(t, key, sub, &expired)},
		{"no expiry", "Bearer " + signSession(t, key, sub, nil)},
		{"hs512", "Bearer " + hs512},
		{"alg none", "Bearer " + none},
		{"empty subject", "Bearer " + signSession(t, key, "", &inAnHour)},
		{"subject is not a user id", "Bearer " + signSession(t, key, "not-a-uuid", &inAnHour)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			handler := c.requireSession(func(http.ResponseWriter, *http.Request) { called = true })

			req := httptest.NewRequest(http.MethodGet, "/v1/user/"+uuid.New().String(), nil)
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}
			rec := httptest.NewRecorder()
			handler(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", rec.Code)
			}
			if called {
				t.Fatal("handler ran for a rejected session")
			}
		})
	}
}

func TestRequireSessionAcceptsValidToken(t *testing.T) {
	caller := activeUser(false)
	c := newTestController(fakeStore{
		getUserById: func(_ context.Context, id uuid.UUID) (repository.User, error) {
			if id != caller.ID {
				t.Fatalf("looked up %s, want the session subject %s", id, caller.ID)
			}
			return caller, nil
		},
	})

	var got repository.User
	called := false
	handler := c.requireSession(func(w http.ResponseWriter, r *http.Request) {
		called = true
		got, _ = callerFrom(r.Context())
		w.WriteHeader(http.StatusNoContent)
	})

	rec := httptest.NewRecorder()
	handler(rec, authRequest(t, http.MethodGet, "/v1/user/"+caller.ID.String(), caller.ID.String()))

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
	if !called {
		t.Fatal("handler did not run for a valid session")
	}
	if got.ID != caller.ID {
		t.Fatalf("caller in context = %s, want %s", got.ID, caller.ID)
	}
}

func TestRequireSessionRejectsUnresolvableCaller(t *testing.T) {
	caller := activeUser(false)
	inactive := caller
	inactive.Active = false

	tests := []struct {
		name  string
		store fakeStore
		want  int
	}{
		{
			name: "deleted account",
			store: fakeStore{
				getUserById: func(context.Context, uuid.UUID) (repository.User, error) {
					return repository.User{}, pgx.ErrNoRows
				},
			},
			want: http.StatusUnauthorized,
		},
		{
			name: "deactivated account",
			store: fakeStore{
				getUserById: func(context.Context, uuid.UUID) (repository.User, error) {
					return inactive, nil
				},
			},
			want: http.StatusUnauthorized,
		},
		{
			name: "lookup failure",
			store: fakeStore{
				getUserById: func(context.Context, uuid.UUID) (repository.User, error) {
					return repository.User{}, errors.New("connection reset")
				},
			},
			want: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			handler := newTestController(tt.store).requireSession(func(http.ResponseWriter, *http.Request) { called = true })

			rec := httptest.NewRecorder()
			handler(rec, authRequest(t, http.MethodGet, "/v1/user/"+caller.ID.String(), caller.ID.String()))

			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d", rec.Code, tt.want)
			}
			if called {
				t.Fatal("handler ran for an unresolvable caller")
			}
		})
	}
}

func TestProtectedRoutesRequireSession(t *testing.T) {
	caller := activeUser(false)
	store := fakeStore{
		getUserById: func(_ context.Context, id uuid.UUID) (repository.User, error) {
			return repository.User{ID: id, Email: "a@b.com", Active: true}, nil
		},
	}
	c := newTestController(store)

	protected := []struct {
		name    string
		handler http.HandlerFunc
		method  string
		target  string
	}{
		{"get user by id", c.userByIDHandler, http.MethodGet, "/v1/user/" + caller.ID.String()},
		{"get user", c.userHandler, http.MethodGet, "/v1/user"},
		{"delete user", c.userHandler, http.MethodDelete, "/v1/user"},
		{"update user", c.userHandler, http.MethodPatch, "/v1/user"},
	}

	for _, tt := range protected {
		t.Run(tt.name, func(t *testing.T) {
			rec := doRequest(tt.handler, tt.method, tt.target, "", "")
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", rec.Code)
			}
		})
	}

	// Sign up stays public: the gate must not turn a bad request into a 401.
	t.Run("create user stays public", func(t *testing.T) {
		rec := doRequest(c.userHandler, http.MethodPost, "/v1/user", "text/plain", `{}`)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})

	// A valid session reaches the handler instead of being short-circuited.
	t.Run("valid session reaches handler", func(t *testing.T) {
		req := authRequest(t, http.MethodGet, "/v1/user/"+caller.ID.String(), caller.ID.String())
		req.SetPathValue("id", caller.ID.String())
		rec := httptest.NewRecorder()

		c.userByIDHandler(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		var got User
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if got.ID != caller.ID {
			t.Fatalf("id = %s, want %s", got.ID, caller.ID)
		}
	})
}

func TestGetUserByIDRequiresSelfOrAdmin(t *testing.T) {
	caller := activeUser(false)
	admin := activeUser(true)
	other := repository.User{ID: uuid.New(), Email: "other@example.com", Active: true}

	store := fakeStore{
		getUserById: func(_ context.Context, id uuid.UUID) (repository.User, error) {
			for _, u := range []repository.User{caller, admin, other} {
				if u.ID == id {
					return u, nil
				}
			}
			return repository.User{}, pgx.ErrNoRows
		},
	}

	tests := []struct {
		name   string
		caller repository.User
		target uuid.UUID
		want   int
	}{
		{"self", caller, caller.ID, http.StatusOK},
		{"admin reading another user", admin, other.ID, http.StatusOK},
		{"non-admin reading another user", caller, other.ID, http.StatusForbidden},
		{"non-admin probing an unknown id", caller, uuid.New(), http.StatusForbidden},
		{"admin probing an unknown id", admin, uuid.New(), http.StatusNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestController(store)
			req := authRequest(t, http.MethodGet, "/v1/user/"+tt.target.String(), tt.caller.ID.String())
			req.SetPathValue("id", tt.target.String())
			rec := httptest.NewRecorder()

			c.userByIDHandler(rec, req)

			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d", rec.Code, tt.want)
			}
			if tt.want != http.StatusOK && rec.Body.Len() != 0 {
				t.Fatalf("denied response leaked a body: %q", rec.Body.String())
			}
		})
	}
}

func TestGetUserSelfWithoutQueryReadsSession(t *testing.T) {
	caller := activeUser(false)
	lookups := 0
	store := fakeStore{
		getUserById: func(_ context.Context, id uuid.UUID) (repository.User, error) {
			lookups++
			if id != caller.ID {
				t.Fatalf("looked up %s, want the session subject %s", id, caller.ID)
			}
			return caller, nil
		},
		getUserByEmail: func(context.Context, string) (repository.User, error) {
			t.Fatal("a query-less read touched the email lookup")
			return repository.User{}, nil
		},
	}
	c := newTestController(store)

	rec := httptest.NewRecorder()
	c.userHandler(rec, authRequest(t, http.MethodGet, "/v1/user", caller.ID.String()))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var got User
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	want := User{ID: caller.ID, Email: caller.Email, Active: caller.Active, Admin: caller.Admin}
	if got != want {
		t.Fatalf("body = %+v, want the caller's record %+v", got, want)
	}
	if bytes.Contains(rec.Body.Bytes(), []byte("hashed_password")) || bytes.Contains(rec.Body.Bytes(), []byte("salt")) {
		t.Fatalf("response leaked stored password material: %q", rec.Body.String())
	}
	// Only the session subject is resolved; the record itself comes from the
	// request context.
	if lookups != 1 {
		t.Fatalf("lookups = %d, want 1", lookups)
	}
}

func TestGetUserByEmail(t *testing.T) {
	caller := activeUser(false)
	admin := activeUser(true)
	other := repository.User{ID: uuid.New(), Email: "other@example.com", Active: true, Admin: true}

	t.Run("own address is resolved from the session", func(t *testing.T) {
		store := fakeStore{
			getUserById: func(context.Context, uuid.UUID) (repository.User, error) {
				return caller, nil
			},
			getUserByEmail: func(context.Context, string) (repository.User, error) {
				t.Fatal("the caller's own address was looked up")
				return repository.User{}, nil
			},
		}

		rec := httptest.NewRecorder()
		newTestController(store).userHandler(rec, authRequest(t, http.MethodGet,
			"/v1/user?email="+caller.Email, caller.ID.String()))

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		var got User
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if got.ID != caller.ID {
			t.Fatalf("id = %s, want the caller %s", got.ID, caller.ID)
		}
	})

	t.Run("another address is refused without a lookup", func(t *testing.T) {
		lookups := 0
		store := fakeStore{
			getUserById: func(context.Context, uuid.UUID) (repository.User, error) {
				lookups++
				return caller, nil
			},
			getUserByEmail: func(context.Context, string) (repository.User, error) {
				t.Fatal("a non-admin's request for another address reached the store")
				return repository.User{}, nil
			},
		}

		rec := httptest.NewRecorder()
		newTestController(store).userHandler(rec, authRequest(t, http.MethodGet,
			"/v1/user?email="+other.Email, caller.ID.String()))

		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rec.Code)
		}
		if rec.Body.Len() != 0 {
			t.Fatalf("denied response leaked a body: %q", rec.Body.String())
		}
		if lookups != 1 {
			t.Fatalf("lookups = %d, want 1 (the session subject only)", lookups)
		}
	})

	t.Run("admin reads another account", func(t *testing.T) {
		store := fakeStore{
			getUserById: func(_ context.Context, id uuid.UUID) (repository.User, error) {
				if id == other.ID {
					return other, nil
				}
				return admin, nil
			},
			getUserByEmail: func(_ context.Context, email string) (repository.User, error) {
				if email != other.Email {
					t.Fatalf("looked up %q, want %q", email, other.Email)
				}
				return other, nil
			},
		}

		rec := httptest.NewRecorder()
		newTestController(store).userHandler(rec, authRequest(t, http.MethodGet,
			"/v1/user?email="+other.Email, admin.ID.String()))

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		var got User
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		want := User{ID: other.ID, Email: other.Email, Active: other.Active, Admin: other.Admin}
		if got != want {
			t.Fatalf("body = %+v, want %+v", got, want)
		}
	})

	t.Run("missing and failing reads", func(t *testing.T) {
		tests := []struct {
			name string
			err  error
			want int
		}{
			{"unknown address", pgx.ErrNoRows, http.StatusNotFound},
			{"store failure", errors.New("connection reset"), http.StatusInternalServerError},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				store := fakeStore{
					getUserById: func(_ context.Context, id uuid.UUID) (repository.User, error) {
						if id != other.ID {
							return admin, nil
						}
						return repository.User{}, tt.err
					},
					getUserByEmail: func(context.Context, string) (repository.User, error) {
						return other, nil
					},
				}

				rec := httptest.NewRecorder()
				newTestController(store).userHandler(rec, authRequest(t, http.MethodGet,
					"/v1/user?email="+other.Email, admin.ID.String()))

				if rec.Code != tt.want {
					t.Fatalf("status = %d, want %d", rec.Code, tt.want)
				}
			})
		}
	})
}

func TestDeleteUserSelfDeletesAccount(t *testing.T) {
	caller := activeUser(false)
	deleted := uuid.Nil
	store := fakeStore{
		getUserById: func(context.Context, uuid.UUID) (repository.User, error) {
			return caller, nil
		},
		deleteUser: func(_ context.Context, id uuid.UUID) (int64, error) {
			deleted = id
			return 1, nil
		},
	}
	c := newTestController(store)

	rec := httptest.NewRecorder()
	c.userHandler(rec, authRequestWithBody(t, http.MethodDelete, "/v1/user", caller.ID.String(), "application/json",
		`{"id":"`+caller.ID.String()+`"}`))

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
	if deleted != caller.ID {
		t.Fatalf("deleted %s, want the caller %s", deleted, caller.ID)
	}
}

func TestDeleteUserNonAdminMayOnlyDeleteSelf(t *testing.T) {
	caller := activeUser(false)
	store := fakeStore{
		getUserById: func(context.Context, uuid.UUID) (repository.User, error) {
			return caller, nil
		},
		deleteUser: func(context.Context, uuid.UUID) (int64, error) {
			t.Fatal("store was asked to delete")
			return 0, nil
		},
	}
	c := newTestController(store)

	// Another account and an unknown one are answered the same way: the refusal
	// must not report whether the id exists.
	for _, target := range []uuid.UUID{uuid.New(), uuid.New()} {
		rec := httptest.NewRecorder()
		c.userHandler(rec, authRequestWithBody(t, http.MethodDelete, "/v1/user", caller.ID.String(), "application/json",
			`{"id":"`+target.String()+`"}`))

		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rec.Code)
		}
		if rec.Body.Len() != 0 {
			t.Fatalf("denied response leaked a body: %q", rec.Body.String())
		}
	}
}

func TestDeleteUserByEmail(t *testing.T) {
	caller := activeUser(false)
	admin := activeUser(true)
	other := repository.User{ID: uuid.New(), Email: "other@example.com", Active: true}

	t.Run("self is resolved from the session", func(t *testing.T) {
		deleted := uuid.Nil
		store := fakeStore{
			getUserById: func(context.Context, uuid.UUID) (repository.User, error) {
				return caller, nil
			},
			getUserByEmail: func(context.Context, string) (repository.User, error) {
				t.Fatal("the caller's own address was looked up")
				return repository.User{}, nil
			},
			deleteUser: func(_ context.Context, id uuid.UUID) (int64, error) {
				deleted = id
				return 1, nil
			},
		}

		rec := httptest.NewRecorder()
		newTestController(store).userHandler(rec, authRequestWithBody(t, http.MethodDelete, "/v1/user",
			caller.ID.String(), "application/json", `{"email":"`+caller.Email+`"}`))

		if rec.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204", rec.Code)
		}
		if deleted != caller.ID {
			t.Fatalf("deleted %s, want the caller %s", deleted, caller.ID)
		}
	})

	t.Run("another address is refused without a lookup", func(t *testing.T) {
		store := fakeStore{
			getUserById: func(context.Context, uuid.UUID) (repository.User, error) {
				return caller, nil
			},
			getUserByEmail: func(context.Context, string) (repository.User, error) {
				t.Fatal("a non-admin's request for another address reached the store")
				return repository.User{}, nil
			},
			deleteUser: func(context.Context, uuid.UUID) (int64, error) {
				t.Fatal("store was asked to delete")
				return 0, nil
			},
		}

		rec := httptest.NewRecorder()
		newTestController(store).userHandler(rec, authRequestWithBody(t, http.MethodDelete, "/v1/user",
			caller.ID.String(), "application/json", `{"email":"other@example.com"}`))

		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rec.Code)
		}
	})

	t.Run("admin resolves another address", func(t *testing.T) {
		deleted := uuid.Nil
		store := fakeStore{
			getUserById: func(context.Context, uuid.UUID) (repository.User, error) {
				return admin, nil
			},
			getUserByEmail: func(_ context.Context, email string) (repository.User, error) {
				if email != other.Email {
					t.Fatalf("looked up %q, want %q", email, other.Email)
				}
				return other, nil
			},
			deleteUser: func(_ context.Context, id uuid.UUID) (int64, error) {
				deleted = id
				return 1, nil
			},
		}

		rec := httptest.NewRecorder()
		newTestController(store).userHandler(rec, authRequestWithBody(t, http.MethodDelete, "/v1/user",
			admin.ID.String(), "application/json", `{"email":"`+other.Email+`"}`))

		if rec.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204", rec.Code)
		}
		if deleted != other.ID {
			t.Fatalf("deleted %s, want %s", deleted, other.ID)
		}
	})
}

func TestDeleteUserIDTakesPrecedenceOverEmail(t *testing.T) {
	admin := activeUser(true)
	other := repository.User{ID: uuid.New(), Email: "other@example.com", Active: true}
	deleted := uuid.Nil
	store := fakeStore{
		getUserById: func(context.Context, uuid.UUID) (repository.User, error) {
			return admin, nil
		},
		getUserByEmail: func(context.Context, string) (repository.User, error) {
			t.Fatal("the email was resolved although the request carried an id")
			return repository.User{}, nil
		},
		deleteUser: func(_ context.Context, id uuid.UUID) (int64, error) {
			deleted = id
			return 1, nil
		},
	}
	c := newTestController(store)

	rec := httptest.NewRecorder()
	c.userHandler(rec, authRequestWithBody(t, http.MethodDelete, "/v1/user", admin.ID.String(), "application/json",
		`{"id":"`+other.ID.String()+`","email":"nobody@example.com"}`))

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
	if deleted != other.ID {
		t.Fatalf("deleted %s, want the id %s", deleted, other.ID)
	}
}

func TestDeleteUserMissingAccount(t *testing.T) {
	admin := activeUser(true)
	tests := []struct {
		name    string
		deleted int64
		err     error
		want    int
	}{
		{"no such account", 0, nil, http.StatusNotFound},
		{"store failure", 0, errors.New("connection reset"), http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := fakeStore{
				getUserById: func(context.Context, uuid.UUID) (repository.User, error) {
					return admin, nil
				},
				deleteUser: func(context.Context, uuid.UUID) (int64, error) {
					return tt.deleted, tt.err
				},
			}

			rec := httptest.NewRecorder()
			newTestController(store).userHandler(rec, authRequestWithBody(t, http.MethodDelete, "/v1/user",
				admin.ID.String(), "application/json", `{"id":"`+uuid.New().String()+`"}`))

			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d", rec.Code, tt.want)
			}
		})
	}
}

func TestDeleteUserBadRequests(t *testing.T) {
	caller := activeUser(false)
	c := newTestController(fakeStore{
		getUserById: func(context.Context, uuid.UUID) (repository.User, error) {
			return caller, nil
		},
	})

	tests := []struct {
		name        string
		contentType string
		body        string
	}{
		{"bad content type", "text/plain", `{"id":"` + caller.ID.String() + `"}`},
		{"malformed json", "application/json", `{`},
		{"neither id nor email", "application/json", `{}`},
		{"unparseable id", "application/json", `{"id":"not-a-uuid"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			c.userHandler(rec, authRequestWithBody(t, http.MethodDelete, "/v1/user", caller.ID.String(),
				tt.contentType, tt.body))

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", rec.Code)
			}
		})
	}
}

func TestUpdateUserChangesPassword(t *testing.T) {
	oldSalt := []byte("0123456789abcdef")
	caller := activeUser(false)
	caller.HashedPassword = argon2.HashPassword("oldpassword", oldSalt)
	caller.Salt = oldSalt

	var stored repository.UpdateUserParams
	store := fakeStore{
		getUserById: func(context.Context, uuid.UUID) (repository.User, error) {
			return caller, nil
		},
		updateUser: func(_ context.Context, arg repository.UpdateUserParams) (repository.User, error) {
			stored = arg
			return repository.User{ID: arg.ID, Email: arg.Email, Active: arg.Active, Admin: arg.Admin}, nil
		},
	}
	c := newTestController(store)

	rec := httptest.NewRecorder()
	c.userHandler(rec, authRequestWithBody(t, http.MethodPatch, "/v1/user", caller.ID.String(), "application/json",
		`{"id":"`+caller.ID.String()+`","password":"newpassword"}`))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if err := argon2.Validate("newpassword", stored.HashedPassword, stored.Salt); err != nil {
		t.Fatalf("stored credential does not validate the new password: %v", err)
	}
	if bytes.Equal(stored.Salt, oldSalt) {
		t.Fatal("password change reused the stored salt")
	}
	// The update rewrites the whole row, so the fields the request did not
	// mention have to come back unchanged.
	if stored.Email != caller.Email || !stored.Active || stored.Admin {
		t.Fatalf("untouched fields changed: %+v", stored)
	}
	if bytes.Contains(rec.Body.Bytes(), stored.HashedPassword) || bytes.Contains(rec.Body.Bytes(), stored.Salt) {
		t.Fatal("response leaked stored password material")
	}
}

func TestUpdateUserChangesEmailKeepsCredential(t *testing.T) {
	salt := []byte("0123456789abcdef")
	caller := activeUser(false)
	caller.HashedPassword = argon2.HashPassword("oldpassword", salt)
	caller.Salt = salt

	var stored repository.UpdateUserParams
	store := fakeStore{
		getUserById: func(context.Context, uuid.UUID) (repository.User, error) {
			return caller, nil
		},
		updateUser: func(_ context.Context, arg repository.UpdateUserParams) (repository.User, error) {
			stored = arg
			return repository.User{ID: arg.ID, Email: arg.Email, Active: arg.Active, Admin: arg.Admin}, nil
		},
	}
	c := newTestController(store)

	rec := httptest.NewRecorder()
	c.userHandler(rec, authRequestWithBody(t, http.MethodPatch, "/v1/user", caller.ID.String(), "application/json",
		`{"id":"`+caller.ID.String()+`","email":"new@example.com"}`))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if stored.Email != "new@example.com" {
		t.Fatalf("email = %q, want new@example.com", stored.Email)
	}
	if !bytes.Equal(stored.Salt, salt) {
		t.Fatal("email change replaced the stored salt")
	}
	if err := argon2.Validate("oldpassword", stored.HashedPassword, stored.Salt); err != nil {
		t.Fatalf("email change disturbed the stored credential: %v", err)
	}

	var got User
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.Email != "new@example.com" || got.ID != caller.ID {
		t.Fatalf("response = %+v, want the updated account", got)
	}
}

func TestUpdateUserNonAdminMayNotWritePrivilegedFields(t *testing.T) {
	caller := activeUser(false)
	other := repository.User{ID: uuid.New(), Email: "other@example.com", Active: true}

	store := fakeStore{
		getUserById: func(_ context.Context, id uuid.UUID) (repository.User, error) {
			if id == other.ID {
				return other, nil
			}
			return caller, nil
		},
		updateUser: func(context.Context, repository.UpdateUserParams) (repository.User, error) {
			t.Fatal("store was asked to update")
			return repository.User{}, nil
		},
	}
	c := newTestController(store)

	tests := []struct {
		name string
		body string
	}{
		{"self deactivation", `{"id":"` + caller.ID.String() + `","active":false}`},
		{"self promotion", `{"id":"` + caller.ID.String() + `","admin":true}`},
		{"self demotion", `{"id":"` + caller.ID.String() + `","admin":false}`},
		{"another account", `{"id":"` + other.ID.String() + `","email":"mine@example.com"}`},
		{"unknown account", `{"id":"` + uuid.New().String() + `","email":"mine@example.com"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			c.userHandler(rec, authRequestWithBody(t, http.MethodPatch, "/v1/user", caller.ID.String(),
				"application/json", tt.body))

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", rec.Code)
			}
			if rec.Body.Len() != 0 {
				t.Fatalf("denied response leaked a body: %q", rec.Body.String())
			}
		})
	}
}

func TestUpdateUserAdminMaySetPrivilegedFields(t *testing.T) {
	admin := activeUser(true)
	other := repository.User{ID: uuid.New(), Email: "other@example.com", Active: false}

	var stored repository.UpdateUserParams
	store := fakeStore{
		getUserById: func(_ context.Context, id uuid.UUID) (repository.User, error) {
			if id == other.ID {
				return other, nil
			}
			return admin, nil
		},
		updateUser: func(_ context.Context, arg repository.UpdateUserParams) (repository.User, error) {
			stored = arg
			return repository.User{ID: arg.ID, Email: arg.Email, Active: arg.Active, Admin: arg.Admin}, nil
		},
	}
	c := newTestController(store)

	rec := httptest.NewRecorder()
	c.userHandler(rec, authRequestWithBody(t, http.MethodPatch, "/v1/user", admin.ID.String(), "application/json",
		`{"id":"`+other.ID.String()+`","active":true,"admin":true}`))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !stored.Active || !stored.Admin {
		t.Fatalf("active = %v, admin = %v, want both true", stored.Active, stored.Admin)
	}
	if stored.Email != other.Email {
		t.Fatalf("email = %q, want the stored %q", stored.Email, other.Email)
	}
}

func TestUpdateUserStoreErrors(t *testing.T) {
	admin := activeUser(true)
	target := uuid.New()

	tests := []struct {
		name      string
		getErr    error
		updateErr error
		want      int
	}{
		{"unknown account", pgx.ErrNoRows, nil, http.StatusNotFound},
		{"duplicate email", nil, &pgconn.PgError{Code: "23505"}, http.StatusConflict},
		{"store failure", nil, errors.New("connection reset"), http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := fakeStore{
				getUserById: func(_ context.Context, id uuid.UUID) (repository.User, error) {
					if id != target {
						// requireSession resolves the caller first.
						return admin, nil
					}
					if tt.getErr != nil {
						return repository.User{}, tt.getErr
					}
					return repository.User{ID: target, Email: "other@example.com", Active: true}, nil
				},
				updateUser: func(context.Context, repository.UpdateUserParams) (repository.User, error) {
					return repository.User{}, tt.updateErr
				},
			}

			rec := httptest.NewRecorder()
			newTestController(store).userHandler(rec, authRequestWithBody(t, http.MethodPatch, "/v1/user",
				admin.ID.String(), "application/json",
				`{"id":"`+target.String()+`","email":"taken@example.com"}`))

			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d", rec.Code, tt.want)
			}
		})
	}
}

func TestUpdateUserBadRequests(t *testing.T) {
	caller := activeUser(false)
	c := newTestController(fakeStore{
		getUserById: func(context.Context, uuid.UUID) (repository.User, error) {
			return caller, nil
		},
	})

	tests := []struct {
		name        string
		contentType string
		body        string
	}{
		{"bad content type", "text/plain", `{"id":"` + caller.ID.String() + `"}`},
		{"malformed json", "application/json", `{`},
		{"missing id", "application/json", `{"password":"newpassword"}`},
		{"unparseable id", "application/json", `{"id":"not-a-uuid"}`},
		{"empty email", "application/json", `{"id":"` + caller.ID.String() + `","email":""}`},
		{"short password", "application/json", `{"id":"` + caller.ID.String() + `","password":"short"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			c.userHandler(rec, authRequestWithBody(t, http.MethodPatch, "/v1/user", caller.ID.String(),
				tt.contentType, tt.body))

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", rec.Code)
			}
		})
	}
}
