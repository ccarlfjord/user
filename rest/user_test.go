package rest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
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
