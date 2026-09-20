package rest

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ccarlfjord/argon2"
	"github.com/ccarlfjord/user/internal/repository"
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

func newTestController(store userStore) *controller {
	salt := argon2.GenerateSalt()
	return &controller{
		db:           store,
		sessionToken: []byte("test-signing-key"),
		dummyHash:    argon2.HashPassword("", salt),
		dummySalt:    salt,
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
	store := fakeStore{
		getUserByEmail: func(context.Context, string) (repository.User, error) {
			return repository.User{}, pgx.ErrNoRows
		},
		createUser: func(_ context.Context, arg repository.CreateUserParams) (repository.User, error) {
			created = true
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

func TestGetUserByIDNotFound(t *testing.T) {
	store := fakeStore{
		getUserById: func(context.Context, uuid.UUID) (repository.User, error) {
			return repository.User{}, pgx.ErrNoRows
		},
	}
	c := newTestController(store)

	missing := httptest.NewRecorder()
	missingReq := httptest.NewRequest(http.MethodGet, "/v1/user/"+uuid.New().String(), nil)
	missingReq.SetPathValue("id", uuid.New().String())
	c.getUserByID(missing, missingReq)

	invalid := doRequest(c.getUserByID, http.MethodGet, "/v1/user/not-a-uuid", "", "")

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
