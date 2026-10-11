package rest

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
	getClientById                    func(context.Context, string) (repository.OauthClient, error)
	createClient                     func(context.Context, repository.CreateClientParams) (repository.OauthClient, error)
	createRegistrationToken          func(context.Context, repository.CreateRegistrationTokenParams) error
	consumeRegistrationToken         func(context.Context, []byte) (repository.RegistrationToken, error)
	deleteExpiredRegistrationTokens  func(context.Context) (int64, error)
	createAuthorizationCode          func(context.Context, repository.CreateAuthorizationCodeParams) error
	consumeAuthorizationCode         func(context.Context, []byte) (repository.AuthorizationCode, error)
	deleteExpiredAuthorizationCodes  func(context.Context) (int64, error)
	getUserByEmail                   func(context.Context, string) (repository.User, error)
	getUserById                      func(context.Context, uuid.UUID) (repository.User, error)
	createUser                       func(context.Context, repository.CreateUserParams) (repository.User, error)
	createVerificationToken          func(context.Context, repository.CreateVerificationTokenParams) error
	getVerificationToken             func(context.Context, []byte) (repository.VerificationToken, error)
	deleteVerificationTokensForUser  func(context.Context, uuid.UUID) error
	activateUser                     func(context.Context, uuid.UUID) error
	updateUser                       func(context.Context, repository.UpdateUserParams) (repository.User, error)
	deleteUser                       func(context.Context, uuid.UUID) (int64, error)
	createRefreshToken               func(context.Context, repository.CreateRefreshTokenParams) error
	consumeRefreshToken              func(context.Context, []byte) (repository.RefreshToken, error)
	deleteExpiredRefreshTokens       func(context.Context) (int64, error)
	deleteExpiredVerificationTokens  func(context.Context) (int64, error)
	createPasswordResetToken         func(context.Context, repository.CreatePasswordResetTokenParams) error
	consumePasswordResetToken        func(context.Context, []byte) (repository.PasswordResetToken, error)
	deletePasswordResetTokensForUser func(context.Context, uuid.UUID) error
	deleteExpiredPasswordResetTokens func(context.Context) (int64, error)
	getUsers                         func(context.Context) ([]repository.User, error)
	searchUsers                      func(context.Context, string) ([]repository.User, error)
}

func (f fakeStore) GetClientById(ctx context.Context, clientID string) (repository.OauthClient, error) {
	if f.getClientById == nil {
		return repository.OauthClient{}, pgx.ErrNoRows
	}
	return f.getClientById(ctx, clientID)
}

func (f fakeStore) CreateClient(ctx context.Context, arg repository.CreateClientParams) (repository.OauthClient, error) {
	return f.createClient(ctx, arg)
}

func (f fakeStore) CreateRegistrationToken(ctx context.Context, arg repository.CreateRegistrationTokenParams) error {
	return f.createRegistrationToken(ctx, arg)
}

func (f fakeStore) ConsumeRegistrationToken(ctx context.Context, tokenHash []byte) (repository.RegistrationToken, error) {
	if f.consumeRegistrationToken == nil {
		return repository.RegistrationToken{}, pgx.ErrNoRows
	}
	return f.consumeRegistrationToken(ctx, tokenHash)
}

func (f fakeStore) DeleteExpiredRegistrationTokens(ctx context.Context) (int64, error) {
	return f.deleteExpiredRegistrationTokens(ctx)
}

func (f fakeStore) CreateAuthorizationCode(ctx context.Context, arg repository.CreateAuthorizationCodeParams) error {
	return f.createAuthorizationCode(ctx, arg)
}

func (f fakeStore) ConsumeAuthorizationCode(ctx context.Context, codeHash []byte) (repository.AuthorizationCode, error) {
	return f.consumeAuthorizationCode(ctx, codeHash)
}

func (f fakeStore) DeleteExpiredAuthorizationCodes(ctx context.Context) (int64, error) {
	return f.deleteExpiredAuthorizationCodes(ctx)
}

func (f fakeStore) GetUserByEmail(ctx context.Context, email string) (repository.User, error) {
	return f.getUserByEmail(ctx, email)
}

func (f fakeStore) GetUserById(ctx context.Context, id uuid.UUID) (repository.User, error) {
	if f.getUserById == nil {
		return repository.User{}, pgx.ErrNoRows
	}
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

func (f fakeStore) CreateRefreshToken(ctx context.Context, arg repository.CreateRefreshTokenParams) error {
	return f.createRefreshToken(ctx, arg)
}

func (f fakeStore) ConsumeRefreshToken(ctx context.Context, tokenHash []byte) (repository.RefreshToken, error) {
	return f.consumeRefreshToken(ctx, tokenHash)
}

func (f fakeStore) DeleteExpiredRefreshTokens(ctx context.Context) (int64, error) {
	return f.deleteExpiredRefreshTokens(ctx)
}

func (f fakeStore) DeleteExpiredVerificationTokens(ctx context.Context) (int64, error) {
	return f.deleteExpiredVerificationTokens(ctx)
}

func (f fakeStore) CreatePasswordResetToken(ctx context.Context, arg repository.CreatePasswordResetTokenParams) error {
	return f.createPasswordResetToken(ctx, arg)
}

func (f fakeStore) ConsumePasswordResetToken(ctx context.Context, tokenHash []byte) (repository.PasswordResetToken, error) {
	return f.consumePasswordResetToken(ctx, tokenHash)
}

func (f fakeStore) DeletePasswordResetTokensForUser(ctx context.Context, userID uuid.UUID) error {
	return f.deletePasswordResetTokensForUser(ctx, userID)
}

func (f fakeStore) DeleteExpiredPasswordResetTokens(ctx context.Context) (int64, error) {
	return f.deleteExpiredPasswordResetTokens(ctx)
}

func (f fakeStore) GetUsers(ctx context.Context) ([]repository.User, error) {
	return f.getUsers(ctx)
}

func (f fakeStore) SearchUsers(ctx context.Context, query string) ([]repository.User, error) {
	return f.searchUsers(ctx, query)
}

// testIssuer is the OIDC issuer identifier newTestController advertises.
const testIssuer = "https://issuer.example.com"

// testSigningKey is the ES256 key every test controller signs and validates
// with. It is generated once: the key is immutable, and a per-test key would
// only make the signing helpers more awkward.
var testSigningKey = mustGenerateTestKey()

func mustGenerateTestKey() *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return key
}

func newTestController(store userStore) *controller {
	return &controller{
		db:      store,
		oidcKey: testSigningKey,
		issuer:  testIssuer,
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
		{"whitespace-only email", "application/json", `{"email":"   ","username":"ab","password":"password1"}`},
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

func TestCreateUserNormalizesEmail(t *testing.T) {
	var lookedUp, stored string
	store := fakeStore{
		getUserByEmail: func(_ context.Context, email string) (repository.User, error) {
			lookedUp = email
			return repository.User{}, pgx.ErrNoRows
		},
		createUser: func(_ context.Context, arg repository.CreateUserParams) (repository.User, error) {
			stored = arg.Email
			return repository.User{ID: arg.ID, Email: arg.Email, Active: arg.Active}, nil
		},
		createVerificationToken: func(context.Context, repository.CreateVerificationTokenParams) error {
			return nil
		},
	}
	c := newTestController(store)

	rec := doRequest(c.createUser, http.MethodPost, "/v1/user", "application/json",
		`{"email":"  A@B.Com ","password":"password1"}`)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201", rec.Code)
	}
	if lookedUp != "a@b.com" {
		t.Fatalf("lookup email = %q, want a@b.com", lookedUp)
	}
	if stored != "a@b.com" {
		t.Fatalf("stored email = %q, want a@b.com", stored)
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

func TestLoginNormalizesEmail(t *testing.T) {
	salt := []byte("0123456789abcdef")
	user := repository.User{
		ID:             uuid.New(),
		Email:          "known@example.com",
		HashedPassword: argon2.HashPassword("rightpassword", salt),
		Salt:           salt,
		Active:         true,
	}

	var lookedUp string
	store := fakeStore{
		getUserByEmail: func(_ context.Context, email string) (repository.User, error) {
			lookedUp = email
			return user, nil
		},
		createRefreshToken: func(context.Context, repository.CreateRefreshTokenParams) error {
			return nil
		},
	}
	c := newTestController(store)

	rec := doRequest(c.login, http.MethodPost, "/v1/login", "application/json",
		`{"email":"Known@Example.COM","password":"rightpassword"}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if lookedUp != "known@example.com" {
		t.Fatalf("lookup email = %q, want known@example.com", lookedUp)
	}
}

func TestLoginReturnsSessionAndRefreshToken(t *testing.T) {
	salt := []byte("0123456789abcdef")
	user := repository.User{
		ID:             uuid.New(),
		Email:          "known@example.com",
		HashedPassword: argon2.HashPassword("rightpassword", salt),
		Salt:           salt,
		Active:         true,
		SessionEpoch:   4,
	}

	var stored repository.CreateRefreshTokenParams
	store := fakeStore{
		getUserByEmail: func(context.Context, string) (repository.User, error) {
			return user, nil
		},
		createRefreshToken: func(_ context.Context, arg repository.CreateRefreshTokenParams) error {
			stored = arg
			return nil
		},
	}
	c := newTestController(store)

	rec := doRequest(c.login, http.MethodPost, "/v1/login", "application/json",
		`{"email":"known@example.com","password":"rightpassword"}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp SessionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Session == "" {
		t.Fatal("expected a session token")
	}
	if resp.Refresh == "" {
		t.Fatal("expected a refresh token")
	}
	// The value handed to the client has to be the one whose hash was stored,
	// at the account's current generation and with the refresh lifetime.
	if !bytes.Equal(stored.TokenHash, hashToken(resp.Refresh)) {
		t.Fatal("stored hash does not match the returned refresh token")
	}
	if stored.UserID != user.ID || stored.SessionEpoch != user.SessionEpoch {
		t.Fatalf("stored refresh token names %s at epoch %d, want %s at %d",
			stored.UserID, stored.SessionEpoch, user.ID, user.SessionEpoch)
	}
	if !stored.ExpiresAt.After(time.Now().Add(refreshTokenTTL - time.Hour)) {
		t.Fatalf("refresh token expires %s, want about %s out", stored.ExpiresAt, refreshTokenTTL)
	}
}

func TestRefreshRotatesTokenAndMintsSession(t *testing.T) {
	user := activeUser(false)
	user.SessionEpoch = 2
	old := "refresh-token-from-the-old-session"

	var consumed []byte
	var created repository.CreateRefreshTokenParams
	store := fakeStore{
		consumeRefreshToken: func(_ context.Context, tokenHash []byte) (repository.RefreshToken, error) {
			if !bytes.Equal(tokenHash, hashToken(old)) {
				t.Fatalf("consumed hash %x, want the presented token's", tokenHash)
			}
			consumed = tokenHash
			return repository.RefreshToken{
				TokenHash:    tokenHash,
				UserID:       user.ID,
				SessionEpoch: user.SessionEpoch,
				ExpiresAt:    time.Now().Add(time.Hour),
			}, nil
		},
		getUserById: func(context.Context, uuid.UUID) (repository.User, error) {
			return user, nil
		},
		createRefreshToken: func(_ context.Context, arg repository.CreateRefreshTokenParams) error {
			created = arg
			return nil
		},
	}
	c := newTestController(store)

	rec := doRequest(c.refresh, http.MethodPost, "/v1/refresh", "application/json",
		`{"refresh":"`+old+`"}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var resp SessionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Session == "" || resp.Refresh == "" {
		t.Fatalf("response = %+v, want a session and a refresh token", resp)
	}
	if !bytes.Equal(consumed, hashToken(old)) {
		t.Fatal("the presented refresh token was not consumed")
	}
	if !bytes.Equal(created.TokenHash, hashToken(resp.Refresh)) {
		t.Fatal("the returned refresh token's hash was not the one stored")
	}
	if bytes.Equal(created.TokenHash, hashToken(old)) {
		t.Fatal("rotation handed back the token it just consumed")
	}
	if created.UserID != user.ID || created.SessionEpoch != user.SessionEpoch {
		t.Fatalf("rotated token names %s at epoch %d, want %s at %d",
			created.UserID, created.SessionEpoch, user.ID, user.SessionEpoch)
	}

	// The session minted from the old refresh token has to be usable as-is.
	claims := new(sessionClaims)
	if _, err := jwt.ParseWithClaims(resp.Session, claims, c.sessionKey,
		jwt.WithValidMethods([]string{jwt.SigningMethodES256.Alg()}),
		jwt.WithIssuer(sessionIssuer),
		jwt.WithAudience(sessionAudience),
	); err != nil {
		t.Fatalf("refreshed session does not parse: %v", err)
	}
	if claims.SessionEpoch == nil || *claims.SessionEpoch != user.SessionEpoch {
		t.Fatalf("refreshed session epoch = %v, want %d", claims.SessionEpoch, user.SessionEpoch)
	}
}

// A refresh token minted before a password change must stop working, so that
// resetting a password really does end every session in circulation.
func TestPasswordChangeRetiresRefreshTokens(t *testing.T) {
	salt := []byte("0123456789abcdef")
	caller := activeUser(false)
	caller.HashedPassword = argon2.HashPassword("oldpassword", salt)
	caller.Salt = salt

	old := "refresh-token-minted-before-the-change"
	current := caller
	store := fakeStore{
		getUserById: func(context.Context, uuid.UUID) (repository.User, error) {
			return current, nil
		},
		updateUser: func(_ context.Context, arg repository.UpdateUserParams) (repository.User, error) {
			current = repository.User{
				ID:             arg.ID,
				Email:          arg.Email,
				HashedPassword: arg.HashedPassword,
				Salt:           arg.Salt,
				Active:         arg.Active,
				Admin:          arg.Admin,
				SessionEpoch:   arg.SessionEpoch,
			}
			return current, nil
		},
		consumeRefreshToken: func(context.Context, []byte) (repository.RefreshToken, error) {
			return repository.RefreshToken{
				TokenHash:    hashToken(old),
				UserID:       caller.ID,
				SessionEpoch: caller.SessionEpoch,
				ExpiresAt:    time.Now().Add(time.Hour),
			}, nil
		},
		createRefreshToken: func(context.Context, repository.CreateRefreshTokenParams) error {
			t.Fatal("a retired refresh token must not mint a replacement")
			return nil
		},
	}
	c := newTestController(store)

	req := authRequestWithBody(t, http.MethodPatch, "/v1/user", caller, "application/json",
		`{"id":"`+caller.ID.String()+`","password":"newpassword"}`)
	rec := httptest.NewRecorder()
	c.requireSession(c.updateUser)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("password change status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if current.SessionEpoch != caller.SessionEpoch+1 {
		t.Fatalf("session_epoch = %d, want %d", current.SessionEpoch, caller.SessionEpoch+1)
	}

	rec = doRequest(c.refresh, http.MethodPost, "/v1/refresh", "application/json",
		`{"refresh":"`+old+`"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("refresh status = %d, want 401", rec.Code)
	}
}

func TestRefreshRejectsInvalidTokens(t *testing.T) {
	user := activeUser(false)

	// Each case builds a store around one stored row, or none. Spending the
	// row is the lookup, so the row is consumed either way; what must not
	// happen is a replacement being minted.
	tests := []struct {
		name  string
		store func(t *testing.T) fakeStore
	}{
		{
			"unknown token",
			func(t *testing.T) fakeStore {
				return fakeStore{
					consumeRefreshToken: func(context.Context, []byte) (repository.RefreshToken, error) {
						return repository.RefreshToken{}, pgx.ErrNoRows
					},
				}
			},
		},
		{
			"expired token",
			func(t *testing.T) fakeStore {
				return fakeStore{
					consumeRefreshToken: func(context.Context, []byte) (repository.RefreshToken, error) {
						return repository.RefreshToken{
							UserID:       user.ID,
							SessionEpoch: user.SessionEpoch,
							ExpiresAt:    time.Now().Add(-time.Minute),
						}, nil
					},
					getUserById: func(context.Context, uuid.UUID) (repository.User, error) {
						t.Fatal("expired token must be refused before the account is read")
						return user, nil
					},
				}
			},
		},
		{
			"retired session generation",
			func(t *testing.T) fakeStore {
				return fakeStore{
					consumeRefreshToken: func(context.Context, []byte) (repository.RefreshToken, error) {
						return repository.RefreshToken{
							UserID:       user.ID,
							SessionEpoch: user.SessionEpoch + 1,
							ExpiresAt:    time.Now().Add(time.Hour),
						}, nil
					},
					getUserById: func(context.Context, uuid.UUID) (repository.User, error) {
						return user, nil
					},
					createRefreshToken: func(context.Context, repository.CreateRefreshTokenParams) error {
						t.Fatal("a token from a retired generation must not mint a replacement")
						return nil
					},
				}
			},
		},
		{
			"inactive account",
			func(t *testing.T) fakeStore {
				inactive := user
				inactive.Active = false
				return fakeStore{
					consumeRefreshToken: func(context.Context, []byte) (repository.RefreshToken, error) {
						return repository.RefreshToken{
							UserID:       user.ID,
							SessionEpoch: user.SessionEpoch,
							ExpiresAt:    time.Now().Add(time.Hour),
						}, nil
					},
					getUserById: func(context.Context, uuid.UUID) (repository.User, error) {
						return inactive, nil
					},
					createRefreshToken: func(context.Context, repository.CreateRefreshTokenParams) error {
						t.Fatal("an inactive account must not be refreshed")
						return nil
					},
				}
			},
		},
		{
			"account is gone",
			func(t *testing.T) fakeStore {
				return fakeStore{
					consumeRefreshToken: func(context.Context, []byte) (repository.RefreshToken, error) {
						return repository.RefreshToken{
							UserID:       user.ID,
							SessionEpoch: user.SessionEpoch,
							ExpiresAt:    time.Now().Add(time.Hour),
						}, nil
					},
					getUserById: func(context.Context, uuid.UUID) (repository.User, error) {
						return repository.User{}, pgx.ErrNoRows
					},
					createRefreshToken: func(context.Context, repository.CreateRefreshTokenParams) error {
						t.Fatal("a token for a deleted account must not mint a replacement")
						return nil
					},
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestController(tt.store(t))

			rec := doRequest(c.refresh, http.MethodPost, "/v1/refresh", "application/json",
				`{"refresh":"some-token"}`)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", rec.Code)
			}
		})
	}
}

func TestRefreshBadRequests(t *testing.T) {
	c := newTestController(fakeStore{
		consumeRefreshToken: func(context.Context, []byte) (repository.RefreshToken, error) {
			t.Fatal("a malformed request must not reach the store")
			return repository.RefreshToken{}, nil
		},
	})

	tests := []struct {
		name        string
		method      string
		contentType string
		body        string
		want        int
	}{
		{"wrong method", http.MethodGet, "application/json", "", http.StatusMethodNotAllowed},
		{"missing content type", http.MethodPost, "", `{"refresh":"x"}`, http.StatusBadRequest},
		{"malformed body", http.MethodPost, "application/json", `{`, http.StatusBadRequest},
		{"empty refresh", http.MethodPost, "application/json", `{"refresh":""}`, http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/v1/refresh", strings.NewReader(tt.body))
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}
			rec := httptest.NewRecorder()
			c.refreshHandler(rec, req)
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d", rec.Code, tt.want)
			}
		})
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
	missingReq := authRequest(t, http.MethodGet, "/v1/user/"+uuid.New().String(), admin)
	missingReq.SetPathValue("id", uuid.New().String())
	c.userByIDHandler(missing, missingReq)

	// Unparseable id: rejected before any lookup or authorization.
	invalidReq := authRequest(t, http.MethodGet, "/v1/user/not-a-uuid", admin)
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

// mintedClaims is the claim set login mints for an account at session epoch
// epoch. Tests start from it and vary one field at a time, so a rejection
// isolates the claim under test.
func mintedClaims(sub string, epoch int32) sessionClaims {
	now := time.Now()
	return sessionClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    sessionIssuer,
			Subject:   sub,
			Audience:  jwt.ClaimStrings{sessionAudience},
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
		SessionEpoch: &epoch,
	}
}

// signClaims signs an arbitrary claim set with key, naming the key in the
// token header the way mintSession does.
func signClaims(t *testing.T, key *ecdsa.PrivateKey, claims sessionClaims) string {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = keyID(&key.PublicKey)
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign session: %v", err)
	}
	return signed
}

// authRequest returns a request carrying a session token for user, minted at
// that account's current session epoch.
func authRequest(t *testing.T, method, target string, user repository.User) *http.Request {
	t.Helper()

	req := httptest.NewRequest(method, target, nil)
	req.Header.Set("Authorization", "Bearer "+signClaims(t, testSigningKey, mintedClaims(user.ID.String(), user.SessionEpoch)))
	return req
}

// authRequestWithBody returns an authenticated request carrying a body.
func authRequestWithBody(t *testing.T, method, target string, user repository.User, contentType, body string) *http.Request {
	t.Helper()

	req := authRequest(t, method, target, user)
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
	// The store resolves any subject, so a token that survives parsing and the
	// claim checks reaches the handler and the test fails on that instead of on
	// a nil fake.
	account := activeUser(false)
	c := newTestController(fakeStore{
		getUserById: func(context.Context, uuid.UUID) (repository.User, error) {
			return account, nil
		},
	})
	key := testSigningKey
	otherKey := mustGenerateTestKey()
	sub := uuid.New().String()

	// vary returns the expected claim set with one field changed.
	vary := func(change func(*sessionClaims)) sessionClaims {
		claims := mintedClaims(sub, 0)
		change(&claims)
		return claims
	}

	// A token signed with a different algorithm and a key the caller controls:
	// verification is pinned to ES256, so an HMAC token is refused before the
	// key function is even consulted.
	hs256 := func() string {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, mintedClaims(sub, 0))
		signed, err := token.SignedString([]byte("attacker-controlled-key"))
		if err != nil {
			t.Fatalf("sign hs256 token: %v", err)
		}
		return signed
	}()

	none := func() string {
		token := jwt.NewWithClaims(jwt.SigningMethodNone, mintedClaims(sub, 0))
		signed, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
		if err != nil {
			t.Fatalf("sign none token: %v", err)
		}
		return signed
	}()

	// Missing and unknown key ids: the verifier selects by kid, so neither may
	// verify even though the signature itself is valid.
	noKid := func() string {
		token := jwt.NewWithClaims(jwt.SigningMethodES256, mintedClaims(sub, 0))
		signed, err := token.SignedString(key)
		if err != nil {
			t.Fatalf("sign token without kid: %v", err)
		}
		return signed
	}()
	unknownKid := func() string {
		token := jwt.NewWithClaims(jwt.SigningMethodES256, mintedClaims(sub, 0))
		token.Header["kid"] = "not-the-current-key"
		signed, err := token.SignedString(key)
		if err != nil {
			t.Fatalf("sign token with unknown kid: %v", err)
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
		{"wrong scheme", "Basic " + signClaims(t, key, mintedClaims(sub, 0))},
		{"malformed token", "Bearer not-a-jwt"},
		{"signed with another key", "Bearer " + signClaims(t, otherKey, mintedClaims(sub, 0))},
		{"expired", "Bearer " + signClaims(t, key, vary(func(c *sessionClaims) {
			c.ExpiresAt = jwt.NewNumericDate(expired)
		}))},
		{"no expiry", "Bearer " + signClaims(t, key, vary(func(c *sessionClaims) {
			c.ExpiresAt = nil
		}))},
		{"wrong issuer", "Bearer " + signClaims(t, key, vary(func(c *sessionClaims) {
			c.Issuer = "somewhere-else"
		}))},
		{"no issuer", "Bearer " + signClaims(t, key, vary(func(c *sessionClaims) {
			c.Issuer = ""
		}))},
		{"wrong audience", "Bearer " + signClaims(t, key, vary(func(c *sessionClaims) {
			c.Audience = jwt.ClaimStrings{"other-api"}
		}))},
		{"no audience", "Bearer " + signClaims(t, key, vary(func(c *sessionClaims) {
			c.Audience = nil
		}))},
		{"issued in the future", "Bearer " + signClaims(t, key, vary(func(c *sessionClaims) {
			c.IssuedAt = jwt.NewNumericDate(time.Now().Add(time.Hour))
		}))},
		{"no session epoch", "Bearer " + signClaims(t, key, vary(func(c *sessionClaims) {
			c.SessionEpoch = nil
		}))},
		{"hs256", "Bearer " + hs256},
		{"missing kid", "Bearer " + noKid},
		{"unknown kid", "Bearer " + unknownKid},
		{"alg none", "Bearer " + none},
		{"empty subject", "Bearer " + signClaims(t, key, vary(func(c *sessionClaims) {
			c.Subject = ""
		}))},
		{"subject is not a user id", "Bearer " + signClaims(t, key, vary(func(c *sessionClaims) {
			c.Subject = "not-a-uuid"
		}))},
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
	handler(rec, authRequest(t, http.MethodGet, "/v1/user/"+caller.ID.String(), caller))

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
			handler(rec, authRequest(t, http.MethodGet, "/v1/user/"+caller.ID.String(), caller))

			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d", rec.Code, tt.want)
			}
			if called {
				t.Fatal("handler ran for an unresolvable caller")
			}
		})
	}
}

func TestRequireSessionHonoursSessionEpoch(t *testing.T) {
	caller := activeUser(false)
	caller.SessionEpoch = 2

	tests := []struct {
		name   string
		claims sessionClaims
		want   int
	}{
		{"matching epoch", mintedClaims(caller.ID.String(), 2), http.StatusOK},
		{"retired by a password change", mintedClaims(caller.ID.String(), 1), http.StatusUnauthorized},
		{"epoch ahead of the stored one", mintedClaims(caller.ID.String(), 3), http.StatusUnauthorized},
		{"claim omitted", func() sessionClaims {
			claims := mintedClaims(caller.ID.String(), 2)
			claims.SessionEpoch = nil
			return claims
		}(), http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestController(fakeStore{
				getUserById: func(context.Context, uuid.UUID) (repository.User, error) {
					return caller, nil
				},
			})

			called := false
			handler := c.requireSession(func(w http.ResponseWriter, _ *http.Request) {
				called = true
				w.WriteHeader(http.StatusOK)
			})

			req := httptest.NewRequest(http.MethodGet, "/v1/user/"+caller.ID.String(), nil)
			req.Header.Set("Authorization", "Bearer "+signClaims(t, testSigningKey, tt.claims))
			rec := httptest.NewRecorder()
			handler(rec, req)

			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d", rec.Code, tt.want)
			}
			if called != (tt.want == http.StatusOK) {
				t.Fatalf("handler ran = %v, want %v", called, tt.want == http.StatusOK)
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
		req := authRequest(t, http.MethodGet, "/v1/user/"+caller.ID.String(), caller)
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
			req := authRequest(t, http.MethodGet, "/v1/user/"+tt.target.String(), tt.caller)
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
	c.userHandler(rec, authRequest(t, http.MethodGet, "/v1/user", caller))

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
			"/v1/user?email="+caller.Email, caller))

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
			"/v1/user?email="+other.Email, caller))

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
			"/v1/user?email="+other.Email, admin))

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
					"/v1/user?email="+other.Email, admin))

				if rec.Code != tt.want {
					t.Fatalf("status = %d, want %d", rec.Code, tt.want)
				}
			})
		}
	})
}

func TestResolveTargetNormalizesEmail(t *testing.T) {
	caller := activeUser(false)
	other := repository.User{ID: uuid.New(), Email: "other@example.com", Active: true, Admin: true}

	t.Run("own address matches despite case", func(t *testing.T) {
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
			"/v1/user?email=Caller@Example.COM", caller))

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
	})

	t.Run("admin lookup is normalized", func(t *testing.T) {
		admin := activeUser(true)
		store := fakeStore{
			getUserById: func(_ context.Context, id uuid.UUID) (repository.User, error) {
				if id == admin.ID {
					return admin, nil
				}
				return other, nil
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
			"/v1/user?email=Other@Example.COM", admin))

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
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
	c.userHandler(rec, authRequestWithBody(t, http.MethodDelete, "/v1/user", caller, "application/json",
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
		c.userHandler(rec, authRequestWithBody(t, http.MethodDelete, "/v1/user", caller, "application/json",
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
			caller, "application/json", `{"email":"`+caller.Email+`"}`))
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
			caller, "application/json", `{"email":"other@example.com"}`))
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
			admin, "application/json", `{"email":"`+other.Email+`"}`))
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
	c.userHandler(rec, authRequestWithBody(t, http.MethodDelete, "/v1/user", admin, "application/json",
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
				admin, "application/json", `{"id":"`+uuid.New().String()+`"}`))
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
			c.userHandler(rec, authRequestWithBody(t, http.MethodDelete, "/v1/user", caller,
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
	c.userHandler(rec, authRequestWithBody(t, http.MethodPatch, "/v1/user", caller, "application/json",
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
	// Sessions minted before the change have to stop working, which is what
	// requireSession compares the token's epoch against.
	if stored.SessionEpoch != caller.SessionEpoch+1 {
		t.Fatalf("session_epoch = %d, want %d", stored.SessionEpoch, caller.SessionEpoch+1)
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
	// A previous password change left the account at a later epoch; an email
	// change must not move it, or it would sign the caller out for no reason.
	caller.SessionEpoch = 3

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
	c.userHandler(rec, authRequestWithBody(t, http.MethodPatch, "/v1/user", caller, "application/json",
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
	if stored.SessionEpoch != caller.SessionEpoch {
		t.Fatalf("session_epoch = %d, want the stored %d", stored.SessionEpoch, caller.SessionEpoch)
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

func TestUpdateUserNormalizesEmail(t *testing.T) {
	caller := activeUser(false)
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
	c.userHandler(rec, authRequestWithBody(t, http.MethodPatch, "/v1/user", caller, "application/json",
		`{"id":"`+caller.ID.String()+`","email":"  New@Example.COM "}`))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if stored.Email != "new@example.com" {
		t.Fatalf("stored email = %q, want new@example.com", stored.Email)
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
			c.userHandler(rec, authRequestWithBody(t, http.MethodPatch, "/v1/user", caller,
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
	c.userHandler(rec, authRequestWithBody(t, http.MethodPatch, "/v1/user", admin, "application/json",
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
				admin, "application/json", `{"id":"`+target.String()+`","email":"taken@example.com"}`))

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
			c.userHandler(rec, authRequestWithBody(t, http.MethodPatch, "/v1/user", caller,
				tt.contentType, tt.body))

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", rec.Code)
			}
		})
	}
}

// forgetting a password for a registered address issues a single live token
// and answers with the same generic body as any other account.
func TestForgotPasswordIssuesResetToken(t *testing.T) {
	user := activeUser(false)
	var stored repository.CreatePasswordResetTokenParams
	cleared := false
	store := fakeStore{
		getUserByEmail: func(_ context.Context, email string) (repository.User, error) {
			if email != user.Email {
				t.Fatalf("looked up %q, want %q", email, user.Email)
			}
			return user, nil
		},
		deletePasswordResetTokensForUser: func(_ context.Context, id uuid.UUID) error {
			cleared = true
			if id != user.ID {
				t.Fatalf("cleared tokens for %s, want %s", id, user.ID)
			}
			return nil
		},
		createPasswordResetToken: func(_ context.Context, arg repository.CreatePasswordResetTokenParams) error {
			stored = arg
			return nil
		},
	}
	c := newTestController(store)

	rec := doRequest(c.forgotPassword, http.MethodPost, "/v1/password/forgot", "application/json",
		`{"email":"`+user.Email+`"}`)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", rec.Code)
	}
	if !cleared {
		t.Fatal("outstanding reset tokens were not cleared")
	}
	if stored.UserID != user.ID {
		t.Fatalf("token names %s, want %s", stored.UserID, user.ID)
	}
	if !stored.ExpiresAt.After(time.Now().Add(passwordResetTTL - time.Hour)) {
		t.Fatalf("token expires %s, want about %s out", stored.ExpiresAt, passwordResetTTL)
	}
	if len(stored.TokenHash) == 0 {
		t.Fatal("token hash was not stored")
	}
}

func TestForgotPasswordNormalizesEmail(t *testing.T) {
	user := activeUser(false)
	var lookedUp string
	store := fakeStore{
		getUserByEmail: func(_ context.Context, email string) (repository.User, error) {
			lookedUp = email
			return user, nil
		},
		deletePasswordResetTokensForUser: func(context.Context, uuid.UUID) error { return nil },
		createPasswordResetToken: func(context.Context, repository.CreatePasswordResetTokenParams) error {
			return nil
		},
	}
	c := newTestController(store)

	rec := doRequest(c.forgotPassword, http.MethodPost, "/v1/password/forgot", "application/json",
		`{"email":"  `+user.Email+` "}`)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", rec.Code)
	}
	if lookedUp != user.Email {
		t.Fatalf("lookup email = %q, want %q", lookedUp, user.Email)
	}
}

func TestForgotPasswordUnknownEmailIsIndistinguishable(t *testing.T) {
	issued := false
	store := fakeStore{
		getUserByEmail: func(context.Context, string) (repository.User, error) {
			return repository.User{}, pgx.ErrNoRows
		},
		createPasswordResetToken: func(context.Context, repository.CreatePasswordResetTokenParams) error {
			issued = true
			return nil
		},
	}
	c := newTestController(store)

	rec := doRequest(c.forgotPassword, http.MethodPost, "/v1/password/forgot", "application/json",
		`{"email":"nobody@example.com"}`)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", rec.Code)
	}
	if got := rec.Body.String(); got != `{"status":"ok"}` {
		t.Fatalf("body = %q, want the generic acknowledgement", got)
	}
	if issued {
		t.Fatal("a reset token was issued for an unknown address")
	}
}

// A successful reset stores a fresh credential and bumps the session epoch, so
// every session and refresh token minted before the reset stops working.
func TestResetPasswordUpdatesCredentialAndRetiresSessions(t *testing.T) {
	oldSalt := []byte("0123456789abcdef")
	user := activeUser(false)
	user.HashedPassword = argon2.HashPassword("oldpassword", oldSalt)
	user.Salt = oldSalt
	user.SessionEpoch = 2

	token := "reset-token-value"
	var stored repository.UpdateUserParams
	store := fakeStore{
		consumePasswordResetToken: func(_ context.Context, tokenHash []byte) (repository.PasswordResetToken, error) {
			if !bytes.Equal(tokenHash, hashToken(token)) {
				t.Fatalf("consumed hash %x, want the presented token's", tokenHash)
			}
			return repository.PasswordResetToken{
				TokenHash: tokenHash,
				UserID:    user.ID,
				ExpiresAt: time.Now().Add(time.Hour),
			}, nil
		},
		getUserById: func(_ context.Context, id uuid.UUID) (repository.User, error) {
			if id != user.ID {
				t.Fatalf("read account %s, want %s", id, user.ID)
			}
			return user, nil
		},
		updateUser: func(_ context.Context, arg repository.UpdateUserParams) (repository.User, error) {
			stored = arg
			return repository.User{ID: arg.ID, Email: arg.Email, Active: arg.Active, Admin: arg.Admin}, nil
		},
		deletePasswordResetTokensForUser: func(context.Context, uuid.UUID) error { return nil },
	}
	c := newTestController(store)

	rec := doRequest(c.resetPassword, http.MethodPost, "/v1/password/reset", "application/json",
		`{"token":"`+token+`","password":"newpassword"}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if err := argon2.Validate("newpassword", stored.HashedPassword, stored.Salt); err != nil {
		t.Fatalf("stored credential does not validate the new password: %v", err)
	}
	if bytes.Equal(stored.Salt, oldSalt) {
		t.Fatal("reset reused the stored salt")
	}
	if stored.SessionEpoch != user.SessionEpoch+1 {
		t.Fatalf("session_epoch = %d, want %d", stored.SessionEpoch, user.SessionEpoch+1)
	}
	if stored.Email != user.Email || !stored.Active || stored.Admin {
		t.Fatalf("reset disturbed untouched fields: %+v", stored)
	}
	if bytes.Contains(rec.Body.Bytes(), stored.HashedPassword) || bytes.Contains(rec.Body.Bytes(), stored.Salt) {
		t.Fatal("response leaked stored password material")
	}
}

func TestResetPasswordRejectsInvalidOrExpiredToken(t *testing.T) {
	user := activeUser(false)
	tests := []struct {
		name  string
		store fakeStore
	}{
		{
			"unknown token",
			fakeStore{
				consumePasswordResetToken: func(context.Context, []byte) (repository.PasswordResetToken, error) {
					return repository.PasswordResetToken{}, pgx.ErrNoRows
				},
			},
		},
		{
			"expired token",
			fakeStore{
				consumePasswordResetToken: func(context.Context, []byte) (repository.PasswordResetToken, error) {
					return repository.PasswordResetToken{UserID: user.ID, ExpiresAt: time.Now().Add(-time.Minute)}, nil
				},
				getUserById: func(context.Context, uuid.UUID) (repository.User, error) {
					t.Fatal("expired token must be refused before the account is read")
					return user, nil
				},
			},
		},
		{
			"account is gone",
			fakeStore{
				consumePasswordResetToken: func(context.Context, []byte) (repository.PasswordResetToken, error) {
					return repository.PasswordResetToken{UserID: user.ID, ExpiresAt: time.Now().Add(time.Hour)}, nil
				},
				getUserById: func(context.Context, uuid.UUID) (repository.User, error) {
					return repository.User{}, pgx.ErrNoRows
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := doRequest(newTestController(tt.store).resetPassword, http.MethodPost,
				"/v1/password/reset", "application/json", `{"token":"some-token","password":"newpassword"}`)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", rec.Code)
			}
			if !bytes.Contains(rec.Body.Bytes(), []byte("invalid or expired token")) {
				t.Fatalf("body = %q, want the generic token error", rec.Body.String())
			}
		})
	}
}

func TestPasswordResetBadRequests(t *testing.T) {
	c := newTestController(fakeStore{})

	tests := []struct {
		name    string
		handler http.HandlerFunc
		method  string
		content string
		body    string
		want    int
	}{
		{"forgot wrong method", c.forgotPasswordHandler, http.MethodGet, "application/json", "", http.StatusMethodNotAllowed},
		{"forgot bad content type", c.forgotPasswordHandler, http.MethodPost, "text/plain", `{"email":"a@b.com"}`, http.StatusBadRequest},
		{"forgot empty email", c.forgotPasswordHandler, http.MethodPost, "application/json", `{"email":""}`, http.StatusBadRequest},
		{"reset wrong method", c.resetPasswordHandler, http.MethodGet, "application/json", "", http.StatusMethodNotAllowed},
		{"reset bad content type", c.resetPasswordHandler, http.MethodPost, "text/plain", `{"token":"x","password":"newpassword"}`, http.StatusBadRequest},
		{"reset empty token", c.resetPasswordHandler, http.MethodPost, "application/json", `{"token":"","password":"newpassword"}`, http.StatusBadRequest},
		{"reset short password", c.resetPasswordHandler, http.MethodPost, "application/json", `{"token":"x","password":"short"}`, http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := doRequest(tt.handler, tt.method, "/v1/password/x", tt.content, tt.body)
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d", rec.Code, tt.want)
			}
		})
	}
}
