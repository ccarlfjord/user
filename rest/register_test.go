package rest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ccarlfjord/user/internal/repository"
	"github.com/jackc/pgx/v5"
)

// testRegistrationToken is the initial access token the register tests
// present. Its hash is what the store is wired to accept.
const testRegistrationToken = "registration-token-0123456789abcdef"

// registerBody is well-formed metadata for a public client.
func registerBody() map[string]any {
	return map[string]any{
		"redirect_uris":             []string{"https://app.example.com/callback"},
		"token_endpoint_auth_method": "none",
		"client_name":               "Example App",
		"scope":                     "openid email",
	}
}

// registrationRoute returns the handler exactly as Run registers it.
func registrationRoute(c *controller) http.HandlerFunc {
	return c.registerHandler
}

// doRegister posts body (JSON-encoded) to /register with an Authorization
// bearer header carrying the registration token. A nil token sends no header.
func doRegister(t *testing.T, c *controller, token *string, body any) *httptest.ResponseRecorder {
	t.Helper()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/register", nil)
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		req = httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(string(payload)))
		req.Header.Set("Content-Type", "application/json")
	}
	if token != nil {
		req.Header.Set("Authorization", "Bearer "+*token)
	}
	registrationRoute(c)(rec, req)
	return rec
}

// registrationStore is a fakeStore wired to accept testRegistrationToken and
// record the client that gets created.
type registrationStore struct {
	fakeStore
	created    *repository.CreateClientParams
	tokenSpent bool
}

func newRegistrationStore() *registrationStore {
	s := &registrationStore{}
	s.fakeStore = fakeStore{
		consumeRegistrationToken: func(_ context.Context, tokenHash []byte) (repository.RegistrationToken, error) {
			if string(tokenHash) != string(hashToken(testRegistrationToken)) {
				return repository.RegistrationToken{}, pgx.ErrNoRows
			}
			s.tokenSpent = true
			return repository.RegistrationToken{
				TokenHash: tokenHash,
				ExpiresAt: time.Now().Add(time.Hour),
			}, nil
		},
		createClient: func(_ context.Context, arg repository.CreateClientParams) (repository.OauthClient, error) {
			if s.created != nil {
				return repository.OauthClient{ClientID: arg.ClientID, Name: arg.Name}, nil
			}
			saved := arg
			s.created = &saved
			return repository.OauthClient{ClientID: arg.ClientID, Name: arg.Name}, nil
		},
	}
	return s
}

// TestRegisterHappyPathPublic: a public client registers with no secret, and
// the effective metadata — defaults filled in — comes back with the store
// record matching it.
func TestRegisterHappyPathPublic(t *testing.T) {
	store := newRegistrationStore()
	c := newTestController(store)

	token := testRegistrationToken
	rec := doRegister(t, c, &token, registerBody())

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", rec.Code, rec.Body.String())
	}
	if !store.tokenSpent {
		t.Fatal("the registration token was not consumed")
	}

	var got registrationResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.ClientID == "" {
		t.Fatal("no client_id in the response")
	}
	if got.ClientSecret != "" {
		t.Fatal("a public client must not get a secret")
	}
	if got.ClientSecretExpiresAt != nil {
		t.Fatal("client_secret_expires_at must be absent for a public client")
	}
	if got.TokenEndpointAuthMethod != "none" {
		t.Fatalf("token_endpoint_auth_method = %q, want none", got.TokenEndpointAuthMethod)
	}
	if got.Scope != "openid email" {
		t.Fatalf("scope = %q, want the requested set echoed", got.Scope)
	}
	if got.ClientName != "Example App" {
		t.Fatalf("client_name = %q", got.ClientName)
	}
	if len(got.RedirectURIs) != 1 || got.RedirectURIs[0] != "https://app.example.com/callback" {
		t.Fatalf("redirect_uris = %v", got.RedirectURIs)
	}
	if got.GrantTypes == nil || len(got.GrantTypes) != 1 || got.GrantTypes[0] != "authorization_code" {
		t.Fatalf("grant_types = %v, want the default [authorization_code]", got.GrantTypes)
	}
	if got.ResponseTypes == nil || len(got.ResponseTypes) != 1 || got.ResponseTypes[0] != "code" {
		t.Fatalf("response_types = %v, want the default [code]", got.ResponseTypes)
	}
	if got.ClientIDIssuedAt == 0 {
		t.Fatal("client_id_issued_at is not set")
	}

	if store.created == nil {
		t.Fatal("no client was created")
	}
	if store.created.ClientID != got.ClientID {
		t.Fatalf("stored client_id = %q, want the response's %q", store.created.ClientID, got.ClientID)
	}
	if !store.created.IsPublic {
		t.Fatal("a client registered with auth method none must be stored public")
	}
	if store.created.ClientSecretHash != nil {
		t.Fatal("a public client must be stored without a secret")
	}
	if !store.created.Active {
		t.Fatal("a registered client must be active")
	}
}

// TestRegisterHappyPathConfidential: the default auth method is
// client_secret_basic, so omitting it registers a confidential client whose
// secret comes back exactly once and whose stored hash validates against it.
func TestRegisterHappyPathConfidential(t *testing.T) {
	store := newRegistrationStore()
	c := newTestController(store)

	body := registerBody()
	delete(body, "token_endpoint_auth_method")

	token := testRegistrationToken
	rec := doRegister(t, c, &token, body)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", rec.Code, rec.Body.String())
	}

	var got registrationResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.ClientSecret == "" {
		t.Fatal("a confidential client must get a secret")
	}
	if got.TokenEndpointAuthMethod != "client_secret_basic" {
		t.Fatalf("token_endpoint_auth_method = %q, want the default client_secret_basic", got.TokenEndpointAuthMethod)
	}
	if got.ClientSecretExpiresAt == nil {
		t.Fatal("client_secret_expires_at must be present when a secret is returned")
	}

	if store.created == nil || store.created.IsPublic {
		t.Fatal("a client registered without an auth method must be stored confidential")
	}
	if store.created.ClientSecretHash == nil {
		t.Fatal("a confidential client must be stored with a secret hash")
	}
	// The stored hash must match the plaintext secret that was handed out
	// exactly once — that hash is what /token will check against, with the
	// same plain SHA-256 lookup used for every other server-minted token.
	if want := hashToken(got.ClientSecret); string(store.created.ClientSecretHash) != string(want) {
		t.Fatal("the stored secret hash is not the SHA-256 of the returned secret")
	}
	// And it must not match something that is not the secret.
	if string(store.created.ClientSecretHash) == string(hashToken(got.ClientSecret+"wrong")) {
		t.Fatal("the stored secret hash matches a wrong secret")
	}
}

// TestRegisterGate: no token, a wrong token, or a spent token all get 401 and
// create nothing. An expired token is refused too.
func TestRegisterGate(t *testing.T) {
	newController := func(consume func(context.Context, []byte) (repository.RegistrationToken, error)) *controller {
		store := newRegistrationStore()
		store.consumeRegistrationToken = consume
		return newTestController(store)
	}

	wrongToken := testRegistrationToken + "-wrong"
	// The table wants pointers; &const is not a thing, so make a variable.
	regToken := testRegistrationToken
	consumed := false

	cases := []struct {
		name    string
		token   *string
		consume func(context.Context, []byte) (repository.RegistrationToken, error)
	}{
		{
			name:  "no Authorization header",
			token: nil,
		},
		{
			name:  "wrong token",
			token: &wrongToken,
		},
		{
			name:  "expired token",
			token: &regToken,
			consume: func(_ context.Context, _ []byte) (repository.RegistrationToken, error) {
				return repository.RegistrationToken{ExpiresAt: time.Now().Add(-time.Minute)}, nil
			},
		},
		{
			name:  "already spent (single-use)",
			token: &regToken,
			consume: func(_ context.Context, _ []byte) (repository.RegistrationToken, error) {
				consumed = true
				return repository.RegistrationToken{}, pgx.ErrNoRows
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newController(tc.consume)
			rec := doRegister(t, c, tc.token, registerBody())

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401: %s", rec.Code, rec.Body.String())
			}
			if store := newRegistrationStore(); store == nil {
				t.Fatal("unreachable")
			}
			if consumed && tc.name != "already spent (single-use)" {
				t.Fatal("token consumed outside the single-use case")
			}
		})
	}

	// The single-use case really is single-use: a second registration with the
	// same token fails.
	c := newController(func(context.Context, []byte) (repository.RegistrationToken, error) {
		return repository.RegistrationToken{}, pgx.ErrNoRows
	})
	rec := doRegister(t, c, &regToken, registerBody())
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("second use status = %d, want 401", rec.Code)
	}
}

// TestRegisterRefusesBadMetadata: every malformed request is a 400 naming the
// RFC 7591 error code, and nothing reaches the store.
func TestRegisterRefusesBadMetadata(t *testing.T) {
	cases := []struct {
		name     string
		body     func() map[string]any
		wantCode string
	}{
		{
			name: "no redirect_uris",
			body: func() map[string]any {
				body := registerBody()
				delete(body, "redirect_uris")
				return body
			},
			wantCode: "invalid_redirect_uri",
		},
		{
			name: "empty redirect_uris",
			body: func() map[string]any {
				body := registerBody()
				body["redirect_uris"] = []string{}
				return body
			},
			wantCode: "invalid_redirect_uri",
		},
		{
			name: "redirect_uri without a scheme",
			body: func() map[string]any {
				body := registerBody()
				body["redirect_uris"] = []string{"app.example.com/callback"}
				return body
			},
			wantCode: "invalid_redirect_uri",
		},
		{
			name: "http redirect_uri off loopback",
			body: func() map[string]any {
				body := registerBody()
				body["redirect_uris"] = []string{"http://app.example.com/callback"}
				return body
			},
			wantCode: "invalid_redirect_uri",
		},
		{
			name: "redirect_uri with a fragment",
			body: func() map[string]any {
				body := registerBody()
				body["redirect_uris"] = []string{"https://app.example.com/callback#frag"}
				return body
			},
			wantCode: "invalid_redirect_uri",
		},
		{
			name: "unknown auth method",
			body: func() map[string]any {
				body := registerBody()
				body["token_endpoint_auth_method"] = "client_secret_jwt"
				return body
			},
			wantCode: "invalid_client_metadata",
		},
		{
			name: "grant types without authorization_code",
			body: func() map[string]any {
				body := registerBody()
				body["grant_types"] = []string{"refresh_token"}
				return body
			},
			wantCode: "invalid_client_metadata",
		},
		{
			name: "unsupported grant type",
			body: func() map[string]any {
				body := registerBody()
				body["grant_types"] = []string{"authorization_code", "urn:ietf:params:oauth:grant-type:jwt-bearer"}
				return body
			},
			wantCode: "invalid_client_metadata",
		},
		{
			name: "response type other than code",
			body: func() map[string]any {
				body := registerBody()
				body["response_types"] = []string{"token"}
				return body
			},
			wantCode: "invalid_client_metadata",
		},
		{
			name: "missing client_name",
			body: func() map[string]any {
				body := registerBody()
				delete(body, "client_name")
				return body
			},
			wantCode: "invalid_client_metadata",
		},
		{
			name: "blank client_name",
			body: func() map[string]any {
				body := registerBody()
				body["client_name"] = "   "
				return body
			},
			wantCode: "invalid_client_metadata",
		},
		{
			name: "scope outside the vocabulary",
			body: func() map[string]any {
				body := registerBody()
				body["scope"] = "openid profile"
				return body
			},
			wantCode: "invalid_client_metadata",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := newRegistrationStore()
			c := newTestController(store)

			token := testRegistrationToken
			rec := doRegister(t, c, &token, tc.body())

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
			}
			var got registrationError
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatalf("decode error body: %v", err)
			}
			if got.Error != tc.wantCode {
				t.Fatalf("error = %q, want %q", got.Error, tc.wantCode)
			}
			// A token must not burn on a metadata typo.
			if store.tokenSpent {
				t.Fatal("the registration token was consumed for a refused request")
			}
			if store.created != nil {
				t.Fatal("a client was created for a refused request")
			}
		})
	}
}

// TestRegisterLoopbackHTTPAllowed: plain http is accepted on loopback for
// native app development.
func TestRegisterLoopbackHTTPAllowed(t *testing.T) {
	store := newRegistrationStore()
	c := newTestController(store)

	body := registerBody()
	body["redirect_uris"] = []string{"http://127.0.0.1:8080/callback", "http://localhost:8080/callback"}

	token := testRegistrationToken
	rec := doRegister(t, c, &token, body)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", rec.Code, rec.Body.String())
	}
	if store.created == nil || len(store.created.RedirectUris) != 2 {
		t.Fatalf("stored redirect_uris = %v, want both loopback URIs", store.created)
	}
}

// TestRegisterMalformedJSON: an undecodable body is invalid metadata, not a
// 500.
func TestRegisterMalformedJSON(t *testing.T) {
	store := newRegistrationStore()
	c := newTestController(store)

	token := testRegistrationToken
	rec := doRegister(t, c, &token, nil)
	// nil body means no Content-Type either, which is refused first.
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader("{not json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+testRegistrationToken)
	registrationRoute(c)(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if store.created != nil {
		t.Fatal("a client was created for a malformed body")
	}
}

// TestRegisterRequiresPost: the registration endpoint is a POST.
func TestRegisterRequiresPost(t *testing.T) {
	c := newTestController(fakeStore{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/register", nil)
	registrationRoute(c)(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

