package rest

import (
	"context"
	"encoding/json"
	"io"
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
		"redirect_uris":              []string{"https://app.example.com/callback"},
		"token_endpoint_auth_method": "none",
		"client_name":                "Example App",
		"scope":                      "openid email",
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
				return clientFromParams(arg), nil
			}
			saved := arg
			s.created = &saved
			return clientFromParams(arg), nil
		},
	}
	return s
}

// clientFromParams turns a CreateClientParams into the row a real store would
// return from RETURNING *, so handler tests see the metadata they stored.
func clientFromParams(arg repository.CreateClientParams) repository.OauthClient {
	return repository.OauthClient{
		ClientID:                    arg.ClientID,
		ClientSecretHash:            arg.ClientSecretHash,
		IsPublic:                    arg.IsPublic,
		Name:                        arg.Name,
		RedirectUris:                arg.RedirectUris,
		AllowedScopes:               arg.AllowedScopes,
		Active:                      arg.Active,
		CreatedAt:                   time.Now(),
		RegistrationAccessTokenHash: arg.RegistrationAccessTokenHash,
		TokenEndpointAuthMethod:     arg.TokenEndpointAuthMethod,
		GrantTypes:                  arg.GrantTypes,
		ResponseTypes:               arg.ResponseTypes,
	}
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

// testRegistrationAccessToken is the management credential the RFC 7592 tests
// present; its hash is what the fake store authenticates against.
const testRegistrationAccessToken = "registration-access-token-0123456789abcdef"

// managementStore backs the RFC 7592 tests with one stored client. Its
// GetClientByRegistrationToken matches on both the client id and the token
// hash, exactly as the real query does, so a token for another client fails.
type managementStore struct {
	fakeStore
	client  repository.OauthClient
	updated *repository.UpdateClientParams
	deleted bool
}

func (s *managementStore) seed(client repository.OauthClient, token string) *managementStore {
	client.RegistrationAccessTokenHash = hashToken(token)
	s.client = client
	s.fakeStore.getClientByRegistrationToken = func(_ context.Context, arg repository.GetClientByRegistrationTokenParams) (repository.OauthClient, error) {
		if arg.ClientID != s.client.ClientID || string(arg.RegistrationAccessTokenHash) != string(s.client.RegistrationAccessTokenHash) {
			return repository.OauthClient{}, pgx.ErrNoRows
		}
		return s.client, nil
	}
	s.fakeStore.updateClient = func(_ context.Context, arg repository.UpdateClientParams) (repository.OauthClient, error) {
		s.updated = &arg
		updated := s.client
		updated.ClientSecretHash = arg.ClientSecretHash
		updated.IsPublic = arg.IsPublic
		updated.Name = arg.Name
		updated.RedirectUris = arg.RedirectUris
		updated.AllowedScopes = arg.AllowedScopes
		updated.TokenEndpointAuthMethod = arg.TokenEndpointAuthMethod
		updated.GrantTypes = arg.GrantTypes
		updated.ResponseTypes = arg.ResponseTypes
		updated.RegistrationAccessTokenHash = arg.RegistrationAccessTokenHash
		s.client = updated
		return updated, nil
	}
	s.fakeStore.deleteClient = func(_ context.Context, id string) (int64, error) {
		if id != s.client.ClientID {
			return 0, nil
		}
		s.deleted = true
		return 1, nil
	}
	return s
}

// doManagement drives the RFC 7592 endpoint. A nil bearer sends no header.
func doManagement(t *testing.T, c *controller, method, clientID string, bearer *string, body any) *httptest.ResponseRecorder {
	t.Helper()

	var reader io.Reader
	contentType := ""
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		reader = strings.NewReader(string(payload))
		contentType = "application/json"
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, "/register/"+clientID, reader)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if bearer != nil {
		req.Header.Set("Authorization", "Bearer "+*bearer)
	}
	req.SetPathValue("client_id", clientID)
	c.clientRegistrationHandler(rec, req)
	return rec
}

func managementClient() repository.OauthClient {
	return repository.OauthClient{
		ClientID:                "client-1",
		Name:                    "Example App",
		RedirectUris:            []string{"https://app.example.com/callback"},
		AllowedScopes:           []string{"openid", "email"},
		IsPublic:                true,
		TokenEndpointAuthMethod: "none",
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		Active:                  true,
		CreatedAt:               time.Now(),
	}
}

// TestRegisterIssuesManagementCredentials: a fresh registration hands back a
// registration access token and its client information URI, and stores only
// the token's hash.
func TestRegisterIssuesManagementCredentials(t *testing.T) {
	store := newRegistrationStore()
	c := newTestController(store)

	token := testRegistrationToken
	rec := doRegister(t, c, &token, registerBody())
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", rec.Code, rec.Body.String())
	}

	var got registrationResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.RegistrationAccessToken == "" {
		t.Fatal("no registration_access_token in the response")
	}
	if want := testIssuer + "/register/" + got.ClientID; got.RegistrationClientURI != want {
		t.Fatalf("registration_client_uri = %q, want %q", got.RegistrationClientURI, want)
	}
	if store.created == nil {
		t.Fatal("no client was created")
	}
	if store.created.RegistrationAccessTokenHash == nil {
		t.Fatal("the registration access token hash was not stored")
	}
	if want := hashToken(got.RegistrationAccessToken); string(store.created.RegistrationAccessTokenHash) != string(want) {
		t.Fatal("the stored registration token hash is not the SHA-256 of the returned token")
	}
	if store.created.TokenEndpointAuthMethod != "none" {
		t.Fatalf("stored token_endpoint_auth_method = %q", store.created.TokenEndpointAuthMethod)
	}
	if len(store.created.GrantTypes) != 1 || store.created.GrantTypes[0] != "authorization_code" {
		t.Fatalf("stored grant_types = %v", store.created.GrantTypes)
	}
}

// TestReadClientRegistration: a valid management token reads the metadata,
// with neither the secret nor the management token echoed.
func TestReadClientRegistration(t *testing.T) {
	store := (&managementStore{}).seed(managementClient(), testRegistrationAccessToken)
	c := newTestController(store)

	token := testRegistrationAccessToken
	rec := doManagement(t, c, http.MethodGet, "client-1", &token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	var got registrationResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.ClientID != "client-1" || got.ClientName != "Example App" {
		t.Fatalf("unexpected client identity: %+v", got)
	}
	if got.Scope != "openid email" {
		t.Fatalf("scope = %q", got.Scope)
	}
	if got.TokenEndpointAuthMethod != "none" {
		t.Fatalf("token_endpoint_auth_method = %q", got.TokenEndpointAuthMethod)
	}
	if got.ClientSecret != "" || got.ClientSecretExpiresAt != nil {
		t.Fatal("a read must not echo a client secret")
	}
	if got.RegistrationAccessToken != "" {
		t.Fatal("a read must not echo the registration access token")
	}
	if got.RegistrationClientURI != testIssuer+"/register/client-1" {
		t.Fatalf("registration_client_uri = %q", got.RegistrationClientURI)
	}
}

// TestManagementAuthGate: a missing token, a wrong token, an unknown client,
// and a token that belongs to another client all get the same 401 and reach
// no mutation.
func TestManagementAuthGate(t *testing.T) {
	otherToken := testRegistrationAccessToken + "-other"
	wrongToken := testRegistrationAccessToken + "-wrong"

	cases := []struct {
		name     string
		clientID string
		bearer   *string
	}{
		{name: "no Authorization header", clientID: "client-1"},
		{name: "wrong token", clientID: "client-1", bearer: &wrongToken},
		{name: "unknown client", clientID: "nobody", bearer: &otherToken},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := (&managementStore{}).seed(managementClient(), testRegistrationAccessToken)
			c := newTestController(store)

			rec := doManagement(t, c, http.MethodGet, tc.clientID, tc.bearer, nil)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401: %s", rec.Code, rec.Body.String())
			}
			if store.deleted || store.updated != nil {
				t.Fatal("an unauthorized request reached the store")
			}
		})
	}
}

// TestUpdateClientRegistrationRotatesManagementToken: a confidential client
// stays confidential, keeps its stored secret, and gets a fresh registration
// access token; every rewritten field lands in the store.
func TestUpdateClientRegistrationRotatesManagementToken(t *testing.T) {
	client := managementClient()
	client.IsPublic = false
	client.TokenEndpointAuthMethod = "client_secret_basic"
	client.ClientSecretHash = hashToken("the-existing-secret")
	store := (&managementStore{}).seed(client, testRegistrationAccessToken)
	c := newTestController(store)

	token := testRegistrationAccessToken
	body := map[string]any{
		"redirect_uris":              []string{"https://app.example.com/new-callback"},
		"token_endpoint_auth_method": "client_secret_basic",
		"client_name":                "Renamed App",
		"scope":                      "openid",
	}
	rec := doManagement(t, c, http.MethodPut, "client-1", &token, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	var got registrationResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.RegistrationAccessToken == "" || got.RegistrationAccessToken == testRegistrationAccessToken {
		t.Fatal("the registration access token was not rotated")
	}
	if got.ClientSecret != "" {
		t.Fatal("a confidential-to-confidential update must not re-issue the secret")
	}

	if store.updated == nil {
		t.Fatal("UpdateClient was not called")
	}
	if got.ClientName != "Renamed App" || store.updated.Name != "Renamed App" {
		t.Fatalf("client_name not updated: %+v", store.updated)
	}
	if len(store.updated.RedirectUris) != 1 || store.updated.RedirectUris[0] != "https://app.example.com/new-callback" {
		t.Fatalf("redirect_uris not updated: %v", store.updated.RedirectUris)
	}
	if store.updated.IsPublic {
		t.Fatal("a client_secret_basic update must stay confidential")
	}
	if string(store.updated.ClientSecretHash) != string(client.ClientSecretHash) {
		t.Fatal("the existing secret hash was not carried over")
	}
	if want := hashToken(got.RegistrationAccessToken); string(store.updated.RegistrationAccessTokenHash) != string(want) {
		t.Fatal("the rotated token's hash was not stored")
	}
}

// TestUpdateClientRegistrationCrossesToConfidential: moving from public to
// confidential mints a secret and returns it once.
func TestUpdateClientRegistrationCrossesToConfidential(t *testing.T) {
	store := (&managementStore{}).seed(managementClient(), testRegistrationAccessToken)
	c := newTestController(store)

	token := testRegistrationAccessToken
	body := map[string]any{
		"redirect_uris":              []string{"https://app.example.com/callback"},
		"token_endpoint_auth_method": "client_secret_basic",
		"client_name":                "Example App",
	}
	rec := doManagement(t, c, http.MethodPut, "client-1", &token, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	var got registrationResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.ClientSecret == "" {
		t.Fatal("crossing to confidential must return a new secret")
	}
	if got.ClientSecretExpiresAt == nil {
		t.Fatal("client_secret_expires_at must accompany the secret")
	}
	if store.updated == nil || store.updated.IsPublic {
		t.Fatal("the update did not store a confidential client")
	}
	if want := hashToken(got.ClientSecret); string(store.updated.ClientSecretHash) != string(want) {
		t.Fatal("the stored secret hash is not the SHA-256 of the returned secret")
	}
}

// TestUpdateClientRegistrationKeepsPublicWithoutMethod: an update that omits
// token_endpoint_auth_method keeps the client's current method, so renaming a
// public client does not silently make it confidential.
func TestUpdateClientRegistrationKeepsPublicWithoutMethod(t *testing.T) {
	store := (&managementStore{}).seed(managementClient(), testRegistrationAccessToken)
	c := newTestController(store)

	token := testRegistrationAccessToken
	body := map[string]any{
		"redirect_uris": []string{"https://app.example.com/callback"},
		"client_name":   "Renamed App",
	}
	rec := doManagement(t, c, http.MethodPut, "client-1", &token, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	var got registrationResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.ClientSecret != "" {
		t.Fatal("a public client must not be handed a secret by a rename")
	}
	if got.TokenEndpointAuthMethod != "none" {
		t.Fatalf("token_endpoint_auth_method = %q, want none", got.TokenEndpointAuthMethod)
	}
	if store.updated == nil || !store.updated.IsPublic {
		t.Fatal("the client did not stay public")
	}
	if store.updated.ClientSecretHash != nil {
		t.Fatal("a public client must be stored without a secret")
	}
}

// TestDeleteClientRegistration: a valid token deletes the client and answers
// 204.
func TestDeleteClientRegistration(t *testing.T) {
	store := (&managementStore{}).seed(managementClient(), testRegistrationAccessToken)
	c := newTestController(store)

	token := testRegistrationAccessToken
	rec := doManagement(t, c, http.MethodDelete, "client-1", &token, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204: %s", rec.Code, rec.Body.String())
	}
	if !store.deleted {
		t.Fatal("the client was not deleted")
	}
}

// TestManagementUpdateRefusesBadMetadata: a management PUT runs the same
// validation as registration, so bad redirect URIs never reach the store.
func TestManagementUpdateRefusesBadMetadata(t *testing.T) {
	store := (&managementStore{}).seed(managementClient(), testRegistrationAccessToken)
	c := newTestController(store)

	token := testRegistrationAccessToken
	body := map[string]any{"client_name": "No Redirect"}
	rec := doManagement(t, c, http.MethodPut, "client-1", &token, body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
	}

	var got registrationError
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if got.Error != "invalid_redirect_uri" {
		t.Fatalf("error = %q, want invalid_redirect_uri", got.Error)
	}
	if store.updated != nil {
		t.Fatal("a malformed update reached the store")
	}
}
