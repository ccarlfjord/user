package rest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ccarlfjord/argon2"
	"github.com/ccarlfjord/user/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// testClientID is the client_id of the registered client the tests use.
const testClientID = "6f0b1a2e-9c3d-4a5b-8e7f-1234567890ab"

// testRedirectURI is the exact URI the test client registered. Valid requests
// must present it byte for byte.
const testRedirectURI = "https://app.example.com/callback"

// testChallenge is a well-formed S256 challenge: 43 characters of the
// base64url alphabet, the shape a SHA-256 digest of a verifier encodes to
// (RFC 7636's worked example).
const testChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

// testClient is the registered client behind every /authorize test. It is
// public (no secret), so it must always present PKCE, and it may ask for
// openid and email.
func testClient() repository.OauthClient {
	return repository.OauthClient{
		ClientID:      testClientID,
		Name:          "Example App",
		IsPublic:      true,
		RedirectUris:  []string{testRedirectURI},
		AllowedScopes: []string{ScopeOpenID, ScopeEmail},
		Active:        true,
	}
}

// validAuthorizeQuery is a well-formed request against testClient.
func validAuthorizeQuery() url.Values {
	return url.Values{
		"response_type":         {"code"},
		"client_id":             {testClientID},
		"redirect_uri":          {testRedirectURI},
		"scope":                 {ScopeOpenID + " " + ScopeEmail},
		"state":                 {"st-abc123"},
		"nonce":                 {"n-abc123"},
		"code_challenge":        {testChallenge},
		"code_challenge_method": {PKCEMethodS256},
	}
}

// authorizeRoute returns the wrapped handler for an authorize route path,
// exactly as Run registers it, so the routing gates are exercised.
func authorizeRoute(c *controller, path string) http.HandlerFunc {
	switch path {
	case "/authorize":
		return c.authorizeHandler
	case "/authorize/login":
		return c.authorizeLoginHandler
	case "/authorize/consent":
		return c.authorizeConsentHandler
	default:
		panic("unrouted authorize path " + path)
	}
}

// doAuthorize sends req to the authorize handler at path and returns the
// recorder.
func doAuthorize(c *controller, path string, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	authorizeRoute(c, path)(rec, req)
	return rec
}

// authorizeGet builds a GET /authorize request from query values.
func authorizeGet(t *testing.T, q url.Values) *http.Request {
	t.Helper()
	return httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil)
}

// withSessionCookie adds the browser session cookie for user, minted at that
// account's current session epoch.
func withSessionCookie(r *http.Request, t *testing.T, user repository.User) {
	t.Helper()
	r.AddCookie(&http.Cookie{
		Name:  sessionCookieName,
		Value: signClaims(t, testSigningKey, mintedClaims(user.ID.String(), user.SessionEpoch)),
	})
}

// formRequest builds a POST of an x-www-form-urlencoded body.
func formRequest(target string, form url.Values) *http.Request {
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

// consentForm is the consent POST for params.
func consentForm(params url.Values, deny bool) url.Values {
	form := url.Values{}
	for k, v := range params {
		form[k] = v
	}
	if deny {
		form.Set("deny", "1")
	}
	return form
}

// authorizeStore is a fakeStore wired to resolve testClient and account,
// capturing any code minted. client and account are pointers so a test can
// vary them and the closures see the variation.
type authorizeStore struct {
	fakeStore
	client  *repository.OauthClient
	account *repository.User
	minted  repository.CreateAuthorizationCodeParams
}

func newAuthorizeStore(client repository.OauthClient, user repository.User) authorizeStore {
	s := &authorizeStore{client: &client, account: &user}
	s.fakeStore = fakeStore{
		getClientById: func(_ context.Context, id string) (repository.OauthClient, error) {
			if id != s.client.ClientID {
				return repository.OauthClient{}, pgx.ErrNoRows
			}
			return *s.client, nil
		},
		getUserById: func(_ context.Context, id uuid.UUID) (repository.User, error) {
			if id != s.account.ID {
				return repository.User{}, pgx.ErrNoRows
			}
			return *s.account, nil
		},
	}
	return *s
}

func (s *authorizeStore) CreateAuthorizationCode(ctx context.Context, arg repository.CreateAuthorizationCodeParams) error {
	s.minted = arg
	return nil
}

// TestAuthorizeRefusesBeforeRedirectValidated covers the failures that render
// an error page: without a validated redirect URI there is nowhere safe to
// redirect, so the response must never carry a Location header — redirecting
// to an unvalidated URL would let a malformed request turn the server into an
// open redirector.
func TestAuthorizeRefusesBeforeRedirectValidated(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(q url.Values)
		store  func(t *testing.T) userStore
	}{
		{
			name: "unknown client",
			mutate: func(q url.Values) {
				q.Set("client_id", "not-registered")
			},
		},
		{
			name: "missing client_id",
			mutate: func(q url.Values) {
				q.Del("client_id")
			},
		},
		{
			name:   "inactive client",
			mutate: func(q url.Values) {},
			store: func(t *testing.T) userStore {
				client := testClient()
				client.Active = false
				s := newAuthorizeStore(client, activeUser(false))
				return &s
			},
		},
		{
			name: "missing redirect_uri",
			mutate: func(q url.Values) {
				q.Del("redirect_uri")
			},
		},
		{
			name: "redirect_uri differs by scheme",
			mutate: func(q url.Values) {
				q.Set("redirect_uri", "http://app.example.com/callback")
			},
		},
		{
			name: "redirect_uri differs by path",
			mutate: func(q url.Values) {
				q.Set("redirect_uri", testRedirectURI+"/extra")
			},
		},
		{
			name: "redirect_uri with a query the client did not register",
			mutate: func(q url.Values) {
				q.Set("redirect_uri", testRedirectURI+"?x=1")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := userStore(fakeStore{getUserById: func(context.Context, uuid.UUID) (repository.User, error) {
				return repository.User{}, pgx.ErrNoRows
			}})
			if tc.store != nil {
				store = tc.store(t)
			}
			c := newTestController(store)

			q := validAuthorizeQuery()
			tc.mutate(q)
			rec := doAuthorize(c, "/authorize", authorizeGet(t, q))

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
			}
			if rec.Header().Get("Location") != "" {
				t.Fatalf("Location = %q, want none before the redirect URI is validated",
					rec.Header().Get("Location"))
			}
		})
	}
}

// TestAuthorizeRefusesToRedirect covers the failures that are safe to send
// back to the client: once client_id and redirect_uri validate, the response
// is a 302 to that redirect URI carrying the OAuth error code, the echoed
// state, and iss.
func TestAuthorizeRefusesToRedirect(t *testing.T) {
	store := newAuthorizeStore(testClient(), activeUser(false))
	c := newTestController(&store)

	cases := []struct {
		name   string
		mutate func(q url.Values)
		after  func()
		want   string
	}{
		{
			name:   "response_type token",
			mutate: func(q url.Values) { q.Set("response_type", "token") },
			want:   "unsupported_response_type",
		},
		{
			name:   "missing response_type",
			mutate: func(q url.Values) { q.Del("response_type") },
			want:   "unsupported_response_type",
		},
		{
			name:   "scope without openid",
			mutate: func(q url.Values) { q.Set("scope", ScopeEmail) },
			want:   "invalid_scope",
		},
		{
			name:   "scope outside the provider vocabulary",
			mutate: func(q url.Values) { q.Set("scope", ScopeOpenID+" profile") },
			want:   "invalid_scope",
		},
		{
			name:   "scope outside the client's grant ceiling",
			mutate: func(q url.Values) { store.client.AllowedScopes = []string{ScopeOpenID} },
			want:   "invalid_scope",
			after:  func() { store.client.AllowedScopes = []string{ScopeOpenID, ScopeEmail} },
		},
		{
			name:   "missing scope",
			mutate: func(q url.Values) { q.Del("scope") },
			want:   "invalid_scope",
		},
		{
			name:   "public client without a challenge",
			mutate: func(q url.Values) { q.Del("code_challenge") },
			want:   "invalid_request",
		},
		{
			name:   "plain method",
			mutate: func(q url.Values) { q.Set("code_challenge_method", "plain") },
			want:   "invalid_request",
		},
		{
			name:   "missing method",
			mutate: func(q url.Values) { q.Del("code_challenge_method") },
			want:   "invalid_request",
		},
		{
			name:   "challenge too short",
			mutate: func(q url.Values) { q.Set("code_challenge", strings.Repeat("A", 42)) },
			want:   "invalid_request",
		},
		{
			name:   "challenge with a character outside the base64url alphabet",
			mutate: func(q url.Values) { q.Set("code_challenge", strings.Repeat("A", 42)+"+") },
			want:   "invalid_request",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			q := validAuthorizeQuery()
			tc.mutate(q)
			rec := doAuthorize(c, "/authorize", authorizeGet(t, q))
			if tc.after != nil {
				tc.after()
			}

			if rec.Code != http.StatusFound {
				t.Fatalf("status = %d, want 302: %s", rec.Code, rec.Body.String())
			}
			location, err := url.Parse(rec.Header().Get("Location"))
			if err != nil {
				t.Fatalf("parse Location: %v", err)
			}
			if location.Scheme+"://"+location.Host+location.Path != testRedirectURI {
				t.Fatalf("redirect = %q, want %q", location, testRedirectURI)
			}
			got := location.Query()
			if got.Get("error") != tc.want {
				t.Fatalf("error = %q, want %q", got.Get("error"), tc.want)
			}
			if got.Get("state") != "st-abc123" {
				t.Fatalf("state = %q, want the request's state echoed", got.Get("state"))
			}
			if got.Get("iss") != testIssuer {
				t.Fatalf("iss = %q, want %q", got.Get("iss"), testIssuer)
			}
			if got.Get("code") != "" {
				t.Fatalf("code = %q, want none on an error redirect", got.Get("code"))
			}
		})
	}
}

// TestAuthorizeShowsLoginPage: no session, no consent — the flow renders the
// login form and carries every request parameter through hidden fields so the
// POST can re-validate them.
func TestAuthorizeShowsLoginPage(t *testing.T) {
	store := newAuthorizeStore(testClient(), activeUser(false))
	c := newTestController(&store)

	rec := doAuthorize(c, "/authorize", authorizeGet(t, validAuthorizeQuery()))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Sign in to continue") {
		t.Fatal("the login step is not rendered")
	}
	if !strings.Contains(body, `action="/authorize/login"`) {
		t.Fatal("the login form does not post to /authorize/login")
	}
	for _, name := range []string{"response_type", "client_id", "redirect_uri", "scope", "state", "nonce", "code_challenge"} {
		want := validAuthorizeQuery().Get(name)
		if !strings.Contains(body, `name="`+name+`" value="`+want+`"`) {
			t.Fatalf("hidden field %s does not carry %q", name, want)
		}
	}
	if strings.Contains(body, "Example App") {
		t.Fatal("the login page names the client; that is the consent page's job")
	}
}

// TestAuthorizeOneClickSkipsLogin: a valid session cookie goes straight to
// consent — the flow rides the panel's cookie.
func TestAuthorizeOneClickSkipsLogin(t *testing.T) {
	user := activeUser(false)
	store := newAuthorizeStore(testClient(), user)
	c := newTestController(&store)

	req := authorizeGet(t, validAuthorizeQuery())
	withSessionCookie(req, t, user)
	rec := doAuthorize(c, "/authorize", req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, "Sign in to continue") {
		t.Fatal("a valid session should skip the login step")
	}
	if !strings.Contains(body, "Example App") {
		t.Fatal("consent does not name the client")
	}
	if !strings.Contains(body, "See your email address") {
		t.Fatal("consent does not describe the email scope")
	}
	if !strings.Contains(body, "Allow") || !strings.Contains(body, "Deny") {
		t.Fatal("consent offers no Allow/Deny choice")
	}
}

// TestAuthorizeWithRetiredSessionShowsLogin: a cookie from a retired session
// epoch (a password change) is no better than no cookie.
func TestAuthorizeWithRetiredSessionShowsLogin(t *testing.T) {
	user := activeUser(false)
	retired := user
	retired.SessionEpoch = user.SessionEpoch + 1
	store := newAuthorizeStore(testClient(), retired)
	c := newTestController(&store)

	req := authorizeGet(t, validAuthorizeQuery())
	withSessionCookie(req, t, user) // minted at the old epoch
	rec := doAuthorize(c, "/authorize", req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Sign in to continue") {
		t.Fatal("a retired session should land on the login step")
	}
}

// TestAuthorizeLoginSignsInAndReturns: the login POST authenticates, starts a
// cookie session, and sends the browser back through GET /authorize with the
// original parameters intact.
func TestAuthorizeLoginSignsInAndReturns(t *testing.T) {
	salt := []byte("0123456789abcdef")
	user := activeUser(false)
	user.HashedPassword = argon2.HashPassword("rightpassword", salt)
	user.Salt = salt

	store := newAuthorizeStore(testClient(), user)
	store.getUserByEmail = func(context.Context, string) (repository.User, error) {
		return user, nil
	}
	c := newTestController(&store)

	form := validAuthorizeQuery()
	form.Set("email", user.Email)
	form.Set("password", "rightpassword")
	rec := doAuthorize(c, "/authorize/login", formRequest("/authorize/login", form))

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303: %s", rec.Code, rec.Body.String())
	}
	location, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if location.Path != "/authorize" {
		t.Fatalf("redirect path = %q, want /authorize", location.Path)
	}
	got := location.Query()
	for _, name := range []string{"response_type", "client_id", "redirect_uri", "scope", "state", "nonce", "code_challenge_method"} {
		if got.Get(name) != validAuthorizeQuery().Get(name) {
			t.Fatalf("%s = %q, want the original %q", name, got.Get(name), validAuthorizeQuery().Get(name))
		}
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
}

// TestAuthorizeLoginThenConsent walks the full browser flow: login POST, then
// GET /authorize with the cookie, and a valid session must reach consent.
func TestAuthorizeLoginThenConsent(t *testing.T) {
	salt := []byte("0123456789abcdef")
	user := activeUser(false)
	user.HashedPassword = argon2.HashPassword("rightpassword", salt)
	user.Salt = salt

	store := newAuthorizeStore(testClient(), user)
	store.getUserByEmail = func(context.Context, string) (repository.User, error) {
		return user, nil
	}
	c := newTestController(&store)

	form := validAuthorizeQuery()
	form.Set("email", user.Email)
	form.Set("password", "rightpassword")
	rec := doAuthorize(c, "/authorize/login", formRequest("/authorize/login", form))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("login status = %d, want 303", rec.Code)
	}

	req := authorizeGet(t, validAuthorizeQuery())
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == sessionCookieName {
			req.AddCookie(cookie)
		}
	}
	consent := doAuthorize(c, "/authorize", req)
	if consent.Code != http.StatusOK {
		t.Fatalf("authorize status = %d, want 200: %s", consent.Code, consent.Body.String())
	}
	if !strings.Contains(consent.Body.String(), "Example App") {
		t.Fatal("consent was not reached after login")
	}
}

// TestAuthorizeLoginRefusesBadCredentials: a wrong password re-renders the
// form with the generic message, and no session cookie is set.
func TestAuthorizeLoginRefusesBadCredentials(t *testing.T) {
	salt := []byte("0123456789abcdef")
	user := activeUser(false)
	user.HashedPassword = argon2.HashPassword("rightpassword", salt)
	user.Salt = salt

	store := newAuthorizeStore(testClient(), user)
	store.getUserByEmail = func(context.Context, string) (repository.User, error) {
		return user, nil
	}
	c := newTestController(&store)

	form := validAuthorizeQuery()
	form.Set("email", user.Email)
	form.Set("password", "wrongpassword")
	rec := doAuthorize(c, "/authorize/login", formRequest("/authorize/login", form))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Invalid email or password.") {
		t.Fatal("the login failure message is not shown")
	}
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == sessionCookieName && cookie.Value != "" {
			t.Fatal("a session cookie was set for a refused sign-in")
		}
	}
	// The parameters must survive the failed attempt, or the user would have
	// to start over.
	if !strings.Contains(rec.Body.String(), `name="state" value="st-abc123"`) {
		t.Fatal("the hidden parameters did not survive the failed login")
	}
}

// TestAuthorizeLoginRevalidatesParameters: the form POST re-validates the
// carried parameters — a tampered redirect_uri gets the error page, never a
// redirect, and no session is started.
func TestAuthorizeLoginRevalidatesParameters(t *testing.T) {
	salt := []byte("0123456789abcdef")
	user := activeUser(false)
	user.HashedPassword = argon2.HashPassword("rightpassword", salt)
	user.Salt = salt

	store := newAuthorizeStore(testClient(), user)
	store.getUserByEmail = func(context.Context, string) (repository.User, error) {
		return user, nil
	}
	c := newTestController(&store)

	form := validAuthorizeQuery()
	form.Set("redirect_uri", "https://attacker.example.com/cb")
	form.Set("email", user.Email)
	form.Set("password", "rightpassword")
	rec := doAuthorize(c, "/authorize/login", formRequest("/authorize/login", form))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Location") != "" {
		t.Fatalf("Location = %q, want none", rec.Header().Get("Location"))
	}
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == sessionCookieName && cookie.Value != "" {
			t.Fatal("a session cookie was set for a refused request")
		}
	}
}

// TestAuthorizeConsentIssuesCode: Allow mints a code, stores only its hash
// with the request's binding parameters, and redirects with code, state, and
// iss.
func TestAuthorizeConsentIssuesCode(t *testing.T) {
	user := activeUser(false)
	store := newAuthorizeStore(testClient(), user)
	c := newTestController(&store)

	req := formRequest("/authorize/consent", consentForm(validAuthorizeQuery(), false))
	withSessionCookie(req, t, user)
	rec := doAuthorize(c, "/authorize/consent", req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302: %s", rec.Code, rec.Body.String())
	}
	location, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if location.Scheme+"://"+location.Host+location.Path != testRedirectURI {
		t.Fatalf("redirect = %q, want %q", location, testRedirectURI)
	}
	got := location.Query()
	if got.Get("state") != "st-abc123" {
		t.Fatalf("state = %q, want the request's state echoed", got.Get("state"))
	}
	if got.Get("iss") != testIssuer {
		t.Fatalf("iss = %q, want %q", got.Get("iss"), testIssuer)
	}
	if got.Get("error") != "" {
		t.Fatalf("error = %q, want none on success", got.Get("error"))
	}
	code := got.Get("code")
	if code == "" {
		t.Fatal("no code was issued")
	}

	if store.minted.CodeHash == nil {
		t.Fatal("no code hash was stored")
	}
	if want := hashToken(code); string(store.minted.CodeHash) != string(want) {
		t.Fatal("the stored hash is not the hash of the issued code")
	}
	if store.minted.ClientID != testClientID {
		t.Fatalf("client_id = %q, want %q", store.minted.ClientID, testClientID)
	}
	if store.minted.UserID != user.ID {
		t.Fatalf("user_id = %q, want %q", store.minted.UserID, user.ID)
	}
	if store.minted.RedirectUri != testRedirectURI {
		t.Fatalf("redirect_uri = %q, want the exact request URI", store.minted.RedirectUri)
	}
	if store.minted.Scope != ScopeOpenID+" "+ScopeEmail {
		t.Fatalf("scope = %q, want the granted scope", store.minted.Scope)
	}
	if store.minted.Nonce != "n-abc123" {
		t.Fatalf("nonce = %q, want the request's nonce", store.minted.Nonce)
	}
	if store.minted.CodeChallenge != testChallenge {
		t.Fatalf("code_challenge = %q, want the request's challenge", store.minted.CodeChallenge)
	}
	if store.minted.SessionEpoch != user.SessionEpoch {
		t.Fatalf("session_epoch = %d, want the account's current epoch %d",
			store.minted.SessionEpoch, user.SessionEpoch)
	}
	if store.minted.ExpiresAt.Before(time.Now().Add(5 * time.Minute)) {
		t.Fatalf("expires_at = %v, want a lifetime measured in minutes", store.minted.ExpiresAt)
	}
}

// TestAuthorizeConsentDenyRedirectsWithAccessDenied: Deny refuses the grant
// and redirects with error=access_denied, state echoed, and no code stored.
func TestAuthorizeConsentDenyRedirectsWithAccessDenied(t *testing.T) {
	store := newAuthorizeStore(testClient(), activeUser(false))
	c := newTestController(&store)

	req := formRequest("/authorize/consent", consentForm(validAuthorizeQuery(), true))
	withSessionCookie(req, t, *store.account)
	rec := doAuthorize(c, "/authorize/consent", req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302: %s", rec.Code, rec.Body.String())
	}
	location, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	got := location.Query()
	if got.Get("error") != "access_denied" {
		t.Fatalf("error = %q, want access_denied", got.Get("error"))
	}
	if got.Get("state") != "st-abc123" {
		t.Fatalf("state = %q, want the request's state echoed", got.Get("state"))
	}
	if got.Get("code") != "" {
		t.Fatalf("code = %q, want none", got.Get("code"))
	}
	if store.minted.CodeHash != nil {
		t.Fatal("a code was stored for a denied request")
	}
}

// TestAuthorizeConsentWithDeadSessionShowsLogin: the session died between the
// consent page and the submit — the user is asked to sign in again, not
// bounced to a redirect error.
func TestAuthorizeConsentWithDeadSessionShowsLogin(t *testing.T) {
	user := activeUser(false)
	store := newAuthorizeStore(testClient(), user)
	c := newTestController(&store)

	req := formRequest("/authorize/consent", consentForm(validAuthorizeQuery(), false))
	// A cookie minted at a different epoch: the session is retired.
	req.AddCookie(&http.Cookie{
		Name:  sessionCookieName,
		Value: signClaims(t, testSigningKey, mintedClaims(user.ID.String(), user.SessionEpoch+1)),
	})
	rec := doAuthorize(c, "/authorize/consent", req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Sign in to continue") {
		t.Fatal("a dead session should land on the login step")
	}
	if store.minted.CodeHash != nil {
		t.Fatal("a code was issued without a live session")
	}
}

// TestAuthorizeConsentRevalidatesParameters: the consent POST re-validates
// the carried parameters; a tampered client_id is refused with the error page.
func TestAuthorizeConsentRevalidatesParameters(t *testing.T) {
	store := newAuthorizeStore(testClient(), activeUser(false))
	c := newTestController(&store)

	form := consentForm(validAuthorizeQuery(), false)
	form.Set("client_id", "not-registered")
	req := formRequest("/authorize/consent", form)
	withSessionCookie(req, t, *store.account)
	rec := doAuthorize(c, "/authorize/consent", req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Location") != "" {
		t.Fatalf("Location = %q, want none", rec.Header().Get("Location"))
	}
	if store.minted.CodeHash != nil {
		t.Fatal("a code was stored for a refused request")
	}
}

// TestAuthorizeRequiresPOSTForFormSteps: the login and consent steps are form
// posts; a GET on them is a routing mistake.
func TestAuthorizeRequiresPOSTForFormSteps(t *testing.T) {
	c := newTestController(fakeStore{})
	for _, path := range []string{"/authorize/login", "/authorize/consent"} {
		rec := doAuthorize(c, path, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("GET %s status = %d, want 405", path, rec.Code)
		}
	}
}

// TestParseScope covers the scope parser directly: dedup with order kept,
// openid required, unknown scopes refused.
func TestParseScope(t *testing.T) {
	allowed := []string{ScopeOpenID, ScopeEmail}

	cases := []struct {
		name    string
		raw     string
		want    []string
		ok      bool
		ceiling []string
	}{
		{name: "openid only", raw: ScopeOpenID, want: []string{ScopeOpenID}, ok: true, ceiling: allowed},
		{name: "both, in order", raw: ScopeOpenID + " " + ScopeEmail, want: []string{ScopeOpenID, ScopeEmail}, ok: true, ceiling: allowed},
		{name: "duplicates collapse", raw: ScopeOpenID + " " + ScopeOpenID + " " + ScopeEmail, want: []string{ScopeOpenID, ScopeEmail}, ok: true, ceiling: allowed},
		{name: "missing openid", raw: ScopeEmail, ok: false, ceiling: allowed},
		{name: "empty", raw: "", ok: false, ceiling: allowed},
		{name: "unknown scope", raw: ScopeOpenID + " profile", ok: false, ceiling: allowed},
		{name: "outside the client ceiling", raw: ScopeOpenID + " " + ScopeEmail, ok: false, ceiling: []string{ScopeOpenID}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseScope(tc.raw, tc.ceiling)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if tc.ok && strings.Join(got, " ") != strings.Join(tc.want, " ") {
				t.Fatalf("scopes = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestValidatePKCE covers the challenge checks directly: required for public
// clients, optional but validated for confidential ones, S256 only.
func TestValidatePKCE(t *testing.T) {
	cases := []struct {
		name      string
		challenge string
		method    string
		required  bool
		ok        bool
	}{
		{name: "valid S256", challenge: testChallenge, method: PKCEMethodS256, required: true, ok: true},
		{name: "valid S256, 128 chars", challenge: strings.Repeat("A", 128), method: PKCEMethodS256, required: true, ok: true},
		{name: "optional for confidential", challenge: "", method: "", required: false, ok: true},
		{name: "required but missing", challenge: "", method: "", required: true, ok: false},
		{name: "plain refused", challenge: testChallenge, method: "plain", required: true, ok: false},
		{name: "missing method means plain", challenge: testChallenge, method: "", required: true, ok: false},
		{name: "too short", challenge: strings.Repeat("A", 42), method: PKCEMethodS256, required: true, ok: false},
		{name: "too long", challenge: strings.Repeat("A", 129), method: PKCEMethodS256, required: true, ok: false},
		{name: "bad alphabet", challenge: strings.Repeat("A", 42) + "+", method: PKCEMethodS256, required: true, ok: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := validatePKCE(tc.challenge, tc.method, tc.required); got != tc.ok {
				t.Fatalf("validatePKCE = %v, want %v", got, tc.ok)
			}
		})
	}
}

// TestRedirectWithQuery covers query joining: a registered URI may already
// carry a query, and it must be kept.
func TestRedirectWithQuery(t *testing.T) {
	q := url.Values{"code": {"abc"}}
	if got := redirectWithQuery("https://app.example.com/cb", q); got != "https://app.example.com/cb?code=abc" {
		t.Fatalf("plain URI redirect = %q", got)
	}
	if got := redirectWithQuery("https://app.example.com/cb?a=1", q); got != "https://app.example.com/cb?a=1&code=abc" {
		t.Fatalf("URI with query redirect = %q", got)
	}
}
