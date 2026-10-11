package rest

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ccarlfjord/user/internal/repository"
	"github.com/jackc/pgx/v5"
)

// authorizationCodeTTL is how long an issued code stays redeemable. It is
// minutes on purpose: the code is a bearer credential that only has to survive
// the redirect back to the client and the exchange request.
const authorizationCodeTTL = 10 * time.Minute

// PKCEMethodS256 is the only code-challenge method this provider accepts.
// The alternative the spec defines — plain, the default when the method is
// omitted — sends the verifier itself over the redirect chain, which defeats
// the point of the proof, so a bare challenge is refused.
const PKCEMethodS256 = "S256"

// authorizeParams is the parsed form of an /authorize request. The same
// parameters ride through the login and consent forms as hidden fields, and
// every POST handler re-validates from them, so the pages stay stateless.
type authorizeParams struct {
	ResponseType        string
	ClientID            string
	RedirectURI         string
	Scope               string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
}

// authorizeParamsFromRequest reads the parameters from an incoming
// GET /authorize query string.
func authorizeParamsFromRequest(r *http.Request) authorizeParams {
	q := r.URL.Query()
	return authorizeParams{
		ResponseType:        q.Get("response_type"),
		ClientID:            q.Get("client_id"),
		RedirectURI:         q.Get("redirect_uri"),
		Scope:               q.Get("scope"),
		State:               q.Get("state"),
		Nonce:               q.Get("nonce"),
		CodeChallenge:       q.Get("code_challenge"),
		CodeChallengeMethod: q.Get("code_challenge_method"),
	}
}

// authorizeParamsFromForm reads the parameters back out of the hidden fields
// a login or consent form posted.
func authorizeParamsFromForm(r *http.Request) authorizeParams {
	return authorizeParams{
		ResponseType:        r.PostFormValue("response_type"),
		ClientID:            r.PostFormValue("client_id"),
		RedirectURI:         r.PostFormValue("redirect_uri"),
		Scope:               r.PostFormValue("scope"),
		State:               r.PostFormValue("state"),
		Nonce:               r.PostFormValue("nonce"),
		CodeChallenge:       r.PostFormValue("code_challenge"),
		CodeChallengeMethod: r.PostFormValue("code_challenge_method"),
	}
}

// query rebuilds the request parameters as a query string, used to send the
// browser back through GET /authorize after a successful form login. The
// round-trip through the URL re-enters the flow at the top, so the redirect
// after login carries exactly the parameters the user started with — and the
// handler re-validates them like any other request.
func (p authorizeParams) query() url.Values {
	q := url.Values{}
	if p.ResponseType != "" {
		q.Set("response_type", p.ResponseType)
	}
	if p.ClientID != "" {
		q.Set("client_id", p.ClientID)
	}
	if p.RedirectURI != "" {
		q.Set("redirect_uri", p.RedirectURI)
	}
	if p.Scope != "" {
		q.Set("scope", p.Scope)
	}
	if p.State != "" {
		q.Set("state", p.State)
	}
	if p.Nonce != "" {
		q.Set("nonce", p.Nonce)
	}
	if p.CodeChallenge != "" {
		q.Set("code_challenge", p.CodeChallenge)
	}
	if p.CodeChallengeMethod != "" {
		q.Set("code_challenge_method", p.CodeChallengeMethod)
	}
	return q
}

// authorizeFailure describes a refused authorization request, in one of the
// two ways the flow allows. A request is refused with an error page while
// there is no validated redirect URI to send the user to — redirecting to an
// unvalidated URL would let a malformed request turn the server into an open
// redirector. Once client_id and redirect_uri check out, refusals are sent to
// that redirect URI as OAuth error parameters (RFC 6749 §4.1.2.1), with state
// echoed back so the client can match the response to its request.
type authorizeFailure struct {
	status   int    // HTTP status of the error page
	page     string // message for the error page, set only before redirect validation
	redirect string // OAuth error code, set only once the redirect URI is validated
	detail   string // human-readable description sent alongside the error code
}

// authorizeHandler routes the three browser endpoints of the flow. Only GET
// /authorize reads the query string; the two POSTs are the form steps that
// carry the parameters as hidden fields.
func (c *controller) authorizeHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		c.authorize(w, r)
	default:
		methodNotAllowed(w)
	}
}

func (c *controller) authorizeLoginHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		c.authorizeLogin(w, r)
	default:
		methodNotAllowed(w)
	}
}

func (c *controller) authorizeConsentHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		c.authorizeConsent(w, r)
	default:
		methodNotAllowed(w)
	}
}

// authorize is the top of the flow. It validates the request, then either
// shows the login form (no usable session) or the consent page (session found
// in the cookie). Issuing a code is the consent POST's job: a GET must never
// mint anything, since prefetchers and link previews walk GETs without a user.
func (c *controller) authorize(w http.ResponseWriter, r *http.Request) {
	params := authorizeParamsFromRequest(r)

	client, scopes, failure, ok := c.validateAuthorize(r.Context(), params)
	if !ok {
		c.authorizeFailure(w, r, params, failure)
		return
	}

	user, ok, err := c.cookieUser(r)
	if err != nil {
		slog.Error(err.Error())
		http.Error(w, "failed to load authorization", http.StatusInternalServerError)
		return
	}
	if ok {
		render(w, r, authorizeConsentPage(client.Name, scopes, params))
		slog.Debug("authorization consent shown", "client", client.ClientID, "user", user.ID)
		return
	}
	render(w, r, authorizeLoginPage(params, ""))
}

// authorizeLogin handles the login form. It re-validates the carried
// parameters (they came back over the wire from a form, so they get no trust
// for free), authenticates the user the way the API and panel logins do, and
// on success starts a cookie session and sends the browser back through
// GET /authorize — which now finds the session and shows consent.
func (c *controller) authorizeLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		render(w, r, authorizeErrorPage("Invalid request."))
		return
	}

	params := authorizeParamsFromForm(r)
	if _, _, failure, ok := c.validateAuthorize(r.Context(), params); !ok {
		c.authorizeFailure(w, r, params, failure)
		return
	}

	user, err := c.authenticate(r.Context(), r.PostFormValue("email"), r.PostFormValue("password"))
	if errors.Is(err, errInvalidCredentials) {
		// Same message for a bad password and for an account that exists but
		// is not verified, so the form does not confirm who is registered.
		render(w, r, authorizeLoginPage(params, "Invalid email or password."))
		return
	} else if err != nil {
		slog.Error(err.Error())
		http.Error(w, "failed to sign in", http.StatusInternalServerError)
		return
	}

	token, err := c.mintSession(user)
	if err != nil {
		slog.Error(err.Error())
		http.Error(w, "failed to sign in", http.StatusInternalServerError)
		return
	}

	setSessionCookie(w, token)
	http.Redirect(w, r, "/authorize?"+params.query().Encode(), http.StatusSeeOther)
}

// authorizeConsent handles the Allow/Deny form. Everything is re-validated
// from the posted parameters, the session is re-resolved from the cookie (it
// may have expired or been retired between the page render and this submit),
// and only then is a code minted and the browser redirected to the client.
func (c *controller) authorizeConsent(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		render(w, r, authorizeErrorPage("Invalid request."))
		return
	}

	params := authorizeParamsFromForm(r)
	client, scopes, failure, ok := c.validateAuthorize(r.Context(), params)
	if !ok {
		c.authorizeFailure(w, r, params, failure)
		return
	}

	user, ok, err := c.cookieUser(r)
	if err != nil {
		slog.Error(err.Error())
		http.Error(w, "failed to complete authorization", http.StatusInternalServerError)
		return
	}
	if !ok {
		// The session died between the consent page and this submit. Re-render
		// the login step with the parameters intact rather than bouncing to a
		// redirect error: the user only needs to sign in again.
		render(w, r, authorizeLoginPage(params, ""))
		return
	}

	if r.PostFormValue("deny") != "" {
		c.authorizeRedirectError(w, r, params.RedirectURI, "access_denied",
			"the resource owner denied the request", params.State)
		return
	}

	code, err := c.issueAuthorizationCode(r.Context(), user, client, params, strings.Join(scopes, " "))
	if err != nil {
		slog.Error(err.Error())
		http.Error(w, "failed to complete authorization", http.StatusInternalServerError)
		return
	}

	// RFC 6749 §4.1.2: the redirect is a 302 to the client with the code and,
	// when the request carried one, the echoed state. iss goes along so the
	// client can tell which provider redirected it when more than one could.
	q := url.Values{"code": {code}, "iss": {c.issuer}}
	if params.State != "" {
		q.Set("state", params.State)
	}
	http.Redirect(w, r, redirectWithQuery(params.RedirectURI, q), http.StatusFound)
}

// issueAuthorizationCode mints a code and stores its hash with everything the
// token exchange will need to bind against: the exact redirect URI presented,
// the granted scope, the ID-token nonce, the PKCE challenge, and the account's
// current session epoch so a password change after consent retires the code.
// Only the hash is stored; the value exists in the redirect and nowhere else.
func (c *controller) issueAuthorizationCode(ctx context.Context, user repository.User,
	client repository.OauthClient, params authorizeParams, scope string) (string, error) {

	code, err := generateToken()
	if err != nil {
		return "", err
	}

	err = c.db.CreateAuthorizationCode(ctx, repository.CreateAuthorizationCodeParams{
		CodeHash:      hashToken(code),
		ClientID:      client.ClientID,
		UserID:        user.ID,
		RedirectUri:   params.RedirectURI,
		Scope:         scope,
		Nonce:         params.Nonce,
		CodeChallenge: params.CodeChallenge,
		SessionEpoch:  user.SessionEpoch,
		ExpiresAt:     time.Now().Add(authorizationCodeTTL),
	})
	if err != nil {
		return "", err
	}
	return code, nil
}

// validateAuthorize runs every check the flow needs and reports how far it
// got. Requests are refused in the order the pieces of the request can be
// trusted: client_id is resolved first (an unknown or inactive client gets an
// error page, never a redirect), then redirect_uri is exact-matched against
// the client's registered URIs (still an error page on mismatch), and only
// then — with a validated destination in hand — do response_type, scope, and
// PKCE refusals go back to the redirect URI as error parameters.
func (c *controller) validateAuthorize(ctx context.Context, params authorizeParams) (
	repository.OauthClient, []string, authorizeFailure, bool) {

	if params.ClientID == "" {
		return repository.OauthClient{}, nil, authorizeFailure{
			status: http.StatusBadRequest,
			page:   "The request is missing the client identifier.",
		}, false
	}

	client, err := c.db.GetClientById(ctx, params.ClientID)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			slog.Error(err.Error())
		}
		// The same page for unknown and inactive clients: the error is the
		// requester's configuration problem, not the user's, and the flow
		// must not proceed against either.
		return repository.OauthClient{}, nil, authorizeFailure{
			status: http.StatusBadRequest,
			page:   "The application that started this sign-in is not recognized by this provider.",
		}, false
	}
	if !client.Active {
		return repository.OauthClient{}, nil, authorizeFailure{
			status: http.StatusBadRequest,
			page:   "The application that started this sign-in is not recognized by this provider.",
		}, false
	}

	if params.RedirectURI == "" {
		return repository.OauthClient{}, nil, authorizeFailure{
			status: http.StatusBadRequest,
			page:   "The request is missing a redirect URI.",
		}, false
	}
	if !redirectURIRegistered(params.RedirectURI, client.RedirectUris) {
		return repository.OauthClient{}, nil, authorizeFailure{
			status: http.StatusBadRequest,
			page:   "The redirect URI in the request does not match one registered for the application.",
		}, false
	}

	// From here on the redirect URI is validated, so refusals are redirects.
	if params.ResponseType != "code" {
		return client, nil, authorizeFailure{
			redirect: "unsupported_response_type",
			detail:   "only the authorization code flow is supported",
		}, false
	}

	scopes, ok := parseScope(params.Scope, client.AllowedScopes)
	if !ok {
		return client, nil, authorizeFailure{
			redirect: "invalid_scope",
			detail:   "the requested scope is outside what this application may ask for",
		}, false
	}

	if !validatePKCE(params.CodeChallenge, params.CodeChallengeMethod, client.IsPublic) {
		return client, nil, authorizeFailure{
			redirect: "invalid_request",
			detail:   "the PKCE code challenge is missing or malformed (only S256 is supported)",
		}, false
	}

	return client, scopes, authorizeFailure{}, true
}

// authorizeFailure renders or redirects a refused request according to how
// far validation got. A page failure renders the HTML error page; a redirect
// failure goes back to the (already validated) redirect URI with the error,
// echoing the client's state so the response can be matched to the request.
func (c *controller) authorizeFailure(w http.ResponseWriter, r *http.Request,
	params authorizeParams, failure authorizeFailure) {
	if failure.page != "" {
		w.WriteHeader(failure.status)
		render(w, r, authorizeErrorPage(failure.page))
		return
	}
	c.authorizeRedirectError(w, r, params.RedirectURI, failure.redirect, failure.detail, params.State)
}

// authorizeRedirectError sends the browser back to redirectURI with the OAuth
// error parameters. The URI must already have been validated; the empty form
// is only used from authorizeFailure, which passes through an unvalidated URI
// only when there is no redirect failure at all. state is echoed, not
// verified — it belongs to the client.
func (c *controller) authorizeRedirectError(w http.ResponseWriter, r *http.Request,
	redirectURI, code, detail, state string) {

	q := url.Values{"error": {code}, "iss": {c.issuer}}
	if detail != "" {
		q.Set("error_description", detail)
	}
	if state != "" {
		q.Set("state", state)
	}
	http.Redirect(w, r, redirectWithQuery(redirectURI, q), http.StatusFound)
}

// redirectWithQuery appends query parameters to a redirect URI, keeping any
// query the URI already carries (registered URIs may contain one).
func redirectWithQuery(redirectURI string, q url.Values) string {
	if strings.Contains(redirectURI, "?") {
		return redirectURI + "&" + q.Encode()
	}
	return redirectURI + "?" + q.Encode()
}

// redirectURIRegistered reports whether uri exactly matches one of the URIs
// registered for the client. Registered URIs are compared verbatim: no
// wildcards, no pattern matching, no trailing-slash tolerance.
func redirectURIRegistered(uri string, registered []string) bool {
	for _, candidate := range registered {
		if uri == candidate {
			return true
		}
	}
	return false
}

// parseScope splits the space-separated scope parameter and checks every
// scope against both the provider vocabulary and the client's grant ceiling,
// so token exchange never has to widen a grant. Duplicates are collapsed
// while order is kept, so the stored scope renders back the way it was asked.
// `openid` is required: without it this is not an OIDC request and there is no
// ID token to issue.
func parseScope(raw string, allowed []string) ([]string, bool) {
	if raw == "" {
		return nil, false
	}
	fields := strings.Fields(raw)
	scopes := make([]string, 0, len(fields))
	seen := make(map[string]bool, len(fields))
	for _, scope := range fields {
		if seen[scope] {
			continue
		}
		if !scopeSupported(scope) || !scopeAllowed(scope, allowed) {
			return nil, false
		}
		seen[scope] = true
		scopes = append(scopes, scope)
	}
	if !seen[ScopeOpenID] {
		return nil, false
	}
	return scopes, true
}

// scopeSupported reports whether scope is in the provider's vocabulary.
func scopeSupported(scope string) bool {
	for _, candidate := range supportedScopes {
		if scope == candidate {
			return true
		}
	}
	return false
}

// scopeAllowed reports whether scope is within the client's grant ceiling.
func scopeAllowed(scope string, allowed []string) bool {
	for _, candidate := range allowed {
		if scope == candidate {
			return true
		}
	}
	return false
}

// validatePKCE checks the code_challenge/code_challenge_method pair. A public
// client must always present a challenge — it has no client secret, so PKCE
// is the only proof the code exchange comes from the party that started the
// flow — and a confidential client may present one but not a malformed one.
// Only S256 is accepted: a challenge without the method would mean plain,
// which sends the verifier itself over the redirect chain.
func validatePKCE(challenge, method string, required bool) bool {
	if challenge == "" {
		return !required
	}
	if method != PKCEMethodS256 {
		return false
	}
	// RFC 7636 §4.2: the challenge is 43–128 characters of the base64url
	// alphabet — the shape a SHA-256 digest of a verifier encodes to.
	if len(challenge) < 43 || len(challenge) > 128 {
		return false
	}
	for _, r := range challenge {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9',
			r == '-', r == '.', r == '_', r == '~':
		default:
			return false
		}
	}
	return true
}

// cookieUser resolves the browser session for the authorize flow: the session
// cookie only, never the Authorization header, because this endpoint is
// navigated by a browser. The checks are the ones requireSession applies —
// signed by the current key, live account, current session epoch — so a
// session the API would reject is also rejected here. A false result with no
// error means "no usable session" and the caller renders the login page; an
// error is an infrastructure failure the caller reports as 500.
func (c *controller) cookieUser(r *http.Request) (repository.User, bool, error) {
	raw, ok := cookieSession(r)
	if !ok {
		return repository.User{}, false, nil
	}
	return c.sessionUser(r, raw)
}
