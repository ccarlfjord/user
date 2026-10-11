package rest

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ccarlfjord/user/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// The token_endpoint_auth_method values RFC 7591 names that this provider
// understands. `none` is a public client (SPA or native app: no secret, PKCE
// mandatory); the two secret methods make a confidential client, whose secret
// is checked at /token — which of basic or post it is does not change what is
// stored, so both are accepted and the choice rides through to /token later.
const (
	tokenAuthMethodNone  = "none"
	tokenAuthMethodBasic = "client_secret_basic"
	tokenAuthMethodPost  = "client_secret_post"
)

// grantTypeAuthorizationCode is the grant /authorize issues codes for, and the
// only one a registered client can exchange today. refresh_token may be asked
// for now so /token can honor it the moment that grant lands.
const grantTypeAuthorizationCode = "authorization_code"

// maxClientNameLength caps the name the consent page will render.
const maxClientNameLength = 200

// registrationRequest is the client metadata an RP posts to /register. Only
// the members this provider has somewhere to put are named; RFC 7591 says
// unrecognized members are ignored, so unknown fields decode away harmlessly.
type registrationRequest struct {
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	ClientName              string   `json:"client_name"`
	Scope                   string   `json:"scope"`
	Contacts                []string `json:"contacts"` // accepted, not stored yet
}

// registrationResponse is the effective registration returned on 201. It
// echoes the server's defaults for members the request omitted, and returns
// client_secret once, in plaintext, for a confidential client — only its
// SHA-256 hash is stored, so it cannot be recovered later.
type registrationResponse struct {
	ClientID                string   `json:"client_id"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientSecretExpiresAt   *int64   `json:"client_secret_expires_at,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name"`
	Scope                   string   `json:"scope"`
}

// registrationError is the RFC 7591 §3.2.2 error body. invalid_redirect_uri
// and invalid_client_metadata are the only two codes the spec defines for
// registration, so every metadata problem maps to one of them.
type registrationError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

func registrationErrorResponse(w http.ResponseWriter, status int, code, description string) {
	JSON(w, status, registrationError{Error: code, ErrorDescription: description})
}

func (c *controller) registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	c.register(w, r)
}

// register implements RFC 7591 dynamic client registration, gated by an
// initial access token. Open registration would let anyone mint a client and
// put its name in front of users on the consent page, so a token is minted
// out-of-band per relying party and burned on use. The order is deliberate:
// the gate is checked for presence before anything else (an anonymous caller
// gets 401, not metadata validation feedback), metadata is validated before
// the token is consumed — a typo should not burn the token — and consumption
// is an atomic delete, so two parallel registrations with one token cannot
// both pass.
func (c *controller) register(w http.ResponseWriter, r *http.Request) {
	if !validateContentTypeJSON(w, r) {
		return
	}

	token, ok := bearerToken(r.Header.Get("Authorization"))
	if !ok {
		unauthorized(w)
		return
	}

	var req registrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		registrationErrorResponse(w, http.StatusBadRequest, "invalid_client_metadata",
			"the request body is not valid client metadata")
		return
	}

	params, effective, regErr, ok := validateRegistration(req)
	if !ok {
		registrationErrorResponse(w, http.StatusBadRequest, regErr.code, regErr.description)
		return
	}

	// The token is spent only once the request is known to be well-formed. If
	// client creation fails after this point the token is burned with it: the
	// two writes run on one connection each but not in one transaction, and a
	// failed insert is rare enough that re-issuing a token beats the extra
	// ceremony of a transaction.
	stored, err := c.db.ConsumeRegistrationToken(r.Context(), hashToken(token))
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

	client, err := c.db.CreateClient(r.Context(), params)
	if err != nil {
		slog.Error(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	response := registrationResponse{
		ClientID:                client.ClientID,
		ClientIDIssuedAt:        time.Now().Unix(),
		TokenEndpointAuthMethod: effective.TokenEndpointAuthMethod,
		GrantTypes:              effective.GrantTypes,
		ResponseTypes:           effective.ResponseTypes,
		RedirectURIs:            params.RedirectUris,
		ClientName:              params.Name,
		Scope:                   effective.Scope,
	}
	if effective.ClientSecret != "" {
		// client_secret_expires_at is REQUIRED whenever client_secret is
		// returned; 0 means it does not expire. The secret itself exists only
		// in this response.
		never := int64(0)
		response.ClientSecret = effective.ClientSecret
		response.ClientSecretExpiresAt = &never
		slog.Debug("registered confidential client", "client_id", client.ClientID)
	} else {
		slog.Debug("registered public client", "client_id", client.ClientID)
	}

	JSON(w, http.StatusCreated, response)
}

// effectiveRegistration is the metadata the registration actually takes,
// with the request's omissions filled in by their defaults — the response
// echoes these, so the RP sees exactly what was registered.
type effectiveRegistration struct {
	ClientSecret            string
	TokenEndpointAuthMethod string
	GrantTypes              []string
	ResponseTypes           []string
	Scope                   string
}

// regErr carries one of RFC 7591's two registration error codes.
type regErr struct {
	code        string
	description string
}

// validateRegistration turns posted metadata into a CreateClient call. Every
// omission gets its RFC default; everything outside the defaults is refused —
// the store's CHECK constraints catch what this does not.
func validateRegistration(req registrationRequest) (repository.CreateClientParams, effectiveRegistration, regErr, bool) {
	invalid := func(description string) (repository.CreateClientParams, effectiveRegistration, regErr, bool) {
		return repository.CreateClientParams{}, effectiveRegistration{},
			regErr{code: "invalid_client_metadata", description: description}, false
	}

	// redirect_uris: required, exact-match strings, stored verbatim. An https
	// URI for web clients; plain http only on loopback for native app
	// development (RFC 8252). No fragments — a fragment never reaches a
	// server, so it could not match at redirect time anyway.
	if len(req.RedirectURIs) == 0 {
		return repository.CreateClientParams{}, effectiveRegistration{},
			regErr{code: "invalid_redirect_uri", description: "at least one redirect_uri is required"}, false
	}
	for _, uri := range req.RedirectURIs {
		if !validRegistrationRedirectURI(uri) {
			return repository.CreateClientParams{}, effectiveRegistration{},
				regErr{code: "invalid_redirect_uri",
					description: "redirect_uri must be an absolute https URL (or http on loopback), without a fragment"}, false
		}
	}

	// token_endpoint_auth_method: defaults to client_secret_basic, i.e. a
	// confidential client holding a secret. `none` makes it public.
	method := req.TokenEndpointAuthMethod
	if method == "" {
		method = tokenAuthMethodBasic
	}
	var isPublic bool
	switch method {
	case tokenAuthMethodNone:
		isPublic = true
	case tokenAuthMethodBasic, tokenAuthMethodPost:
		isPublic = false
	default:
		return invalid("unsupported token_endpoint_auth_method; use none, client_secret_basic, or client_secret_post")
	}

	// grant_types: authorization_code is the flow this provider runs, so it is
	// both the default and the only grant a client may not omit. refresh_token
	// may ride along for when that grant lands at /token.
	grantTypes := req.GrantTypes
	if len(grantTypes) == 0 {
		grantTypes = []string{grantTypeAuthorizationCode}
	}
	hasCode := false
	for _, grant := range grantTypes {
		if grant == grantTypeAuthorizationCode {
			hasCode = true
			continue
		}
		if grant != "refresh_token" {
			return invalid("unsupported grant_types; only authorization_code and refresh_token are supported")
		}
	}
	if !hasCode {
		return invalid("grant_types must include authorization_code")
	}

	// response_types: `code` only. Anything else is refused here rather than
	// at /authorize, so an RP that intends the implicit or hybrid flow learns
	// it at registration.
	responseTypes := req.ResponseTypes
	if len(responseTypes) == 0 {
		responseTypes = []string{"code"}
	}
	for _, responseType := range responseTypes {
		if responseType != "code" {
			return invalid("unsupported response_types; only code is supported")
		}
	}

	// client_name: required — the consent page shows it to the user, so an
	// anonymous client has nothing honest to display.
	name := strings.TrimSpace(req.ClientName)
	if name == "" {
		return invalid("client_name is required; it is shown to users on the consent page")
	}
	if len(name) > maxClientNameLength {
		return invalid("client_name is too long")
	}

	// scope: defaults to `openid`, the only scope OIDC requires. The requested
	// set becomes the client's grant ceiling — /authorize will refuse any
	// request outside it, so the client cannot widen its own grant later.
	scope := req.Scope
	if strings.TrimSpace(scope) == "" {
		scope = ScopeOpenID
	}
	scopes, ok := parseScope(scope, supportedScopes)
	if !ok {
		return invalid("scope must be a space-separated subset of the scopes this provider supports")
	}

	params := repository.CreateClientParams{
		ClientID:      uuid.NewString(),
		IsPublic:      isPublic,
		Name:          name,
		RedirectUris:  req.RedirectURIs,
		AllowedScopes: scopes,
		Active:        true,
	}
	effective := effectiveRegistration{
		TokenEndpointAuthMethod: method,
		GrantTypes:              grantTypes,
		ResponseTypes:           responseTypes,
		Scope:                   strings.Join(scopes, " "),
	}

	// A confidential client gets a random secret now, hashed for the store;
	// the plaintext is returned once and exists nowhere else. It is hashed
	// with SHA-256, not argon2id: the secret is server-generated 256-bit
	// randomness, so there is no low-entropy guess to slow down and no salt
	// to make precomputation infeasible — a fast hash is already
	// irreversible against it. Argon2id stays reserved for passwords, the
	// only credential a person chooses; /token verifies this hash with the
	// same single hashToken() lookup refresh and registration tokens use.
	if !isPublic {
		secret, err := generateToken()
		if err != nil {
			slog.Error(err.Error())
			return repository.CreateClientParams{}, effectiveRegistration{},
				regErr{code: "invalid_client_metadata", description: "failed to mint a client secret"}, false
		}
		params.ClientSecretHash = hashToken(secret)
		effective.ClientSecret = secret
	}

	return params, effective, regErr{}, true
}

// validRegistrationRedirectURI checks one redirect_uri at registration time:
// absolute, https (or http on loopback for native app development), with a
// host, and without a fragment. The verbatim exact-match comparison at
// /authorize is what makes these URIs safe; this only keeps unusable ones out
// of the store.
func validRegistrationRedirectURI(uri string) bool {
	parsed, err := url.Parse(uri)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.Fragment != "" {
		return false
	}
	switch parsed.Scheme {
	case "https":
		return true
	case "http":
		return isLoopbackHost(parsed.Hostname())
	default:
		return false
	}
}

// isLoopbackHost reports whether host is one of the loopback names RFC 8252
// allows for plain-http native app redirects.
func isLoopbackHost(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}
