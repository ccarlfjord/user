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

// registrationRequest is the client metadata an RP posts to /register, and
// the same body a management PUT sends under RFC 7592. Only the members this
// provider has somewhere to put are named; RFC 7591 says unrecognized members
// are ignored, so unknown fields decode away harmlessly.
type registrationRequest struct {
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	ClientName              string   `json:"client_name"`
	Scope                   string   `json:"scope"`
	Contacts                []string `json:"contacts"` // accepted, not stored yet
}

// registrationResponse is the effective registration returned on 201 and on a
// management read or update. It echoes the server's defaults for members the
// request omitted, and returns client_secret once, in plaintext, for a
// confidential client — only its SHA-256 hash is stored, so it cannot be
// recovered later. registration_access_token is likewise returned once per
// issuance, and authenticates the RFC 7592 management endpoints.
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
	// Included only when this response just minted the token. A read cannot
	// echo it back (only the hash is stored), so omitting it beats handing the
	// client an empty string to overwrite its stored copy with.
	RegistrationAccessToken string `json:"registration_access_token,omitempty"`
	RegistrationClientURI   string `json:"registration_client_uri"`
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

	metadata, regErr, ok := validateClientMetadata(req, tokenAuthMethodBasic)
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

	creds, err := mintClientCredentials(metadata.IsPublic)
	if err != nil {
		slog.Error(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	client, err := c.db.CreateClient(r.Context(), newClientParams(metadata, creds))
	if err != nil {
		slog.Error(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	slog.Debug("registered client", "client_id", client.ClientID, "public", metadata.IsPublic)
	JSON(w, http.StatusCreated, c.clientInformation(client, creds))
}

// clientMetadata is the validated, defaulted client metadata shared by
// registration and management updates. It carries no credentials and no
// client id: those are minted per operation, so a PUT cannot accidentally
// reuse or discard the wrong one.
type clientMetadata struct {
	TokenEndpointAuthMethod string
	IsPublic                bool
	Name                    string
	RedirectURIs            []string
	AllowedScopes           []string
	GrantTypes              []string
	ResponseTypes           []string
}

// clientCredentials are the plaintext secrets minted for a client. Each is
// returned exactly once and stored only as a hash; an empty field means the
// operation did not re-issue that credential.
type clientCredentials struct {
	ClientSecret            string
	RegistrationAccessToken string
}

// mintClientCredentials generates the credentials a fresh registration needs:
// a client secret for a confidential client, and always a registration access
// token for the RFC 7592 management endpoints.
func mintClientCredentials(isPublic bool) (clientCredentials, error) {
	var creds clientCredentials
	if !isPublic {
		secret, err := generateToken()
		if err != nil {
			return clientCredentials{}, err
		}
		creds.ClientSecret = secret
	}
	token, err := generateToken()
	if err != nil {
		return clientCredentials{}, err
	}
	creds.RegistrationAccessToken = token
	return creds, nil
}

// newClientParams assembles the store call for a fresh registration.
func newClientParams(metadata clientMetadata, creds clientCredentials) repository.CreateClientParams {
	params := repository.CreateClientParams{
		ClientID:                    uuid.NewString(),
		IsPublic:                    metadata.IsPublic,
		Name:                        metadata.Name,
		RedirectUris:                metadata.RedirectURIs,
		AllowedScopes:               metadata.AllowedScopes,
		TokenEndpointAuthMethod:     metadata.TokenEndpointAuthMethod,
		GrantTypes:                  metadata.GrantTypes,
		ResponseTypes:               metadata.ResponseTypes,
		RegistrationAccessTokenHash: hashToken(creds.RegistrationAccessToken),
		Active:                      true,
	}
	if creds.ClientSecret != "" {
		params.ClientSecretHash = hashToken(creds.ClientSecret)
	}
	return params
}

// clientInformation renders a stored client as the RFC 7591/7592 client
// information response. A secret or registration token is included only when
// the operation just minted it, so a read does not pretend to return a
// credential the server can no longer reconstruct.
func (c *controller) clientInformation(client repository.OauthClient, creds clientCredentials) registrationResponse {
	response := registrationResponse{
		ClientID:                client.ClientID,
		ClientIDIssuedAt:        client.CreatedAt.Unix(),
		TokenEndpointAuthMethod: client.TokenEndpointAuthMethod,
		GrantTypes:              client.GrantTypes,
		ResponseTypes:           client.ResponseTypes,
		RedirectURIs:            client.RedirectUris,
		ClientName:              client.Name,
		Scope:                   strings.Join(client.AllowedScopes, " "),
		RegistrationAccessToken: creds.RegistrationAccessToken,
		RegistrationClientURI:   c.issuer + "/register/" + client.ClientID,
	}
	if creds.ClientSecret != "" {
		// client_secret_expires_at is REQUIRED whenever client_secret is
		// returned; 0 means it does not expire. The secret itself exists only
		// in this response.
		never := int64(0)
		response.ClientSecret = creds.ClientSecret
		response.ClientSecretExpiresAt = &never
	}
	return response
}

// regErr carries one of RFC 7591's two registration error codes.
type regErr struct {
	code        string
	description string
}

// validateClientMetadata applies every rule a registration must pass: the
// redirect URIs are usable exact-match strings, the auth method maps to
// public or confidential, the grant and response types are in the provider's
// fixed sets, the name exists for the consent page, and the scope is inside
// both the provider vocabulary and nothing wider. Every omission gets a
// default; everything outside the defaults is refused. Both /register and a
// management PUT run this, so a PUT cannot smuggle in metadata a fresh
// registration would have rejected. defaultMethod is the method applied when
// the request omits one: registration passes the RFC's client_secret_basic,
// while a management update passes the client's current method so an update
// that only renames a client does not silently flip it between public and
// confidential.
func validateClientMetadata(req registrationRequest, defaultMethod string) (clientMetadata, regErr, bool) {
	invalid := func(description string) (clientMetadata, regErr, bool) {
		return clientMetadata{}, regErr{code: "invalid_client_metadata", description: description}, false
	}

	// redirect_uris: required, exact-match strings, stored verbatim. An https
	// URI for web clients; plain http only on loopback for native app
	// development (RFC 8252). No fragments — a fragment never reaches a
	// server, so it could not match at redirect time anyway.
	if len(req.RedirectURIs) == 0 {
		return clientMetadata{}, regErr{code: "invalid_redirect_uri", description: "at least one redirect_uri is required"}, false
	}
	for _, uri := range req.RedirectURIs {
		if !validRegistrationRedirectURI(uri) {
			return clientMetadata{}, regErr{code: "invalid_redirect_uri",
				description: "redirect_uri must be an absolute https URL (or http on loopback), without a fragment"}, false
		}
	}

	// token_endpoint_auth_method: defaults to defaultMethod — client_secret_basic
	// (a confidential client holding a secret) on registration, or the client's
	// existing method on a management update. `none` makes it public.
	method := req.TokenEndpointAuthMethod
	if method == "" {
		method = defaultMethod
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

	return clientMetadata{
		TokenEndpointAuthMethod: method,
		IsPublic:                isPublic,
		Name:                    name,
		RedirectURIs:            req.RedirectURIs,
		AllowedScopes:           scopes,
		GrantTypes:              grantTypes,
		ResponseTypes:           responseTypes,
	}, regErr{}, true
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
