package rest

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/ccarlfjord/user/internal/repository"
	"github.com/jackc/pgx/v5"
)

// clientRegistrationHandler serves RFC 7592 client registration management on
// the client information endpoint named by registration_client_uri. The
// method selects the action; the credential is the registration access token
// minted at registration, presented as a bearer token.
func (c *controller) clientRegistrationHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		c.readClientRegistration(w, r)
	case http.MethodPut:
		c.updateClientRegistration(w, r)
	case http.MethodDelete:
		c.deleteClientRegistration(w, r)
	default:
		methodNotAllowed(w)
	}
}

// authorizeRegistration resolves the client named by the path and checks the
// bearer token against its stored registration access token hash in one
// lookup. A missing, unknown, or mismatched token gets the same 401, so a
// caller without the token cannot tell a registered client from an absent
// one.
func (c *controller) authorizeRegistration(w http.ResponseWriter, r *http.Request) (repository.OauthClient, bool) {
	token, ok := bearerToken(r.Header.Get("Authorization"))
	if !ok {
		unauthorized(w)
		return repository.OauthClient{}, false
	}

	client, err := c.db.GetClientByRegistrationToken(r.Context(), repository.GetClientByRegistrationTokenParams{
		ClientID:                    r.PathValue("client_id"),
		RegistrationAccessTokenHash: hashToken(token),
	})
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			slog.Error(err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return repository.OauthClient{}, false
		}
		unauthorized(w)
		return repository.OauthClient{}, false
	}
	return client, true
}

// readClientRegistration returns the current client information. Neither the
// secret nor the registration access token is echoed: only their hashes are
// stored, so the response carries everything readable and nothing minted.
func (c *controller) readClientRegistration(w http.ResponseWriter, r *http.Request) {
	client, ok := c.authorizeRegistration(w, r)
	if !ok {
		return
	}
	JSON(w, http.StatusOK, c.clientInformation(client, clientCredentials{}))
}

// updateClientRegistration replaces the client's metadata (RFC 7592 §2.2).
// The whole body is re-validated exactly as at /register, so a management
// update cannot widen redirect URIs or scopes past what a fresh registration
// allows. The registration access token is rotated on every update and
// returned once, giving a client a way to retire a leaked management
// credential. The client secret is rotated only when the client crosses from
// public to confidential: a confidential client that stays confidential keeps
// the secret it holds, since only the hash is stored and re-minting would
// silently invalidate a credential still in use.
func (c *controller) updateClientRegistration(w http.ResponseWriter, r *http.Request) {
	client, ok := c.authorizeRegistration(w, r)
	if !ok {
		return
	}
	if !validateContentTypeJSON(w, r) {
		return
	}

	var req registrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		registrationErrorResponse(w, http.StatusBadRequest, "invalid_client_metadata",
			"the request body is not valid client metadata")
		return
	}

	metadata, regErr, ok := validateClientMetadata(req, client.TokenEndpointAuthMethod)
	if !ok {
		registrationErrorResponse(w, http.StatusBadRequest, regErr.code, regErr.description)
		return
	}

	creds := clientCredentials{}
	if !metadata.IsPublic && client.IsPublic {
		secret, err := generateToken()
		if err != nil {
			slog.Error(err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		creds.ClientSecret = secret
	}
	registrationToken, err := generateToken()
	if err != nil {
		slog.Error(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	creds.RegistrationAccessToken = registrationToken

	updated, err := c.db.UpdateClient(r.Context(), updateClientParams(client, metadata, creds))
	if err != nil {
		slog.Error(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	JSON(w, http.StatusOK, c.clientInformation(updated, creds))
}

// updateClientParams rewrites the mutable columns as a whole row, carrying the
// secret over from the stored client unless the update drops or replaces it.
func updateClientParams(current repository.OauthClient, metadata clientMetadata, creds clientCredentials) repository.UpdateClientParams {
	params := repository.UpdateClientParams{
		ClientID:                    current.ClientID,
		IsPublic:                    metadata.IsPublic,
		Name:                        metadata.Name,
		RedirectUris:                metadata.RedirectURIs,
		AllowedScopes:               metadata.AllowedScopes,
		TokenEndpointAuthMethod:     metadata.TokenEndpointAuthMethod,
		GrantTypes:                  metadata.GrantTypes,
		ResponseTypes:               metadata.ResponseTypes,
		RegistrationAccessTokenHash: hashToken(creds.RegistrationAccessToken),
	}
	switch {
	case metadata.IsPublic:
		params.ClientSecretHash = nil
	case creds.ClientSecret != "":
		params.ClientSecretHash = hashToken(creds.ClientSecret)
	default:
		params.ClientSecretHash = current.ClientSecretHash
	}
	return params
}

// deleteClientRegistration retires the registration. Authorization codes and
// any tokens hung off the client go with the row through the schema's ON
// DELETE CASCADE. RFC 7592 §2.3 answers 204 on success.
func (c *controller) deleteClientRegistration(w http.ResponseWriter, r *http.Request) {
	client, ok := c.authorizeRegistration(w, r)
	if !ok {
		return
	}
	if _, err := c.db.DeleteClient(r.Context(), client.ClientID); err != nil {
		slog.Error(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
