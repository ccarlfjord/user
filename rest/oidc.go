package rest

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// The scope vocabulary this provider grants. `openid` is the only scope OIDC
// itself requires; `email` maps to the email/email_verified claims. Discovery
// advertises exactly this list, a client's allowed_scopes in the database may
// never exceed it, and /authorize rejects any request outside it — so token
// exchange never has to widen a grant. The list grows when a claim to hang a
// new scope on actually exists.
const (
	ScopeOpenID = "openid"
	ScopeEmail  = "email"
)

// supportedScopes is the vocabulary above in the order discovery lists it.
var supportedScopes = []string{ScopeOpenID, ScopeEmail}

// oidcIssuer is the public identifier for this provider. Every token's `iss`
// must match it exactly, so it is resolved once at start-up from OIDC_ISSUER,
// falling back to the same PUBLIC_BASE_URL that builds verification links.
func oidcIssuer() string {
	if issuer := os.Getenv("OIDC_ISSUER"); issuer != "" {
		return strings.TrimRight(issuer, "/")
	}
	return verificationBaseURL()
}

// oidcConfiguration is the OpenID Connect Discovery document. It carries only
// the fields this service can answer for today: the issuer, the key set, the
// ES256 signing method, and the authorization and registration endpoints. The
// token and userinfo endpoints join when they exist — advertising a URL that
// still 404s would mislead a relying party, so they are deliberately absent.
type oidcConfiguration struct {
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	RegistrationEndpoint             string   `json:"registration_endpoint"`
	JWKSURI                          string   `json:"jwks_uri"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	ScopesSupported                  []string `json:"scopes_supported"`
	ClaimsSupported                  []string `json:"claims_supported"`
}

// openIDConfiguration serves the discovery document a relying party fetches
// first to learn where the keys live and what the issuer value is.
func (c *controller) openIDConfiguration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}

	JSON(w, http.StatusOK, oidcConfiguration{
		Issuer:                           c.issuer,
		AuthorizationEndpoint:            c.issuer + "/authorize",
		RegistrationEndpoint:             c.issuer + "/register",
		JWKSURI:                          c.issuer + "/.well-known/jwks.json",
		IDTokenSigningAlgValuesSupported: []string{jwt.SigningMethodES256.Alg()},
		SubjectTypesSupported:            []string{"public"},
		ScopesSupported:                  supportedScopes,
		ClaimsSupported:                  []string{"sub", "email"},
	})
}

// jwk is an elliptic-curve public key in the JSON Web Key form (RFC 7517).
// Only public members are ever emitted; the private key stays in the process.
type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

type jwksResponse struct {
	Keys []jwk `json:"keys"`
}

// jwks publishes the public half of every key still inside the overlap window,
// so a relying party can verify a token without holding anything that could
// mint one, and a token signed just before a rotation still resolves to a key.
func (c *controller) jwks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}

	published := c.keys.Load().published(time.Now())
	if len(published) == 0 {
		slog.Error("JWKS requested before a signing key was loaded")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	keys := make([]jwk, 0, len(published))
	for i := range published {
		keys = append(keys, publicJWK(&published[i].private.PublicKey))
	}
	JSON(w, http.StatusOK, jwksResponse{Keys: keys})
}

func publicJWK(pub *ecdsa.PublicKey) jwk {
	x, y := ecCoordinates(pub)
	return jwk{
		Kty: "EC",
		Crv: "P-256",
		X:   x,
		Y:   y,
		Use: "sig",
		Alg: jwt.SigningMethodES256.Alg(),
		Kid: keyID(pub),
	}
}

// ecCoordinates encodes the affine point of a P-256 public key as the fixed
// 32-byte, base64url, no-padding values that JWK requires. FillBytes left-pads
// a short coordinate, which happens whenever the top byte is zero.
func ecCoordinates(pub *ecdsa.PublicKey) (x, y string) {
	size := (pub.Curve.Params().BitSize + 7) / 8
	x = base64.RawURLEncoding.EncodeToString(pub.X.FillBytes(make([]byte, size)))
	y = base64.RawURLEncoding.EncodeToString(pub.Y.FillBytes(make([]byte, size)))
	return x, y
}

// keyID is the RFC 7638 JWK thumbprint: a stable id derived from the public key
// itself, so it needs no storage and changes only when the key does. The
// canonical form holds exactly the required members in lexicographic order,
// with no whitespace, which encoding/json produces for a struct declared in
// that order.
func keyID(pub *ecdsa.PublicKey) string {
	x, y := ecCoordinates(pub)
	canonical, err := json.Marshal(struct {
		Crv string `json:"crv"`
		Kty string `json:"kty"`
		X   string `json:"x"`
		Y   string `json:"y"`
	}{Crv: "P-256", Kty: "EC", X: x, Y: y})
	if err != nil {
		// The struct holds only strings, so Marshal cannot fail.
		panic(err)
	}

	sum := sha256.Sum256(canonical)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
