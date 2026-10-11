package rest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func TestOpenIDConfiguration(t *testing.T) {
	c := newTestController(fakeStore{})

	rec := doRequest(c.openIDConfiguration, http.MethodGet, "/.well-known/openid-configuration", "", "")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("content-type = %q, want application/json", got)
	}

	var got oidcConfiguration
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode discovery document: %v", err)
	}
	if got.Issuer != testIssuer {
		t.Fatalf("issuer = %q, want %q", got.Issuer, testIssuer)
	}
	if want := testIssuer + "/.well-known/jwks.json"; got.JWKSURI != want {
		t.Fatalf("jwks_uri = %q, want %q", got.JWKSURI, want)
	}
	if len(got.IDTokenSigningAlgValuesSupported) != 1 || got.IDTokenSigningAlgValuesSupported[0] != "ES256" {
		t.Fatalf("id_token_signing_alg_values_supported = %v, want [ES256]", got.IDTokenSigningAlgValuesSupported)
	}
	if len(got.SubjectTypesSupported) != 1 || got.SubjectTypesSupported[0] != "public" {
		t.Fatalf("subject_types_supported = %v, want [public]", got.SubjectTypesSupported)
	}
	// The endpoints that do not exist yet must not be advertised.
	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode discovery document: %v", err)
	}
	for _, absent := range []string{"authorization_endpoint", "token_endpoint", "userinfo_endpoint"} {
		if _, ok := raw[absent]; ok {
			t.Fatalf("discovery advertises %q, which is not implemented", absent)
		}
	}
}

// The JWKS must publish exactly the public key that verifies tokens signed with
// the private key: no secret material, and a usable key, not just the right
// shape.
func TestJWKSPublishesVerificationKey(t *testing.T) {
	c := newTestController(fakeStore{})

	rec := doRequest(c.jwks, http.MethodGet, "/.well-known/jwks.json", "", "")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var body jwksResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode JWKS: %v", err)
	}
	if len(body.Keys) != 1 {
		t.Fatalf("keys = %d, want exactly the one signing key", len(body.Keys))
	}
	key := body.Keys[0]
	if key.Kty != "EC" || key.Crv != "P-256" || key.Use != "sig" || key.Alg != "ES256" {
		t.Fatalf("key = %+v, want an ES256 signing key", key)
	}
	if want := keyID(&testSigningKey.PublicKey); key.Kid != want {
		t.Fatalf("kid = %q, want %q", key.Kid, want)
	}

	pub := publicKeyFromJWK(t, key)
	if !pub.Equal(&testSigningKey.PublicKey) {
		t.Fatal("the published key is not the signing key's public half")
	}

	// A token signed with the private key verifies under the published key.
	signed := signClaims(t, testSigningKey, mintedClaims(uuid.New().String(), 0))
	if _, err := jwt.ParseWithClaims(signed, new(sessionClaims), func(*jwt.Token) (any, error) {
		return pub, nil
	}, jwt.WithValidMethods([]string{"ES256"})); err != nil {
		t.Fatalf("token does not verify under the published key: %v", err)
	}
}

// publicKeyFromJWK rebuilds a P-256 public key from the x/y members, the way a
// relying party would.
func publicKeyFromJWK(t *testing.T, key jwk) *ecdsa.PublicKey {
	t.Helper()

	x, err := base64.RawURLEncoding.DecodeString(key.X)
	if err != nil {
		t.Fatalf("decode x: %v", err)
	}
	y, err := base64.RawURLEncoding.DecodeString(key.Y)
	if err != nil {
		t.Fatalf("decode y: %v", err)
	}
	if len(x) != 32 || len(y) != 32 {
		t.Fatalf("coordinate lengths = %d, %d, want 32 each", len(x), len(y))
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}
}

func TestKeyIDIsStableAndKeySpecific(t *testing.T) {
	first := keyID(&testSigningKey.PublicKey)
	if again := keyID(&testSigningKey.PublicKey); again != first {
		t.Fatalf("keyID changed between calls: %q vs %q", first, again)
	}
	if other := keyID(&mustGenerateTestKey().PublicKey); other == first {
		t.Fatal("two different keys produced the same key id")
	}
}

func TestOIDCEndpointsRejectNonGet(t *testing.T) {
	c := newTestController(fakeStore{})

	tests := []struct {
		name    string
		handler http.HandlerFunc
		target  string
	}{
		{"discovery", c.openIDConfiguration, "/.well-known/openid-configuration"},
		{"jwks", c.jwks, "/.well-known/jwks.json"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := doRequest(tt.handler, http.MethodPost, tt.target, "", "")
			if rec.Code != http.StatusMethodNotAllowed {
				t.Fatalf("status = %d, want 405", rec.Code)
			}
		})
	}
}

// A JWKS with no key must fail closed rather than answer with an empty set a
// relying party could read as "no key revoked everything".
func TestJWKSWithoutKeyFailsClosed(t *testing.T) {
	c := &controller{db: fakeStore{}, issuer: testIssuer}

	rec := doRequest(c.jwks, http.MethodGet, "/.well-known/jwks.json", "", "")

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

func TestOIDCIssuerConfiguration(t *testing.T) {
	t.Run("OIDC_ISSUER wins and is trimmed", func(t *testing.T) {
		t.Setenv("OIDC_ISSUER", "https://id.example.com/")
		if got := oidcIssuer(); got != "https://id.example.com" {
			t.Fatalf("issuer = %q, want https://id.example.com", got)
		}
	})

	t.Run("falls back to PUBLIC_BASE_URL", func(t *testing.T) {
		t.Setenv("OIDC_ISSUER", "")
		t.Setenv("PUBLIC_BASE_URL", "https://login.example.com/")
		if got := oidcIssuer(); got != "https://login.example.com" {
			t.Fatalf("issuer = %q, want https://login.example.com", got)
		}
	})
}
