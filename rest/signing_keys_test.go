package rest

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ccarlfjord/user/internal/repository"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// TestParseSigningKey covers start-up decoding of the stored key, because a
// malformed or wrong-curve row must stop the service rather than produce
// tokens nobody can verify.
func TestParseSigningKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := parseSigningKey(der)
	if err != nil {
		t.Fatalf("P-256 key rejected: %v", err)
	}
	if !parsed.Equal(key) {
		t.Fatal("parsed key differs from the stored one")
	}

	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p384der, err := x509.MarshalPKCS8PrivateKey(p384)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseSigningKey(p384der); err == nil {
		t.Fatal("a P-384 key was accepted, want a P-256-only refusal")
	}

	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edDER, err := x509.MarshalPKCS8PrivateKey(edKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseSigningKey(edDER); err == nil {
		t.Fatal("a non-ECDSA key was accepted")
	}

	if _, err := parseSigningKey([]byte("not a key")); err == nil {
		t.Fatal("garbage was accepted as a signing key")
	}
}

func marshalSigningKey(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// The JWKS keeps the active key and any key whose replacement is still inside
// the retention window, and drops older keys whose tokens cannot be alive.
func TestKeySetPublished(t *testing.T) {
	now := time.Now()
	active := mustGenerateTestKey()
	recent := mustGenerateTestKey()
	retired := mustGenerateTestKey()

	set := &keySet{keys: []signingKey{
		{private: active, created: now},
		{private: recent, created: now.Add(-70 * time.Minute)},
		{private: retired, created: now.Add(-140 * time.Minute)},
	}}

	got := set.published(now)
	if len(got) != 2 {
		t.Fatalf("published keys = %d, want 2", len(got))
	}
	if keyID(&got[0].private.PublicKey) != keyID(&active.PublicKey) {
		t.Fatal("the active key is not published first")
	}
	if keyID(&got[1].private.PublicKey) != keyID(&recent.PublicKey) {
		t.Fatal("a key inside the retention window is not published")
	}
	for _, key := range got {
		if keyID(&key.private.PublicKey) == keyID(&retired.PublicKey) {
			t.Fatal("a key past the retention window is still published")
		}
	}

	// The active key is published even if it is ancient: it is the one signing.
	old := &keySet{keys: []signingKey{{private: retired, created: now.Add(-400 * 24 * time.Hour)}}}
	if len(old.published(now)) != 1 {
		t.Fatal("the active key was hidden")
	}
}

// A key that is no longer published must still verify a token it signed, which
// is what makes the overlap window safe to shorten.
func TestSessionKeyVerifiesUnpublishedKey(t *testing.T) {
	old := mustGenerateTestKey()
	active := mustGenerateTestKey()
	c := &controller{db: fakeStore{}, issuer: testIssuer}
	c.setKeys([]signingKey{
		{private: active, created: time.Now()},
		{private: old, created: time.Now().Add(-400 * 24 * time.Hour)},
	})

	token := signClaims(t, old, mintedClaims(uuid.New().String(), 0))
	if _, err := jwt.ParseWithClaims(token, new(sessionClaims), c.sessionKey,
		jwt.WithValidMethods([]string{"ES256"}),
		jwt.WithIssuer(sessionIssuer), jwt.WithAudience(sessionAudience),
	); err != nil {
		t.Fatalf("token signed with an unpublished key did not verify: %v", err)
	}
}

// mintSession always signs with the newest key and names it, so a verifier can
// select it from the set.
func TestMintSessionUsesNewestKey(t *testing.T) {
	old := mustGenerateTestKey()
	active := mustGenerateTestKey()
	c := &controller{db: fakeStore{}, issuer: testIssuer}
	c.setKeys([]signingKey{
		{private: active, created: time.Now()},
		{private: old, created: time.Now().Add(-time.Hour)},
	})

	signed, err := c.mintSession(activeUser(false))
	if err != nil {
		t.Fatalf("mint session: %v", err)
	}
	token, err := jwt.ParseWithClaims(signed, new(sessionClaims), c.sessionKey,
		jwt.WithValidMethods([]string{"ES256"}))
	if err != nil {
		t.Fatalf("parse minted session: %v", err)
	}
	if got := token.Header["kid"]; got != keyID(&active.PublicKey) {
		t.Fatalf("kid = %v, want the newest key %s", got, keyID(&active.PublicKey))
	}
}

// An active key past its interval is replaced by refreshSigningKeys, and the
// replacement is stored under the due time so racing instances converge.
func TestRefreshSigningKeysRotatesStaleKey(t *testing.T) {
	old := mustGenerateTestKey()
	staleCreated := time.Now().Add(-signingKeyRotationInterval - time.Hour)

	var stored []repository.SigningKey
	stored = append(stored, repository.SigningKey{
		Name: oidcSigningKeyName, Value: marshalSigningKey(t, old), CreatedAt: staleCreated,
	})
	var created repository.CreateSigningKeyParams

	c := &controller{db: fakeStore{
		listSigningKeys: func(context.Context) ([]repository.SigningKey, error) {
			return stored, nil
		},
		createSigningKey: func(_ context.Context, arg repository.CreateSigningKeyParams) error {
			created = arg
			stored = append([]repository.SigningKey{{
				Name: arg.Name, Value: arg.Value, CreatedAt: time.Now(),
			}}, stored...)
			return nil
		},
	}, issuer: testIssuer}

	if err := c.refreshSigningKeys(context.Background()); err != nil {
		t.Fatalf("refresh signing keys: %v", err)
	}

	wantName := oidcSigningKeyName + ":" + staleCreated.Add(signingKeyRotationInterval).UTC().Format(time.RFC3339)
	if created.Name != wantName {
		t.Fatalf("new key name = %q, want %q", created.Name, wantName)
	}

	active := c.keys.Load().active()
	newKey, err := parseSigningKey(created.Value)
	if err != nil {
		t.Fatalf("stored key does not parse: %v", err)
	}
	if active == nil || !active.private.Equal(newKey) {
		t.Fatal("the rotated key did not become the active key")
	}
}

func TestRefreshSigningKeysLeavesFreshKey(t *testing.T) {
	key := mustGenerateTestKey()
	stored := []repository.SigningKey{{
		Name: oidcSigningKeyName, Value: marshalSigningKey(t, key), CreatedAt: time.Now(),
	}}
	created := false

	c := &controller{db: fakeStore{
		listSigningKeys: func(context.Context) ([]repository.SigningKey, error) {
			return stored, nil
		},
		createSigningKey: func(context.Context, repository.CreateSigningKeyParams) error {
			created = true
			return nil
		},
	}, issuer: testIssuer}

	if err := c.refreshSigningKeys(context.Background()); err != nil {
		t.Fatalf("refresh signing keys: %v", err)
	}
	if created {
		t.Fatal("a fresh key was rotated")
	}
	if active := c.keys.Load().active(); active == nil || !active.private.Equal(key) {
		t.Fatal("the stored key did not become the active key")
	}
}

// The operator path rotates regardless of the active key's age.
func TestRotateSigningKeyForcesRotation(t *testing.T) {
	old := mustGenerateTestKey()
	stored := []repository.SigningKey{{
		Name: oidcSigningKeyName, Value: marshalSigningKey(t, old), CreatedAt: time.Now(),
	}}
	var names []string

	c := &controller{db: fakeStore{
		listSigningKeys: func(context.Context) ([]repository.SigningKey, error) {
			return stored, nil
		},
		createSigningKey: func(_ context.Context, arg repository.CreateSigningKeyParams) error {
			names = append(names, arg.Name)
			stored = append([]repository.SigningKey{{
				Name: arg.Name, Value: arg.Value, CreatedAt: time.Now(),
			}}, stored...)
			return nil
		},
	}, issuer: testIssuer}
	c.setKeys([]signingKey{{private: old, created: time.Now()}})

	if err := c.rotateSigningKey(context.Background()); err != nil {
		t.Fatalf("rotate signing key: %v", err)
	}
	if len(names) != 1 {
		t.Fatalf("stored keys = %d, want 1", len(names))
	}
	if !strings.HasPrefix(names[0], oidcSigningKeyName+":") {
		t.Fatalf("rotated key name = %q, want an %s: prefix", names[0], oidcSigningKeyName)
	}
	if active := c.keys.Load().active(); active == nil || active.private.Equal(old) {
		t.Fatal("the old key is still active after a forced rotation")
	}
}

// The admin route reaches the operator rotation and returns the refreshed panel.
func TestAdminRotateSigningKey(t *testing.T) {
	admin := activeUser(true)
	old := mustGenerateTestKey()
	stored := []repository.SigningKey{{
		Name: oidcSigningKeyName, Value: marshalSigningKey(t, old), CreatedAt: time.Now(),
	}}

	c := newTestController(fakeStore{
		getUserById: func(_ context.Context, id uuid.UUID) (repository.User, error) {
			return admin, nil
		},
		listSigningKeys: func(context.Context) ([]repository.SigningKey, error) {
			return stored, nil
		},
		createSigningKey: func(_ context.Context, arg repository.CreateSigningKeyParams) error {
			stored = append([]repository.SigningKey{{
				Name: arg.Name, Value: arg.Value, CreatedAt: time.Now(),
			}}, stored...)
			return nil
		},
	})

	rec := adminRequest(t, c, admin, http.MethodPost, "/admin/signing-keys/rotate")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if active := c.keys.Load().active(); active == nil || active.private.Equal(old) {
		t.Fatal("the admin rotation did not change the active key")
	}
}
