package rest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"log/slog"
	"time"

	"github.com/ccarlfjord/user/internal/repository"
)

// oidcSigningKeyName prefixes every signing_keys row. The first key of a fresh
// database uses the bare name; later keys append a discriminator, so the table
// holds the whole history rather than one replaceable row.
const oidcSigningKeyName = "oidc_signing_key"

// signingKeyRotationInterval is how long the active key serves before a
// start-up or the daily purge replaces it. Overlap makes replacement safe at
// any moment, so the interval bounds a private key's lifetime rather than any
// token's validity.
const signingKeyRotationInterval = 30 * 24 * time.Hour

// signingKeyRetention is how long a key stays in the JWKS after a newer key
// replaced it: the longest a token signed with it can still be alive, plus a
// margin for clock skew. Verification reads every stored key regardless, so a
// lapse here only hides a key whose tokens have expired.
const signingKeyRetention = sessionTTL + 5*time.Minute

// signingKey is a loaded ES256 key and when it entered service.
type signingKey struct {
	private *ecdsa.PrivateKey
	created time.Time
}

// keySet is an immutable view of the signing keys, newest first. The controller
// swaps a whole set in on rotation; readers take one snapshot instead of
// holding a lock while signing or verifying.
type keySet struct {
	keys []signingKey
}

// active returns the newest key, the one that signs. It is nil before the first
// key is loaded.
func (s *keySet) active() *signingKey {
	if s == nil || len(s.keys) == 0 {
		return nil
	}
	return &s.keys[0]
}

// verificationKey returns the public half matching kid, or nil. It searches
// every stored key, published or not: a retired key is only hidden from the
// JWKS, while a token it signed must still verify until it expires.
func (s *keySet) verificationKey(kid string) *ecdsa.PublicKey {
	if s == nil {
		return nil
	}
	for i := range s.keys {
		if pub := &s.keys[i].private.PublicKey; keyID(pub) == kid {
			return pub
		}
	}
	return nil
}

// published returns the keys the JWKS advertises at now: the active key and any
// older key whose replacement is younger than the retention window, so a
// relying party can still resolve a token signed just before a rotation.
func (s *keySet) published(now time.Time) []signingKey {
	if s == nil || len(s.keys) == 0 {
		return nil
	}
	out := s.keys[:1:1]
	for i := 1; i < len(s.keys); i++ {
		if now.Before(s.keys[i-1].created.Add(signingKeyRetention)) {
			out = append(out, s.keys[i])
		}
	}
	return out
}

// publishedKids returns the advertised key ids at now, for display.
func (s *keySet) publishedKids(now time.Time) []string {
	published := s.published(now)
	kids := make([]string, 0, len(published))
	for i := range published {
		kids = append(kids, keyID(&published[i].private.PublicKey))
	}
	return kids
}

// refreshSigningKeys loads the key set into memory and, when the active key has
// served its interval or none exists, generates and stores a new one first. It
// is the automatic rotation path, run at start-up and on the daily purge tick.
func (c *controller) refreshSigningKeys(ctx context.Context) error {
	keys, err := c.loadSigningKeys(ctx)
	if err != nil {
		return err
	}
	now := time.Now()
	if rotationDue(keys, now) {
		name := rotationName(keys, now)
		if err := c.generateSigningKey(ctx, name); err != nil {
			return err
		}
		if keys, err = c.loadSigningKeys(ctx); err != nil {
			return err
		}
		slog.Info("rotated OIDC signing key", "name", name)
	}
	c.setKeys(keys)
	return nil
}

// rotateSigningKey generates and stores a new key now, whatever the active
// key's age, and reloads the in-memory set. It is the operator-triggered path.
func (c *controller) rotateSigningKey(ctx context.Context) error {
	if err := c.generateSigningKey(ctx, ""); err != nil {
		return err
	}
	return c.reloadSigningKeys(ctx)
}

func (c *controller) setKeys(keys []signingKey) {
	c.keys.Store(&keySet{keys: keys})
}

func (c *controller) reloadSigningKeys(ctx context.Context) error {
	keys, err := c.loadSigningKeys(ctx)
	if err != nil {
		return err
	}
	c.setKeys(keys)
	return nil
}

func (c *controller) loadSigningKeys(ctx context.Context) ([]signingKey, error) {
	rows, err := c.db.ListSigningKeys(ctx)
	if err != nil {
		return nil, err
	}
	keys := make([]signingKey, 0, len(rows))
	for _, row := range rows {
		key, err := parseSigningKey(row.Value)
		if err != nil {
			return nil, fmt.Errorf("signing key %q: %w", row.Name, err)
		}
		keys = append(keys, signingKey{private: key, created: row.CreatedAt})
	}
	return keys, nil
}

// generateSigningKey creates a P-256 key and stores it. name identifies the row;
// an empty name derives one from the key's own thumbprint, which keeps
// operator-triggered rotations distinct while automatic ones that race under a
// shared name collapse to one row via ON CONFLICT.
func (c *controller) generateSigningKey(ctx context.Context, name string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if name == "" {
		name = oidcSigningKeyName + ":" + keyID(&key.PublicKey)
	}
	return c.db.CreateSigningKey(ctx, repository.CreateSigningKeyParams{Name: name, Value: der})
}

// rotationDue reports whether the active key has served its interval, or no key
// exists yet.
func rotationDue(keys []signingKey, now time.Time) bool {
	if len(keys) == 0 {
		return true
	}
	return now.Sub(keys[0].created) >= signingKeyRotationInterval
}

// rotationName derives the row name for an automatic rotation. Instances that
// race compute it from the same active key and so the same due time, and their
// inserts collide: exactly one key is stored and every instance reads it back.
// A fresh database keeps the bare name, which is what makes the first boot
// race-safe.
func rotationName(keys []signingKey, now time.Time) string {
	if len(keys) == 0 {
		return oidcSigningKeyName
	}
	due := keys[0].created.Add(signingKeyRotationInterval)
	return oidcSigningKeyName + ":" + due.UTC().Format(time.RFC3339)
}

// parseSigningKey decodes a stored PKCS#8 private key and refuses anything that
// is not a P-256 key, so a malformed or wrong-curve row fails at start-up
// instead of producing tokens nobody can verify.
func parseSigningKey(der []byte) (*ecdsa.PrivateKey, error) {
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("signing key is %T, want *ecdsa.PrivateKey", parsed)
	}
	if key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("signing key uses curve %s, want P-256", key.Curve.Params().Name)
	}
	return key, nil
}
