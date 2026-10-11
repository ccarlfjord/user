package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"os"

	"github.com/ccarlfjord/user/internal/repository"
	"github.com/ccarlfjord/user/rest"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// oidcSigningKeyName is the signing_keys row that holds the ES256 key. There is
// one key: sessions and, later, OIDC ID tokens are all signed with it, and its
// public half is what the JWKS publishes.
const oidcSigningKeyName = "oidc_signing_key"

func main() {
	lvl := new(slog.LevelVar)
	setLogLevel(lvl)
	h := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: lvl,
	})
	logger := slog.New(h)
	slog.SetDefault(logger)

	connString := os.Getenv("DATABASE_URL")
	if connString == "" {
		connString = "postgresql://postgres:postgres@localhost:5432"
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, connString)
	if err != nil {
		log.Fatal(err)
	}
	defer pool.Close()

	signingKey, err := loadSigningKey(ctx, pool)
	if err != nil {
		log.Fatal(err)
	}

	srv := rest.New(pool, signingKey)

	log.Fatal(srv.Run())
}

// loadSigningKey returns the ES256 key from the database, generating and
// persisting a new P-256 key on first boot. Asymmetric signing is what lets a
// relying party verify a token with the public key from the JWKS without
// holding anything that could mint one.
func loadSigningKey(ctx context.Context, pool *pgxpool.Pool) (*ecdsa.PrivateKey, error) {
	db := repository.New(pool)

	stored, err := db.GetSigningKey(ctx, oidcSigningKeyName)
	switch {
	case err == nil:
		return parseSigningKey(stored.Value)
	case !errors.Is(err, pgx.ErrNoRows):
		return nil, err
	}

	// First boot. Two instances can race here, so the insert does nothing if
	// the other one won and the key is read back afterwards: every instance
	// ends up using the one stored key, never the one it generated locally.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := db.CreateSigningKey(ctx, repository.CreateSigningKeyParams{
		Name:  oidcSigningKeyName,
		Value: der,
	}); err != nil {
		return nil, err
	}

	stored, err = db.GetSigningKey(ctx, oidcSigningKeyName)
	if err != nil {
		return nil, err
	}
	return parseSigningKey(stored.Value)
}

// parseSigningKey decodes the stored PKCS#8 private key and refuses anything
// that is not a P-256 key, so a malformed or wrong-curve row fails at start-up
// instead of producing tokens nobody can verify.
func parseSigningKey(der []byte) (*ecdsa.PrivateKey, error) {
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("signing key %q is %T, want *ecdsa.PrivateKey", oidcSigningKeyName, parsed)
	}
	if key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("signing key %q uses curve %s, want P-256", oidcSigningKeyName, key.Curve.Params().Name)
	}
	return key, nil
}

func setLogLevel(lvl *slog.LevelVar) {
	switch os.Getenv("LOGLEVEL") {
	case "debug":
		lvl.Set(slog.LevelDebug)
	case "info":
		lvl.Set(slog.LevelInfo)
	case "error":
		lvl.Set(slog.LevelError)
	default:
		lvl.Set(slog.LevelInfo)
	}
}
