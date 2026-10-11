package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"os"
	"testing"

	"github.com/ccarlfjord/argon2"
	"github.com/ccarlfjord/user/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestCreateUser(t *testing.T) {
	connString := os.Getenv("DATABASE_URL")
	if connString == "" {
		connString = "postgresql://postgres:postgres@localhost:5432"
	}

	ctx := context.Background()
	conn, err := pgx.Connect(ctx, connString)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)

	salt := make([]byte, 16)
	rand.Read(salt)
	db := repository.New(conn)

	// Start from a clean slate so a manually created account does not affect
	// the test.
	if existing, err := db.GetUserByEmail(ctx, "test@example.com"); err == nil {
		if _, err := db.DeleteUser(ctx, existing.ID); err != nil {
			t.Fatal(err)
		}
	}

	pass := argon2.NewDefaultArgon2id()
	user, err := db.CreateUser(ctx, repository.CreateUserParams{
		ID:             uuid.New(),
		Email:          "test@example.com",
		HashedPassword: pass.Hash("test123", salt),
		Salt:           salt,
		Active:         true,
		Admin:          true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := db.DeleteUser(ctx, user.ID); err != nil {
			t.Error(err)
		}
	}()

	b, _ := json.Marshal(user)
	t.Log(string(b))

	if err := db.ActivateUser(ctx, user.ID); err != nil {
		t.Error(err)
	}
	if err := pass.Validate("test123", user.HashedPassword, user.Salt); err != nil {
		t.Error(err)
	}
}

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
