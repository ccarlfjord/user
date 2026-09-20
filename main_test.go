package main

import (
	"context"
	"crypto/rand"
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
		if err := db.DeleteUser(ctx, existing.ID); err != nil {
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
		if err := db.DeleteUser(ctx, user.ID); err != nil {
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
