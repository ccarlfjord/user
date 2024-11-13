package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"log"
	"os"
	"testing"

	argon2 "github.com/ccarlfjord/user-service/argon2"
	"github.com/ccarlfjord/user-service/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestCreateUser(t *testing.T) {
	connString := os.Getenv("DATABASE_URL")
	if connString == "" {
		connString = "postgresql://postgres:postgres@localhost:5432"
	}

	ctx := context.Background()
	conn, err := pgx.Connect(ctx, connString)
	if err != nil {
		log.Fatal(err)
	}
	salt := make([]byte, 16)
	rand.Read(salt)
	db := repository.New(conn)
	// Check if user exists
	pass := argon2.NewDefaultArgon2()
	user, err := db.GetUserByEmail(ctx, "test@example.com")
	if errors.Is(err, pgx.ErrNoRows) {
		user, err = db.CreateUser(ctx, repository.CreateUserParams{
			ID:             uuid.New(),
			Username:       "test",
			Email:          "test@example.com",
			HashedPassword: pass.Hash("test123", salt),
			Salt:           salt,
			Active:         pgtype.Bool{Bool: true},
			Admin:          pgtype.Bool{Bool: false},
		})
		if err != nil {
			log.Println(err)
		}
	}
	defer func() {
		deleteUser(t, db, user.Email)
	}()
	json, _ := json.Marshal(user)
	t.Log(string(json))
	if err := db.ActivateUser(ctx, user.ID); err != nil {
		t.Error(err)
	}
	if err := pass.Validate("test123", user.HashedPassword, user.Salt); err == nil {
		t.Log("Password is valid")
	} else {
		t.Error(err)
	}
}

func deleteUser(t *testing.T, db *repository.Queries, email string) {
	ctx := context.Background()
	user, err := db.GetUserByEmail(ctx, email)
	if err != nil {
		t.Error(err)
	}
	if err := db.DeleteUser(ctx, user.ID); err != nil {
		t.Error(err)
	}
}
