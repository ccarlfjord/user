package main

import (
	"context"
	"crypto/rand"
	"log"
	"log/slog"
	"os"

	"github.com/ccarlfjord/user/internal/repository"
	"github.com/ccarlfjord/user/rest"
	"github.com/jackc/pgx/v5"
)

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
	conn, err := pgx.Connect(ctx, connString)
	if err != nil {
		log.Fatal(err)
	}

	signingKey, err := loadSigningKey(ctx, conn)
	if err != nil {
		log.Fatal(err)
	}

	srv := rest.New(conn, signingKey)

	log.Fatal(srv.Run())
}

// loadSigningKey returns the shared JWT signing key from the database,
// generating and persisting a new one on first boot.
func loadSigningKey(ctx context.Context, conn *pgx.Conn) ([]byte, error) {
	db := repository.New(conn)

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}

	signingKey, err := db.GetOrCreateSigningKey(ctx, repository.GetOrCreateSigningKeyParams{
		Name:  "jwt_signing_key",
		Value: key,
	})
	if err != nil {
		return nil, err
	}
	return signingKey.Value, nil
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
