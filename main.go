package main

import (
	"context"
	"crypto/rand"
	"log"
	"log/slog"
	"os"

	"github.com/ccarlfjord/user/internal/repository"
	"github.com/ccarlfjord/user/rest"
	"github.com/jackc/pgx/v5/pgxpool"
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

// loadSigningKey returns the shared JWT signing key from the database,
// generating and persisting a new one on first boot.
func loadSigningKey(ctx context.Context, pool *pgxpool.Pool) ([]byte, error) {
	db := repository.New(pool)

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
