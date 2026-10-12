package main

import (
	"context"
	"log"
	"log/slog"
	"os"

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

	srv, err := rest.New(ctx, pool)
	if err != nil {
		log.Fatal(err)
	}

	log.Fatal(srv.Run())
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
