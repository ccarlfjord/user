package main

import (
	"context"
	"log"
	"log/slog"
	"os"

	"github.com/ccarlfjord/user-service/repository"
	"github.com/ccarlfjord/user-service/rest"
	"github.com/jackc/pgx/v5"
)

func main() {
	connString := os.Getenv("DATABASE_URL")
	if connString == "" {
		connString = "postgresql://postgres:postgres@localhost:5432"
	}

	ctx := context.Background()
	conn, err := pgx.Connect(ctx, connString)
	if err != nil {
		log.Fatal(err)
	}
	db := repository.New(conn)
	h := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{})
	logger := slog.New(h)
	slog.SetDefault(logger)
	srv := rest.New(db)
	srv.Run()
}
