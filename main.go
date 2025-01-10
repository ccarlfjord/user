package main

import (
	"context"
	"crypto/rand"
	"log"
	"log/slog"
	"net/http"
	"os"

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
		connString = "postgres://postgres:postgres@localhost:5432"
	}

	ctx := context.Background()
	conn, err := pgx.Connect(ctx, connString)
	if err != nil {
		log.Fatal(err)
	}
	srv := rest.New(conn, sessionToken())

	log.Fatal(http.ListenAndServe(":3000", srv))
}

func sessionToken() []byte {
	token := make([]byte, 32)
	rand.Read(token)
	return token
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
		lvl.Set(slog.LevelError)
	}
}
