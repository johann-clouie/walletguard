package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/example/walletguard/internal/api"
	"github.com/example/walletguard/internal/storage"
)

func main() {
	ctx := context.Background()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://walletguard:walletguard@localhost:5432/walletguard?sslmode=disable"
	}
	store, err := storage.ConnectPostgres(ctx, dsn)
	if err != nil {
		log.Fatalf("postgres: %v", err)
	}
	defer store.Close()
	addr := os.Getenv("LISTEN")
	if addr == "" {
		addr = ":8080"
	}
	log.Printf("walletguard api listening on %s", addr)
	if err := http.ListenAndServe(addr, api.NewRouter(store.Pool)); err != nil {
		log.Fatal(err)
	}
}
