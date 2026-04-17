package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// Worker is a placeholder for async jobs (NATS/Redis consumers). Run the scanner on a schedule externally or extend this binary.
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	interval := os.Getenv("WORKER_POLL_INTERVAL")
	if interval == "" {
		interval = "5m"
	}
	d, err := time.ParseDuration(interval)
	if err != nil {
		log.Fatalf("WORKER_POLL_INTERVAL: %v", err)
	}
	t := time.NewTicker(d)
	defer t.Stop()
	log.Printf("walletguard worker idle (MVP); tick every %s — implement queue consumer here", d)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			log.Println("worker tick (no-op)")
		}
	}
}
