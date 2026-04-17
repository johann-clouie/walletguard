package config

import (
	"os"
	"strconv"
	"strings"
)

// Config holds runtime settings for scanner and API.
type Config struct {
	DatabaseURL      string
	ScanRoots        []string
	GitRepoPaths     []string
	S3LocalPath      string // MVP: treat as filesystem "bucket" root when set
	SlackWebhookURL  string
	AlertEmailTo     string
	EVMRPCURL        string
	SolanaRPCURL     string
	WorkerConcurrency int
	ChunkSizeBytes   int
}

// Load reads configuration from environment variables.
func Load() Config {
	wc, _ := strconv.Atoi(env("WORKER_CONCURRENCY", "8"))
	cs, _ := strconv.Atoi(env("CHUNK_SIZE_BYTES", "1048576")) // 1 MiB
	if wc < 1 {
		wc = 8
	}
	if cs < 65536 {
		cs = 65536
	}
	return Config{
		DatabaseURL:       env("DATABASE_URL", "postgres://walletguard:walletguard@localhost:5432/walletguard?sslmode=disable"),
		ScanRoots:         splitEnv("SCAN_ROOTS"),
		GitRepoPaths:      splitEnv("GIT_REPO_PATHS"),
		S3LocalPath:       env("S3_LOCAL_PATH", ""),
		SlackWebhookURL:   env("SLACK_WEBHOOK_URL", ""),
		AlertEmailTo:      env("ALERT_EMAIL_TO", ""),
		EVMRPCURL:         env("EVM_RPC_URL", "https://ethereum.publicnode.com"),
		SolanaRPCURL:      env("SOLANA_RPC_URL", "https://api.mainnet-beta.solana.com"),
		WorkerConcurrency: wc,
		ChunkSizeBytes:    cs,
	}
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func splitEnv(k string) []string {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
