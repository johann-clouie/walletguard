# WalletGuard

WalletGuard scans files and repositories for exposed crypto wallet secrets, verifies whether they look usable, enriches with public chain data, computes risk, and stores incidents in Postgres.

## What it does

- Detects likely secrets in content chunks:
  - EVM private keys (`0x` or raw 64-hex)
  - Bitcoin WIF private keys
  - Solana key material (base58 and 64-byte JSON arrays)
  - BIP-39 mnemonics (12/15/18/21/24 words)
- Masks secret values before persistence.
- Verifies key material and derives addresses where possible.
- Enriches findings with best-effort on-chain balance signals (public RPC).
- Computes risk severity and opens incidents for high/critical findings.
- Exposes a read-only HTTP API for findings and incidents.

## Architecture

Main binaries:

- `cmd/scanner`: one-shot scan pipeline (`detect -> verify -> enrich -> risk -> persist -> alert`).
- `cmd/api`: HTTP API server for querying findings/incidents.
- `cmd/worker`: placeholder periodic worker (currently no-op tick loop).

Key packages:

- `internal/connectors`: filesystem, git repo, and local S3-like connectors.
- `internal/detectors`: pattern and heuristic detection engine.
- `internal/verifiers`: structural key validation + address derivation.
- `internal/enrichment`: JSON-RPC balance lookups (EVM, Solana).
- `internal/risk`: severity scoring.
- `internal/storage`: Postgres persistence and query projections.
- `internal/api`: read-only HTTP routes.

## Requirements

- Go `1.22+`
- PostgreSQL `16+` (or run via Docker Compose)

## Quickstart

### 1) Start Postgres

```bash
docker compose up -d postgres
```

Default DB credentials used by this project:

- user: `walletguard`
- password: `walletguard`
- database: `walletguard`
- host: `localhost:5432`

### 2) Configure environment

PowerShell example:

```powershell
$env:DATABASE_URL = "postgres://walletguard:walletguard@localhost:5432/walletguard?sslmode=disable"
$env:SCAN_ROOTS = "D:\path\to\scan"
# Optional:
$env:GIT_REPO_PATHS = "D:\repo1,D:\repo2"
$env:S3_LOCAL_PATH = "D:\mock-bucket-root"
$env:WORKER_CONCURRENCY = "8"
$env:CHUNK_SIZE_BYTES = "1048576"
$env:EVM_RPC_URL = "https://ethereum.publicnode.com"
$env:SOLANA_RPC_URL = "https://api.mainnet-beta.solana.com"
$env:SLACK_WEBHOOK_URL = ""
$env:ALERT_EMAIL_TO = ""
```

### 3) Run a scan

```bash
go run ./cmd/scanner
```

### 4) Start API server

```bash
go run ./cmd/api
```

By default, API listens on `:8080` (override with `LISTEN`).

### 5) Query results

```bash
curl http://localhost:8080/health
curl http://localhost:8080/api/v1/findings
curl http://localhost:8080/api/v1/incidents
```

## 60-second demo scan

This repo includes a minimal fixture at `fixtures/demo-scan/demo-secrets.txt` so you can verify end-to-end behavior quickly.

1. Start Postgres:
   - `docker compose up -d postgres`
2. Use `.env.example` values (or set only these vars):
   - `DATABASE_URL=postgres://walletguard:walletguard@localhost:5432/walletguard?sslmode=disable`
   - `SCAN_ROOTS=D:\walletguard\fixtures\demo-scan`
3. Run scanner:
   - `go run ./cmd/scanner`
4. Start API:
   - `go run ./cmd/api`
5. Check findings:
   - `curl http://localhost:8080/api/v1/findings`

You should see findings created from the demo fixture (mnemonic, EVM key-like value, WIF-like value, and Solana keypair array).

## Configuration reference

Scanner/API config is environment-based:

- `DATABASE_URL`: Postgres DSN.
- `SCAN_ROOTS`: comma-separated filesystem roots to scan.
- `GIT_REPO_PATHS`: comma-separated local git repos to scan.
- `S3_LOCAL_PATH`: local path treated as an S3-like root.
- `WORKER_CONCURRENCY`: max concurrent document workers (default `8`).
- `CHUNK_SIZE_BYTES`: chunk size for scanning (default `1048576`, min `65536`).
- `EVM_RPC_URL`: EVM JSON-RPC endpoint.
- `SOLANA_RPC_URL`: Solana JSON-RPC endpoint.
- `SLACK_WEBHOOK_URL`: optional Slack notifications for high/critical incidents.
- `ALERT_EMAIL_TO`: reserved for email alert integration.
- `LISTEN`: API bind address (default `:8080`).
- `WORKER_POLL_INTERVAL`: worker tick interval (default `5m`).

## API routes

- `GET /health` -> basic health response.
- `GET /api/v1/findings` -> latest findings.
- `GET /api/v1/findings/{id}` -> finding by ID.
- `GET /api/v1/incidents` -> latest incidents.
- `POST /api/v1/scan/start` -> placeholder hint to run scanner CLI.

## Notes on security and data handling

- Findings are persisted with `masked_value`.
- Pipeline clears in-memory raw snippets after processing.
- Balance enrichment uses public RPC calls and derived addresses only.
- This is an MVP scanner; tune detection thresholds and connector scope before production use.

## Development

Run tests:

```bash
go test ./...
```

Typical local flow:

1. Start Postgres (`docker compose up -d postgres`)
2. Run scanner (`go run ./cmd/scanner`)
3. Run API (`go run ./cmd/api`)
4. Inspect findings/incidents via HTTP routes
