package enrichment

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/example/walletguard/internal/domain"
)

// BalanceChecker fetches public on-chain balances via JSON-RPC (no keys sent).
type BalanceChecker struct {
	EVMClient    *http.Client
	EVMRPC       string
	SolanaClient *http.Client
	SolanaRPC    string
}

// NewBalanceChecker creates an enrichment client with timeouts.
func NewBalanceChecker(evmRPC, solanaRPC string) *BalanceChecker {
	return &BalanceChecker{
		EVMClient:    &http.Client{Timeout: 15 * time.Second},
		SolanaClient: &http.Client{Timeout: 15 * time.Second},
		EVMRPC:       strings.TrimSuffix(evmRPC, "/"),
		SolanaRPC:    strings.TrimSuffix(solanaRPC, "/"),
	}
}

// Enrich adds balance hints to verification details (best effort).
func (b *BalanceChecker) Enrich(ctx context.Context, f domain.Finding, v *domain.VerificationResult) map[string]string {
	out := map[string]string{}
	if v == nil || !v.IsValid || len(v.DerivedAddresses) == 0 {
		return out
	}
	switch f.ChainFamily {
	case domain.ChainEVM:
		if b.EVMRPC == "" {
			return out
		}
		for _, addr := range v.DerivedAddresses {
			if bal, err := b.ethBalance(ctx, addr); err == nil {
				out["eth_balance_wei"] = bal
			}
		}
	case domain.ChainSolana:
		if b.SolanaRPC == "" {
			return out
		}
		for _, pk := range v.DerivedAddresses {
			if lamports, err := b.solBalance(ctx, pk); err == nil {
				out["sol_lamports"] = lamports
			}
		}
	}
	return out
}

func (b *BalanceChecker) ethBalance(ctx context.Context, addr string) (string, error) {
	body := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "eth_getBalance",
		"params":  []any{addr, "latest"},
	}
	raw, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.EVMRPC, bytes.NewReader(raw))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := b.EVMClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	rb, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	var out struct {
		Result string `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rb, &out); err != nil {
		return "", err
	}
	if out.Error != nil {
		return "", fmt.Errorf("rpc: %s", out.Error.Message)
	}
	return strings.TrimPrefix(out.Result, "0x"), nil
}

func (b *BalanceChecker) solBalance(ctx context.Context, pubkey string) (string, error) {
	body := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "getBalance",
		"params":  []any{pubkey, map[string]string{"commitment": "confirmed"}},
	}
	raw, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.SolanaRPC, bytes.NewReader(raw))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := b.SolanaClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	rb, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	var out struct {
		Result struct {
			Value uint64 `json:"value"`
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rb, &out); err != nil {
		return "", err
	}
	if out.Error != nil {
		return "", fmt.Errorf("rpc: %s", out.Error.Message)
	}
	return fmt.Sprintf("%d", out.Result.Value), nil
}
