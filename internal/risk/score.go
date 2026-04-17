package risk

import (
	"strconv"
	"strings"
	"time"

	"github.com/example/walletguard/internal/domain"
)

// Compute produces a severity and numeric score from finding + verification + enrichment.
func Compute(f domain.Finding, v domain.VerificationResult, enrich map[string]string) domain.RiskScore {
	var reasons []string
	score := 0.0
	if v.IsValid {
		score += 40
		reasons = append(reasons, "cryptographically valid material")
	}
	switch f.SecretType {
	case domain.SecretMnemonic:
		score += 25
		if v.IsValid {
			score += 15
			reasons = append(reasons, "valid BIP39 checksum")
		}
		reasons = append(reasons, "mnemonic can derive many wallets")
	case domain.SecretEVMKey, domain.SecretBitcoinWIF, domain.SecretSolanaKey:
		score += 15
		reasons = append(reasons, "raw private key material")
	}
	if f.Confidence >= 0.85 {
		score += 10
		reasons = append(reasons, "high detector confidence")
	}
	path := strings.ToLower(f.Metadata["path"])
	if strings.Contains(path, ".env") || strings.Contains(path, "production") || strings.Contains(path, "prod") {
		score += 15
		reasons = append(reasons, "sensitive path context")
	}
	if wei, ok := enrich["eth_balance_wei"]; ok && wei != "" && wei != "0" {
		score += 25
		reasons = append(reasons, "non-zero EVM balance observed")
	}
	if lam, ok := enrich["sol_lamports"]; ok {
		if v, err := strconv.ParseUint(lam, 10, 64); err == nil && v > 0 {
			score += 25
			reasons = append(reasons, "non-zero Solana balance observed")
		}
	}
	sev := domain.SeverityLow
	switch {
	case score >= 85:
		sev = domain.SeverityCritical
	case score >= 65:
		sev = domain.SeverityHigh
	case score >= 40:
		sev = domain.SeverityMedium
	}
	return domain.RiskScore{
		FindingID:    f.ID,
		Severity:     sev,
		Score:        score,
		Reasons:      reasons,
		CalculatedAt: time.Now().UTC(),
	}
}
