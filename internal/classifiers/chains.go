package classifiers

import "github.com/example/walletguard/internal/domain"

// DerivableChains lists chains that could be derived from a valid secret (informational).
func DerivableChains(f domain.Finding, verified domain.VerificationResult) []string {
	if !verified.IsValid {
		return nil
	}
	switch f.SecretType {
	case domain.SecretMnemonic:
		return []string{"ethereum", "bitcoin", "solana", "tron", "cosmos-family"}
	case domain.SecretEVMKey:
		return []string{"ethereum", "bnb", "polygon", "arbitrum", "base", "optimism"}
	case domain.SecretBitcoinWIF:
		return []string{"bitcoin"}
	case domain.SecretSolanaKey:
		return []string{"solana"}
	default:
		return nil
	}
}
