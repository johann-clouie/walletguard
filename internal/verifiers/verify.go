package verifiers

import (
	"strings"
	"time"

	"github.com/mr-tron/base58"
	"github.com/tyler-smith/go-bip39"

	"github.com/example/walletguard/internal/domain"
	"github.com/example/walletguard/pkg/btc"
	"github.com/example/walletguard/pkg/evm"
	"github.com/example/walletguard/pkg/solana"
)

// Verify performs offline validation for a finding using raw candidate material.
func Verify(f domain.Finding) domain.VerificationResult {
	now := time.Now().UTC()
	res := domain.VerificationResult{
		FindingID: f.ID,
		IsValid:   false,
		Details:   map[string]string{},
		VerifiedAt: now,
	}
	switch f.SecretType {
	case domain.SecretMnemonic:
		phrase := strings.TrimSpace(string(f.RawSnippet))
		if bip39.IsMnemonicValid(phrase) {
			res.IsValid = true
			res.Details["word_count"] = strings.TrimSpace(f.Metadata["word_count"])
			res.DerivedAddresses = []string{}
			res.Details["note"] = "mnemonic valid; derive per-chain addresses in enrichment"
		}
	case domain.SecretEVMKey:
		addr, err := evm.AddressFromPrivateKeyHex(string(f.RawSnippet))
		if err == nil {
			res.IsValid = true
			res.DerivedAddresses = []string{addr}
			res.Details["format"] = "secp256k1_hex"
		} else {
			res.Details["error"] = err.Error()
		}
	case domain.SecretBitcoinWIF:
		addr, compressed, err := btc.AddressFromWIF(strings.TrimSpace(string(f.RawSnippet)))
		if err == nil {
			res.IsValid = true
			res.DerivedAddresses = []string{addr}
			res.Details["compressed"] = boolStr(compressed)
		} else {
			res.Details["error"] = err.Error()
		}
	case domain.SecretSolanaKey:
		s := strings.TrimSpace(string(f.RawSnippet))
		if strings.HasPrefix(s, "[") {
			pub, err := solana.ParseKeypairJSON([]byte(s))
			if err == nil {
				res.IsValid = true
				res.DerivedAddresses = []string{pub}
				res.Details["format"] = "json_array"
			} else {
				res.Details["error"] = err.Error()
			}
		} else {
			raw, err := base58.Decode(s)
			if err == nil && len(raw) == 64 {
				pub, err2 := solana.PubkeyBase58FromSeed(raw)
				if err2 == nil {
					res.IsValid = true
					res.DerivedAddresses = []string{pub}
					res.Details["format"] = "base58"
				} else {
					res.Details["error"] = err2.Error()
				}
			} else if err != nil {
				res.Details["error"] = err.Error()
			} else {
				res.Details["error"] = "invalid base58 key length"
			}
		}
	default:
		res.Details["error"] = "unsupported secret type"
	}
	return res
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
