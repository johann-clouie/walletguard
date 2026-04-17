package evm

import (
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
)

// NormalizeHex strips 0x prefix and lowercases.
func NormalizeHex(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	return strings.ToLower(s)
}

// AddressFromPrivateKeyHex derives the Ethereum address (checksummed hex with 0x).
func AddressFromPrivateKeyHex(hexKey string) (string, error) {
	key, err := crypto.HexToECDSA(NormalizeHex(hexKey))
	if err != nil {
		return "", err
	}
	return crypto.PubkeyToAddress(key.PublicKey).Hex(), nil
}
