package solana

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/mr-tron/base58"
	"golang.org/x/crypto/ed25519"
)

// ParseKeypairJSON parses a Solana keypair export: JSON array of 64 uint8 values (secret||public).
func ParseKeypairJSON(data []byte) (pubBase58 string, err error) {
	var arr []int
	if err := json.Unmarshal(data, &arr); err != nil {
		return "", err
	}
	if len(arr) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("expected %d bytes, got %d", ed25519.PrivateKeySize, len(arr))
	}
	seed := make([]byte, len(arr))
	for i, v := range arr {
		if v < 0 || v > 255 {
			return "", fmt.Errorf("invalid byte at %d", i)
		}
		seed[i] = byte(v)
	}
	return PubkeyBase58FromSeed(seed)
}

// PubkeyBase58FromSeed derives the public key from a 64-byte Solana secret key blob.
func PubkeyBase58FromSeed(seed []byte) (string, error) {
	if len(seed) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("invalid key length %d", len(seed))
	}
	priv := ed25519.PrivateKey(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return base58.Encode(pub), nil
}

// LooksLikeKeypairArray returns true if JSON is a 64-element uint array.
func LooksLikeKeypairArray(data []byte) bool {
	data = bytes.TrimSpace(data)
	if len(data) < 2 || data[0] != '[' {
		return false
	}
	var arr []json.RawMessage
	if json.Unmarshal(data, &arr) != nil {
		return false
	}
	return len(arr) == ed25519.PrivateKeySize
}
