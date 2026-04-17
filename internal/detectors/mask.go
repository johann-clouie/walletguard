package detectors

import (
	"strings"
)

// MaskHex shows only prefix/suffix of hex material.
func MaskHex(hex string, keep int) string {
	h := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(hex), "0x"), "0X")
	if len(h) <= keep*2 {
		return strings.Repeat("*", len(h))
	}
	return h[:keep] + "…" + h[len(h)-keep:]
}

// MaskMnemonic replaces words with counts.
func MaskMnemonic(wordCount int) string {
	return strings.Repeat("*word ", wordCount)
}
