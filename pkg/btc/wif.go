package btc

import (
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
)

// AddressFromWIF decodes WIF and returns P2PKH address for mainnet (legacy display).
func AddressFromWIF(wif string) (address string, compressed bool, err error) {
	key, err := btcutil.DecodeWIF(wif)
	if err != nil {
		return "", false, err
	}
	compressed = key.CompressPubKey
	var pubBytes []byte
	if compressed {
		pubBytes = key.PrivKey.PubKey().SerializeCompressed()
	} else {
		pubBytes = key.PrivKey.PubKey().SerializeUncompressed()
	}
	pkHash := btcutil.Hash160(pubBytes)
	addr, err := btcutil.NewAddressPubKeyHash(pkHash, &chaincfg.MainNetParams)
	if err != nil {
		return "", compressed, err
	}
	return addr.EncodeAddress(), compressed, nil
}
