package evm

import "testing"

func TestAddressFromPrivateKeyHex(t *testing.T) {
	// Well-known Anvil/Hardhat test key — never use on mainnet.
	const hexKey = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
	addr, err := AddressFromPrivateKeyHex(hexKey)
	if err != nil {
		t.Fatal(err)
	}
	want := "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
	if addr != want {
		t.Fatalf("got %s want %s", addr, want)
	}
}
