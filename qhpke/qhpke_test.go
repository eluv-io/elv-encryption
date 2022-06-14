package qhpke

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

var encap, _ = hex.DecodeString("041c606ea5ec589cd99872ab6bf34330dca8f67ccec9f84f4524ee3416af3bb8dcecfe6f2039a05f555066d1136e608dff880c392d3de2709cc0cee0e194e8195c")
var cipher, _ = hex.DecodeString("683b4aa1f72a27429b338ae670273ba492c727dadf49228dfe1ec8b46997527fa72ffd4d636ed6548f7dee07e62e02d84267")
var testSk, _ = hex.DecodeString("cf7b80d773746c91b08cc188d9b02e541ce11476650d8a8461597ab1d72a0877")
var info = []byte("public info string, known to both Alice and Bob")
var msg = []byte("text encrypted to Bob's public key")
var aad = []byte("additional public data")

func TestConsistency(t *testing.T) {
	dec, err := HpkeDecrypt(encap, cipher, info, aad, testSk)
	require.NoError(t, err)
	require.Equal(t, dec, msg)
}

func TestSanity(t *testing.T) {
	pk, sk, err := HpkeKeygen()
	require.NoError(t, err)
	encap, cipher, err := HpkeEncrypt(msg, info, aad, pk)
	require.NoError(t, err)
	dec, err := HpkeDecrypt(encap, cipher, info, aad, sk)
	require.NoError(t, err)
	require.Equal(t, dec, msg)
}
