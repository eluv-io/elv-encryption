package qhpke

import (
	"crypto/rand"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
)

const HPKE = hpke.KEM_K256_HKDF_SHA256

var hpkeSuite hpke.Suite
var authScheme kem.AuthScheme

func init() {
	hpkeSuite = hpke.NewSuite(hpke.KEM_K256_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)
	authScheme = hpke.KEM_K256_HKDF_SHA256.Scheme()
}

// Returns a random (public, secret) keypair
func HpkeKeygen() ([]byte, []byte, error) {
	pk, sk, err := authScheme.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}
	pkBytes, err := pk.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	skBytes, err := sk.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	return pkBytes, skBytes, nil
}

// Encrypts plaintext with the provided info string and aad, under the given public key.
// Public keys are expected to be uncompressed secp256k1 keys and 65 byte long.
// Returns (the encapsulated key, the ciphertext)
func HpkeEncrypt(plaintext, info, aad, pkBytes []byte) ([]byte, []byte, error) {
	pk, err := authScheme.UnmarshalBinaryPublicKey(pkBytes)
	if err != nil {
		return nil, nil, err
	}
	sender, err := hpkeSuite.NewSender(pk, info)
	if err != nil {
		return nil, nil, err
	}
	encap, sealer, err := sender.Setup(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	ciphertext, err := sealer.Seal(plaintext, aad)
	if err != nil {
		return nil, nil, err
	}
	return encap, ciphertext, nil
}

// Decrypts ciphertext with the provided info string and aad, using the given private key.
func HpkeDecrypt(encap, ciphertext, info, aad, skBytes []byte) ([]byte, error) {
	sk, err := authScheme.UnmarshalBinaryPrivateKey(skBytes)
	if err != nil {
		return nil, err
	}
	recv, err := hpkeSuite.NewReceiver(sk, info)
	if err != nil {
		return nil, err
	}
	opener, err := recv.Setup(encap)
	if err != nil {
		return nil, err
	}
	plaintext, err := opener.Open(ciphertext, aad)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
