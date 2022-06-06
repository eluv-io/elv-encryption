package qafgh

import (
	"io"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

const scalarSize = 32

const EncryptionSKSize = scalarSize
const DecryptionSKSize = scalarSize

const EncryptionPKSize = compressedGtSize
const DecryptionPKSize = bls12381.SizeOfG2AffineCompressed

type EncryptionSecretKey struct {
	a1 fr.Element
}

func (sk *EncryptionSecretKey) ToBytes() [EncryptionSKSize]byte {
	return serScalar(&sk.a1)
}

func EncryptionSecretKeyFromBytes(inp []byte) (*EncryptionSecretKey, error) {
	s, err := dsrScalar(inp)
	if err != nil {
		return nil, err
	}
	return &EncryptionSecretKey{
		a1: s,
	}, nil
}

func (sk *EncryptionSecretKey) Pubkey() EncryptionPublicKey {
	res := GTZ // copy generator
	exp := big.Int{}
	sk.a1.ToBigIntRegular(&exp)
	res.Exp(&res, exp)
	return EncryptionPublicKey{
		za1: res,
	}
}

func RandomEncryptionSecretKey(rand io.Reader) (*EncryptionSecretKey, error) {
	a1, err := randScalar(rand)
	if err != nil {
		return nil, err
	}
	return &EncryptionSecretKey{a1: a1}, nil
}

type EncryptionPublicKey struct {
	za1 bls12381.GT
}

func (pk *EncryptionPublicKey) ToBytes() [EncryptionPKSize]byte {
	return compressGt(pk.za1)
}

func EncryptionPublicKeyFromBytes(inp []byte) (*EncryptionPublicKey, error) {
	za1, err := decompressGt(inp)
	if err != nil {
		return nil, err
	}
	return &EncryptionPublicKey{
		za1: *za1,
	}, nil
}

type DecryptionSecretKey struct {
	b2 fr.Element
}

func (sk *DecryptionSecretKey) ToBytes() [EncryptionSKSize]byte {
	return serScalar(&sk.b2)
}

func DecryptionSecretKeyFromBytes(inp []byte) (*DecryptionSecretKey, error) {
	s, err := dsrScalar(inp)
	if err != nil {
		return nil, err
	}
	return &DecryptionSecretKey{
		b2: s,
	}, nil
}

func (sk *DecryptionSecretKey) Pubkey() DecryptionPublicKey {
	res := bls12381.G2Affine{}
	b2Big := scalarToBig(&sk.b2)
	res.ScalarMultiplication(&G2GEN, &b2Big)
	return DecryptionPublicKey{
		gb2: res,
	}
}

func RandomDecryptionSecretKey(rand io.Reader) (*DecryptionSecretKey, error) {
	b2, err := randScalar(rand)
	if err != nil {
		return nil, err
	}
	return &DecryptionSecretKey{b2: b2}, nil
}

type DecryptionPublicKey struct {
	gb2 bls12381.G2Affine
}

func (pk *DecryptionPublicKey) ToBytes() [DecryptionPKSize]byte {
	return pk.gb2.Bytes()
}

func DecryptionPublicKeyFromBytes(inp []byte) (*DecryptionPublicKey, error) {
	gb2, err := dsrG2(inp)
	if err != nil {
		return nil, err
	}
	return &DecryptionPublicKey{
		gb2: gb2,
	}, nil
}
