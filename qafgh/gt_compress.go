package qafgh

import (
	"fmt"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

func CompressGtG(gt *bls12381.GT) []byte {
	b := gt.CompressTorus()
	bytes21 := b.B2.A1.Marshal()
	bytes20 := b.B2.A0.Marshal()
	bytes11 := b.B1.A1.Marshal()
	bytes10 := b.B1.A0.Marshal()
	bytes01 := b.B0.A1.Marshal()
	bytes00 := b.B0.A0.Marshal()

	out := [288]byte{}
	// serialize big endian
	copy(out[0*48:1*48], bytes21[:])
	copy(out[1*48:2*48], bytes20[:])
	copy(out[2*48:3*48], bytes11[:])
	copy(out[3*48:4*48], bytes10[:])
	copy(out[4*48:5*48], bytes01[:])
	copy(out[5*48:6*48], bytes00[:])
	return out[:]
}

func DecompressGtG(inp []byte) (*bls12381.GT, error) {
	a := bls12381.GT{}
	// get an E6
	b := a.C0

	bi21 := big.NewInt(0).SetBytes(inp[0*48 : 1*48])
	bi20 := big.NewInt(0).SetBytes(inp[1*48 : 2*48])
	bi11 := big.NewInt(0).SetBytes(inp[2*48 : 3*48])
	bi10 := big.NewInt(0).SetBytes(inp[3*48 : 4*48])
	bi01 := big.NewInt(0).SetBytes(inp[4*48 : 5*48])
	bi00 := big.NewInt(0).SetBytes(inp[5*48 : 6*48])

	b.B2.A1.SetBigInt(bi21)
	b.B2.A0.SetBigInt(bi20)
	b.B1.A1.SetBigInt(bi11)
	b.B1.A0.SetBigInt(bi10)
	b.B0.A1.SetBigInt(bi01)
	b.B0.A0.SetBigInt(bi00)

	res := b.DecompressTorus()
	if !res.IsInSubGroup() {
		return nil, fmt.Errorf("GT not in group")
	}

	return &res, nil
}
