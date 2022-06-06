package qafgh

import (
	"fmt"
	"io"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func RandScalar(r io.Reader) (*big.Int, error) {
	b := fr.Element{}
	_, err := b.SetRandom()
	if err != nil {
		return nil, err
	}

	var bi big.Int
	b.ToBigIntRegular(&bi)
	return &bi, nil
}

func RandGTInGroup(r io.Reader) (bls12381.GT, error) {
	a := fr.Element{}
	a.SetRandom()
	b := fr.Element{}
	b.SetRandom()

	var ai, bi big.Int

	a.ToBigIntRegular(&ai)
	b.ToBigIntRegular(&bi)

	_, _, g1gen, g2gen := bls12381.Generators()
	g1gen.ScalarMultiplication(&g1gen, &ai)
	g2gen.ScalarMultiplication(&g2gen, &bi)

	return bls12381.Pair([]bls12381.G1Affine{g1gen}, []bls12381.G2Affine{g2gen})
}

// Compress a member of GT to a member of FP6 and then
// serialize it in big endian form
func CompressGtG(gt bls12381.GT) []byte {
	b := gt.CompressTorus()
	bytes21 := b.B2.A1.Bytes()
	bytes20 := b.B2.A0.Bytes()
	bytes11 := b.B1.A1.Bytes()
	bytes10 := b.B1.A0.Bytes()
	bytes01 := b.B0.A1.Bytes()
	bytes00 := b.B0.A0.Bytes()

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

// Deserialize a member of FP6 in big endian form
// and then decompress it to a member of GT.
// Errors if the resulting GT is not in the subgroup, or an invalid
// slice is passed
func DecompressGtG(inp []byte) (*bls12381.GT, error) {

	// get an E6
	a := bls12381.GT{}
	b := a.C0
	if len(inp) != 288 {
		return nil, fmt.Errorf("Invalid slice length. Expected 288, got %v", len(inp))
	}

	b.B2.A1.SetBytes(inp[0*48 : 1*48])
	b.B2.A0.SetBytes(inp[1*48 : 2*48])
	b.B1.A1.SetBytes(inp[2*48 : 3*48])
	b.B1.A0.SetBytes(inp[3*48 : 4*48])
	b.B0.A1.SetBytes(inp[4*48 : 5*48])
	b.B0.A0.SetBytes(inp[5*48 : 6*48])

	res := b.DecompressTorus()
	if !res.IsInSubGroup() {
		return nil, fmt.Errorf("GT not in group")
	}

	return &res, nil
}
