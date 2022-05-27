package qafgh

import (
	"github.com/cloudflare/circl/ecc/bls12381/ff"
)

func serFp6(z ff.Fp6) (b []byte, e error) {
	var b0, b1, b2 []byte
	if b0, e = serFp2(z[0]); e == nil {
		if b1, e = serFp2(z[1]); e == nil {
			if b2, e = serFp2(z[2]); e == nil {
				return append(append(b0, b1...), b2...), e
			}
		}
	}
	return
}

func dsrFp6(b []byte) (z ff.Fp6, e error) {
	if z[0], e = dsrFp2(b[0*ff.Fp2Size : 1*ff.Fp2Size]); e != nil {
		return
	}
	if z[1], e = dsrFp2(b[1*ff.Fp2Size : 2*ff.Fp2Size]); e != nil {
		return
	}
	if z[2], e = dsrFp2(b[2*ff.Fp2Size : 3*ff.Fp2Size]); e != nil {
		return
	}
	return
}

func serFp2(z ff.Fp2) (b []byte, e error) {
	var b0, b1 []byte
	if b0, e = serFp(z[0]); e == nil {
		if b1, e = serFp(z[1]); e == nil {
			return append(b0, b1...), e
		}
	}
	return
}

func dsrFp2(b []byte) (z ff.Fp2, e error) {
	if z[0], e = dsrFp(b[0*ff.FpSize : 1*ff.FpSize]); e != nil {
		return
	}
	if z[1], e = dsrFp(b[1*ff.FpSize : 2*ff.FpSize]); e != nil {
		return
	}
	return
}

func serFp(z ff.Fp) ([]byte, error) {
	bytes, err := z.MarshalBinary()
	if err != nil {
		return nil, err
	}
	// Reverse endianness to little endian
	for i, j := 0, len(bytes)-1; i < j; i, j = i+1, j-1 {
		bytes[i], bytes[j] = bytes[j], bytes[i]
	}
	return bytes, nil
}

func dsrFp(b []byte) (z ff.Fp, e error) {
	// Reverse to big endian
	brev := make([]byte, len(b))
	for i := 0; i < len(brev); i++ {
		brev[i] = b[len(brev)-1-i]
	}
	e = z.UnmarshalBinary(brev)
	return
}
