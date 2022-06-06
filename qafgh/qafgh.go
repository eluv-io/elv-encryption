package qafgh

import (
	"fmt"
	"io"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

var SCALAR_MOD = bls12381.ID.Info().Fr.Modulus()
var SCALAR_BYTES = bls12381.ID.Info().Fr.Bytes

func dsrBigLE(inp []byte) (*big.Int, error) {
	b := big.NewInt(0)
	// pointer passed in so copy into new array
	inpBe := make([]byte, len(inp))
	copy(inpBe, inp)
	// Reverse to make big endian
	for i, j := 0, len(inpBe)-1; i < j; i, j = i+1, j-1 {
		inpBe[i], inpBe[j] = inpBe[j], inpBe[i]
	}

	b.SetBytes(inpBe)

	d := big.NewInt(0)
	d.Set(b).Mod(d, SCALAR_MOD)

	if d.Cmp(b) != 0 {
		return nil, fmt.Errorf("scalar is not canonical")
	}

	return b, nil
}

func serBigLE(b *big.Int) []byte {
	bb := b.Bytes()
	for i, j := 0, len(bb)-1; i < j; i, j = i+1, j-1 {
		bb[i], bb[j] = bb[j], bb[i]
	}
	return bb
}

type Message struct {
	m bls12381.GT
}

func (msg *Message) ToBytes() []byte {
	return CompressGtG(msg.m)
}

func MessageFromBytes(b []byte) (*Message, error) {
	gt, err := DecompressGtG(b)
	if err != nil {
		return nil, err
	}
	return &Message{m: *gt}, nil
}

func RandomMessage(r io.Reader) (*Message, error) {
	gt, err := RandGTInGroup(r)
	if err != nil {
		return nil, err
	}

	cmp := gt.CompressTorus()
	dcm := cmp.DecompressTorus()
	if !gt.Equal(&dcm) {
		return nil, fmt.Errorf("Msg compression failed")
	}

	return &Message{m: gt}, nil
}

type PublicKey struct {
	za1 bls12381.GT
	ga2 bls12381.G2Affine
}

type SecretKey struct {
	a1 big.Int
	a2 big.Int
}

const GtCompressedSize = bls12381.SizeOfGT
const PK_SIZE = GtCompressedSize + bls12381.SizeOfG2AffineCompressed

func (pk *PublicKey) ToBytes() []byte {
	ga2Bytes := pk.ga2.Bytes()
	za1Bytes := CompressGtG(pk.za1)
	return append(ga2Bytes[:], za1Bytes...)
}

func PublicKeyFromBytes(arr []byte) (pk PublicKey, err error) {
	if len(arr) != PK_SIZE {
		err = fmt.Errorf("Invalid pubkey bytes size. Expected %v, got %v", PK_SIZE, len(arr))
		return
	}

	if _, err = pk.ga2.SetBytes(arr[:bls12381.SizeOfG2AffineCompressed]); err != nil {
		return
	}
	var za1 *bls12381.GT
	if za1, err = DecompressGtG(arr[bls12381.SizeOfG2AffineCompressed:]); err != nil {
		return
	}
	pk.za1 = *za1

	return
}

func (sk *SecretKey) ToBytes() []byte {
	b1 := sk.a1.Bytes()
	b2 := sk.a2.Bytes()
	return append(b1, b2...)
}

var _, _, G1GEN, G2GEN = bls12381.Generators()
var GTZ, _ = bls12381.Pair([]bls12381.G1Affine{G1GEN}, []bls12381.G2Affine{G2GEN})

func (sk *SecretKey) Pubkey() (pk PublicKey) {
	pk.za1.Exp(&GTZ, sk.a1)
	pk.ga2.ScalarMultiplication(&G2GEN, &sk.a2)
	return
}

func SecretKeyFromBytes(skBytes []byte) (sk SecretKey, err error) {
	a1, err := dsrBigLE(skBytes[:SCALAR_BYTES])
	if err != nil {
		return
	}
	a2, err := dsrBigLE(skBytes[SCALAR_BYTES : 2*SCALAR_BYTES])
	if err != nil {
		return
	}
	sk.a1 = *a1
	sk.a2 = *a2
	return
}

func RandomSecretKey(rand io.Reader) (*SecretKey, error) {
	a1, err := RandScalar(rand)
	if err != nil {
		return nil, err
	}
	a2, err := RandScalar(rand)
	if err != nil {
		return nil, err
	}
	return &SecretKey{a1: *a1, a2: *a2}, nil
}

const (
	EncForA1 = iota
	EncForA2
)

type FirstLevelEncryption struct {
	encFor int
	zak    bls12381.GT
	mzk    bls12381.GT
}

func FirstLevelEncrypt(msg *Message, pk *PublicKey, rand io.Reader) (*FirstLevelEncryption, error) {
	k, err := RandScalar(rand)
	if err != nil {
		return nil, err
	}

	zak := bls12381.GT{}
	zak.Exp(&pk.za1, *k)

	mzk := bls12381.GT{}
	mzk.Exp(&GTZ, *k)
	mzk.Mul(&msg.m, &mzk)
	return &FirstLevelEncryption{
		encFor: EncForA1,
		zak:    zak,
		mzk:    mzk,
	}, nil
}

func (fe *FirstLevelEncryption) Decrypt(sk *SecretKey) (*Message, error) {
	var invS big.Int
	switch fe.encFor {
	case EncForA1:
		invS = sk.a1
	case EncForA2:
		invS = sk.a2
	default:
		return nil, fmt.Errorf("Invalid EncFor: %v", fe.encFor)
	}

	// 1/a
	invS.ModInverse(&invS, SCALAR_MOD)
	zk := bls12381.GT{}
	// zk = (z^{ak})^(1/a)
	zk.Exp(&fe.zak, invS)
	// zk = 1 / (z^k)
	zk.Inverse(&zk)
	// zk = m z^k/z^k = m
	zk.Mul(&fe.mzk, &zk)

	return &Message{m: zk}, nil
}

const SecondLevelSize = bls12381.SizeOfG1AffineCompressed + GtCompressedSize

type SecondLevelEncryption struct {
	gk   bls12381.G1Affine
	mzak bls12381.GT
}

func EncryptSecondLevel(msg *Message, pk *PublicKey, r io.Reader) (*SecondLevelEncryption, error) {
	k, err := RandScalar(r)
	if err != nil {
		return nil, err
	}

	gk := bls12381.G1Affine{}
	gk.ScalarMultiplication(&G1GEN, k)

	zak := bls12381.GT{}
	zak.Exp(&pk.za1, *k)
	mzak := bls12381.GT{}
	mzak.Mul(&msg.m, &zak)

	return &SecondLevelEncryption{gk: gk, mzak: mzak}, nil
}

func (sl *SecondLevelEncryption) ToBytes() ([]byte, error) {
	gkb := sl.gk.Bytes()
	mzakb := CompressGtG(sl.mzak)
	return append(gkb[:], mzakb...), nil
}

func SecondLevelEncryptionFromBytes(b []byte) (sl SecondLevelEncryption, err error) {
	if len(b) != SecondLevelSize {
		err = fmt.Errorf("Invalid second level size. Got %v, expected %v", len(b), SecondLevelSize)
		return
	}
	if _, err = sl.gk.SetBytes(b[:bls12381.SizeOfG1AffineCompressed]); err != nil {
		return
	}
	var mzak *bls12381.GT
	mzak, err = DecompressGtG(b[bls12381.SizeOfG1AffineCompressed:])
	if err != nil {
		return
	}
	sl.mzak = *mzak
	return
}

type ReencKey struct {
	ga1b2 bls12381.G2Affine
}

func (re *ReencKey) ToBytes() []byte {
	ga1b2bytes := re.ga1b2.Bytes()
	return ga1b2bytes[:]
}

func ReencKeyFromBytes(b []byte) (re ReencKey, err error) {
	_, err = re.ga1b2.SetBytes(b) // checks point is on G2
	if err != nil {
		return
	}
	if re.ga1b2.IsInfinity() {
		err = fmt.Errorf("Invalid ReencKey: is infinity")
	}
	return
}

func NewReencKey(owner *SecretKey, target *PublicKey) ReencKey {
	ga1b2 := bls12381.G2Affine{}
	ga1b2.ScalarMultiplication(&target.ga2, &owner.a1)
	return ReencKey{ga1b2: ga1b2}
}

func (sl *SecondLevelEncryption) ReEncrypt(reencKey *ReencKey) (*FirstLevelEncryption, error) {
	zbak, err := bls12381.Pair([]bls12381.G1Affine{sl.gk}, []bls12381.G2Affine{reencKey.ga1b2})
	if err != nil {
		return nil, err
	}
	return &FirstLevelEncryption{
		encFor: EncForA2,
		zak:    zbak,
		mzk:    sl.mzak,
	}, nil
}
