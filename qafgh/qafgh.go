package qafgh

import (
	"fmt"
	"io"

	"github.com/cloudflare/circl/ecc/bls12381"
	"github.com/cloudflare/circl/ecc/bls12381/ff"
)

const GtCompressedSize = bls12381.GtSize / 2 // == 288

// Formula for decompression for the odd q case from Section 2 in
// "Compression in finite fields and torus-based cryptography" by
// Rubin-Silverberg.
// Use torus-based compression from Section 4.1 in
// "On Compressible Pairings and Their Computation" by Naehrig et al.
func CompressGt(gt *bls12381.Gt) ([]byte, error) {
	mb, _ := gt.MarshalBinary()
	ur := ff.URoot{}
	err := ur.UnmarshalBinary(mb)
	if err != nil {
		return nil, err
	}
	c0B, err := ur[0].MarshalBinary()
	if err != nil {
		return nil, err
	}
	b := ff.Fp6{}
	// b <- ur[0] (fp6)
	err = b.UnmarshalBinary(c0B)
	if err != nil {
		return nil, err
	}
	// b[0] <- b[0] + 1
	fp2one := ff.Fp2{}
	fp2one.SetOne()
	b[0].Add(&b[0], &fp2one)
	// b <- b / ur[1]
	ur1Inv := ff.Fp6{}
	ur1Inv.Inv(&ur[1])
	b.Mul(&b, &ur1Inv)

	return serFp6(b)
}

func DecompressGt(in []byte) (res bls12381.Gt, err error) {
	b, err := dsrFp6(in)
	if err != nil {
		return
	}

	one := ff.Fp6{}
	one.SetOne()
	neg1 := ff.Fp6{}
	neg1.SetOne()
	neg1.Neg()

	t := ff.Fp12{b, neg1}
	t.Inv(&t)
	c := ff.Fp12{b, one}
	c.Mul(&c, &t)
	var cB []byte
	cB, err = c.MarshalBinary()
	if err != nil {
		return
	}
	err = res.UnmarshalBinary(cB)
	if err != nil {
		return
	}
	isPairingRes, err := isFromPairing(&res)
	if err != nil {
		return
	}
	if !isPairingRes {
		err = fmt.Errorf("Invalid message: not a pairing result")
		return
	}
	return res, nil
}

func (msg *Message) Compressed() ([]byte, error) {
	return CompressGt(&msg.m)
}

func DecompressMessage(in []byte) (*Message, error) {
	gt, err := DecompressGt(in)
	if err != nil {
		return nil, err
	}
	return &Message{m: gt}, nil
}

type Message struct {
	m bls12381.Gt
}

func (msg *Message) ToBytes() ([]byte, error) {
	return CompressGt(&msg.m)
}

func MessageFromBytes(b []byte) (*Message, error) {
	gt, err := DecompressGt(b)
	if err != nil {
		return nil, err
	}
	return &Message{m: gt}, nil
}

func RandomMessage(rand io.Reader) (*Message, error) {
	k := bls12381.Scalar{}
	err := k.Random(rand)
	if err != nil {
		return nil, err
	}

	rg1 := bls12381.G1{}
	rg1.ScalarMult(&k, bls12381.G1Generator())
	// random elem of the form e(g1, g2^k) for random k
	return &Message{
		m: *bls12381.Pair(&rg1, bls12381.G2Generator()),
	}, nil
}

type PublicKey struct {
	za1 bls12381.Gt
	ga2 bls12381.G2
}

type SecretKey struct {
	a1 bls12381.Scalar
	a2 bls12381.Scalar
}

const PK_SIZE = GtCompressedSize + bls12381.G2SizeCompressed

func (pk *PublicKey) ToBytes() ([]byte, error) {
	ga2Bytes := pk.ga2.BytesCompressed()
	za1Bytes, err := CompressGt(&pk.za1)
	if err != nil {
		return nil, err
	}
	return append(ga2Bytes, za1Bytes...), nil
}

func PublicKeyFromBytes(arr []byte) (pk PublicKey, err error) {
	if len(arr) != PK_SIZE {
		err = fmt.Errorf("Invalid pubkey bytes size. Expected %v, got %v", PK_SIZE, len(arr))
		return
	}

	if err = pk.ga2.SetBytes(arr[:bls12381.G2SizeCompressed]); err != nil {
		return
	}
	if pk.za1, err = DecompressGt(arr[bls12381.G2SizeCompressed:]); err != nil {
		return
	}
	return
}

func (sk *SecretKey) ToBytes() ([]byte, error) {
	b1, err := sk.a1.MarshalBinary()
	if err != nil {
		return nil, err
	}
	b2, err := sk.a2.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return append(b1, b2...), nil
}

var GTZ = *bls12381.Pair(bls12381.G1Generator(), bls12381.G2Generator())

func (sk *SecretKey) Pubkey() (pk PublicKey) {
	pk.za1.Exp(&GTZ, &sk.a1)
	pk.ga2.ScalarMult(&sk.a2, bls12381.G2Generator())
	return
}

func SecretKeyFromBytes(skBytes []byte) (sk SecretKey, err error) {
	err = sk.a1.UnmarshalBinary(skBytes[:bls12381.ScalarSize])
	if err != nil {
		return
	}
	err = sk.a2.UnmarshalBinary(skBytes[bls12381.ScalarSize:])
	return
}

func RandomSecretKey(rand io.Reader) (sk SecretKey, err error) {
	err = sk.a1.Random(rand)
	if err != nil {
		return
	}
	err = sk.a2.Random(rand)
	return
}

const (
	EncForA1 = iota
	EncForA2
)

type FirstLevelEncryption struct {
	encFor int
	zak    bls12381.Gt
	mzk    bls12381.Gt
}

func FirstLevelEncrypt(msg *Message, pk *PublicKey, rand io.Reader) (*FirstLevelEncryption, error) {
	k := bls12381.Scalar{}
	err := k.Random(rand)
	if err != nil {
		return nil, err
	}

	zak := bls12381.Gt{}
	zak.Exp(&pk.za1, &k)

	mzk := bls12381.Gt{}
	mzk.Exp(&GTZ, &k)
	mzk.Mul(&msg.m, &mzk)
	return &FirstLevelEncryption{
		encFor: EncForA1,
		zak:    zak,
		mzk:    mzk,
	}, nil
}

func (fe *FirstLevelEncryption) Decrypt(sk *SecretKey) (*Message, error) {
	var invS bls12381.Scalar
	switch fe.encFor {
	case EncForA1:
		invS = sk.a1
	case EncForA2:
		invS = sk.a2
	default:
		return nil, fmt.Errorf("Invalid EncFor: %v", fe.encFor)
	}

	// 1/a
	invS.Inv(&invS)
	zk := bls12381.Gt{}
	// zk = (z^{ak})^(1/a)
	zk.Exp(&fe.zak, &invS)
	// zk = 1 / (z^k)
	zk.Inv(&zk)
	// zk = m z^k/z^k = m
	zk.Mul(&fe.mzk, &zk)

	return &Message{m: zk}, nil
}

const SecondLevelSize = bls12381.G1SizeCompressed + bls12381.GtSize

type SecondLevelEncryption struct {
	gk   bls12381.G1
	mzak bls12381.Gt
}

func EncryptSecondLevel(msg *Message, pk *PublicKey, rand io.Reader) (*SecondLevelEncryption, error) {
	k := bls12381.Scalar{}
	err := k.Random(rand)
	if err != nil {
		return nil, err
	}

	gk := bls12381.G1{}
	gk.ScalarMult(&k, bls12381.G1Generator())

	zak := bls12381.Gt{}
	zak.Exp(&pk.za1, &k)
	mzak := bls12381.Gt{}
	mzak.Mul(&msg.m, &zak)

	return &SecondLevelEncryption{gk: gk, mzak: mzak}, nil
}

func (sl *SecondLevelEncryption) ToBytes() ([]byte, error) {
	gkb := sl.gk.BytesCompressed()
	mzakb, err := CompressGt(&sl.mzak)
	if err != nil {
		return nil, err
	}
	return append(gkb, mzakb...), nil
}

func SecondLevelEncryptionFromBytes(b []byte) (sl SecondLevelEncryption, err error) {
	if len(b) != SecondLevelSize {
		err = fmt.Errorf("Invalid second level size. Got %v, expected %v", len(b), SecondLevelSize)
		return
	}
	if err = sl.gk.SetBytes(b[:bls12381.G1SizeCompressed]); err != nil {
		return
	}
	sl.mzak, err = DecompressGt(b[bls12381.G1SizeCompressed:])
	return
}

type ReencKey struct {
	ga1b2 bls12381.G2
}

func (re *ReencKey) ToBytes() []byte {
	return re.ga1b2.BytesCompressed()
}

func ReencKeyFromBytes(b []byte) (re ReencKey, err error) {
	err = re.ga1b2.SetBytes(b) // checks point is on G2
	if err == nil && (re.ga1b2.IsIdentity() || re.ga1b2.IsEqual(bls12381.G2Generator())) {
		err = fmt.Errorf("Invalid ReencKey: is identitiy")
	}
	return
}

func NewReencKey(owner *SecretKey, target *PublicKey) ReencKey {
	ga1b2 := bls12381.G2{}
	ga1b2.ScalarMult(&owner.a1, (&target.ga2))
	return ReencKey{ga1b2: ga1b2}
}

func (sl *SecondLevelEncryption) ReEncrypt(reencKey *ReencKey) *FirstLevelEncryption {
	zbak := bls12381.Pair(&sl.gk, &reencKey.ga1b2)
	return &FirstLevelEncryption{
		encFor: EncForA2,
		zak:    *zbak,
		mzk:    sl.mzak,
	}
}

func isFromPairing(gt *bls12381.Gt) (bool, error) {
	b, err := gt.MarshalBinary()
	if err != nil {
		return false, err
	}

	ur := ff.URoot{}
	err = ur.UnmarshalBinary(b)
	if err != nil {
		return false, err
	}
	ur.Exp(&ur, bls12381.Order())

	return ur.IsIdentity() == 1, nil
}
