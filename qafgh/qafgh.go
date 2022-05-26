package qafgh

import (
	"fmt"
	"io"

	"github.com/cloudflare/circl/ecc/bls12381"
)

func RandomMessage(rand io.Reader) (*bls12381.Gt, error) {
	k := bls12381.Scalar{}
	err := k.Random(rand)
	if err != nil {
		return nil, err
	}
	rg1 := bls12381.G1{}
	rg1.SetIdentity()
	rg2 := bls12381.G2{}
	rg2.SetIdentity()
	rg2.ScalarMult(&k, &rg2)
	// random elem of the form e(g1, g2^k) for random k
	return bls12381.Pair(&rg1, &rg2), nil
}

type PublicKey struct {
	za1 bls12381.Gt
	ga2 bls12381.G2
}

type SecretKey struct {
	a1 bls12381.Scalar
	a2 bls12381.Scalar
}

const PK_SIZE = bls12381.GtSize + bls12381.G2SizeCompressed

func (pk *PublicKey) ToBytes() ([]byte, error) {
	ga2Bytes := pk.ga2.BytesCompressed()
	za1Bytes, err := pk.za1.MarshalBinary()
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
	if err = pk.za1.UnmarshalBinary(arr[bls12381.G2SizeCompressed:]); err != nil {
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

func (sk *SecretKey) Pubkey() (pk PublicKey) {
	pk.za1.SetIdentity()
	pk.za1.Exp(&pk.za1, &sk.a1)
	pk.ga2.SetIdentity()
	pk.ga2.ScalarMult(&sk.a2, &pk.ga2)
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

func FirstLevelEncrypt(msg *bls12381.Gt, pk *PublicKey, rand io.Reader) (*FirstLevelEncryption, error) {
	k := bls12381.Scalar{}
	err := k.Random(rand)
	if err != nil {
		return nil, err
	}

	zak := bls12381.Gt{}
	zak.Exp(&pk.za1, &k)

	mzk := bls12381.Gt{}
	mzk.SetIdentity()
	mzk.Exp(&mzk, &k)
	mzk.Mul(msg, &mzk)
	return &FirstLevelEncryption{
		encFor: EncForA1,
		zak:    zak,
		mzk:    mzk,
	}, nil
}

func (fe *FirstLevelEncryption) Decrypt(sk *SecretKey) (*bls12381.Gt, error) {
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
	// zk = m z^k/z^k
	zk.Mul(&fe.mzk, &zk)

	return &zk, nil
}

type SecondLevelEncryption struct {
	gk   bls12381.G1
	mzak bls12381.Gt
}

func EncryptSecondLevel(msg *bls12381.Gt, pk *PublicKey, rand io.Reader) (*SecondLevelEncryption, error) {
	k := bls12381.Scalar{}
	err := k.Random(rand)
	if err != nil {
		return nil, err
	}

	gk := bls12381.G1{}
	gk.SetIdentity()
	gk.ScalarMult(&k, &gk)

	mzak := bls12381.Gt{}
	mzak.Exp(&pk.za1, &k)
	mzak.Mul(msg, &mzak)

	return &SecondLevelEncryption{gk: gk, mzak: mzak}, nil
}

type ReencKey struct {
	ga1b2 bls12381.G2
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
