package qafgh

import (
	"crypto/sha256"
	"fmt"
	"io"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

const MessageSize = compressedGtSize

type Message struct {
	m bls12381.GT
}

func (msg *Message) DeriveAESKey() ([]byte, error) {
	dst := []byte("ELV_AFGH_MSG")
	msgBytes := msg.ToBytes()
	dst = append(dst, msgBytes[:]...)
	hasher := sha256.New()
	_, err := hasher.Write(dst)
	if err != nil {
		return nil, err
	}
	// Take first 16 bytes of hash
	return hasher.Sum(nil)[:16], nil
}

func (msg *Message) ToBytes() [MessageSize]byte {
	return compressGt(msg.m)
}

func MessageFromBytes(b []byte) (*Message, error) {
	gt, err := decompressGt(b)
	if err != nil {
		return nil, err
	}
	return &Message{m: *gt}, nil
}

func RandomMessage(r io.Reader) (*Message, error) {
	gt, err := randGTInGroup(r)
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

var _, _, G1GEN, G2GEN = bls12381.Generators()
var GTZ, _ = bls12381.Pair([]bls12381.G1Affine{G1GEN}, []bls12381.G2Affine{G2GEN})

const FirstLevelSize = 2 * compressedGtSize

type FirstLevelEncryption struct {
	zak bls12381.GT
	mzk bls12381.GT
}

func FirstLevelEncryptionFromBytes(inp []byte) (*FirstLevelEncryption, error) {
	if len(inp) != FirstLevelSize {
		return nil, fmt.Errorf("Invalid first level size")
	}
	zak, err := decompressGt(inp[:compressedGtSize])
	if err != nil {
		return nil, err
	}
	mzk, err := decompressGt(inp[compressedGtSize:])
	if err != nil {
		return nil, err
	}
	return &FirstLevelEncryption{
		zak: *zak,
		mzk: *mzk,
	}, nil
}

func (fl *FirstLevelEncryption) ToBytes() []byte {
	zakB := compressGt(fl.zak)
	mzkB := compressGt(fl.mzk)
	return append(zakB[:], mzkB[:]...)
}

func (fe *FirstLevelEncryption) Decrypt(sk *DecryptionSecretKey) (*Message, error) {
	invEl := fr.Element{}
	// 1/b
	invEl.Inverse(&sk.b2)

	zk := bls12381.GT{}
	// zk = (z^{bk'})^(1/b)
	zk.Exp(&fe.zak, scalarToBig(&invEl))
	// zk = 1 / (z^k')
	zk.Inverse(&zk)
	// zk = m z^k'/z^k' = m
	zk.Mul(&fe.mzk, &zk)

	return &Message{m: zk}, nil
}

const SecondLevelSize = bls12381.SizeOfG1AffineCompressed + compressedGtSize

type SecondLevelEncryption struct {
	gk   bls12381.G1Affine
	mzak bls12381.GT
}

func EncryptSecondLevel(msg *Message, pk *EncryptionPublicKey, r io.Reader) (*SecondLevelEncryption, error) {
	k, err := randScalar(r)
	if err != nil {
		return nil, err
	}
	kBig := scalarToBig(&k)

	gk := bls12381.G1Affine{}
	gk.ScalarMultiplication(&G1GEN, &kBig)

	zak := bls12381.GT{}
	zak.Exp(&pk.za1, kBig)
	mzak := bls12381.GT{}
	mzak.Mul(&msg.m, &zak)

	return &SecondLevelEncryption{gk: gk, mzak: mzak}, nil
}

func (sl *SecondLevelEncryption) ToBytes() ([]byte, error) {
	gkb := sl.gk.Bytes()
	mzakb := compressGt(sl.mzak)
	return append(gkb[:], mzakb[:]...), nil
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
	mzak, err = decompressGt(b[bls12381.SizeOfG1AffineCompressed:])
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

func NewReencKey(owner *EncryptionSecretKey, target *DecryptionPublicKey) ReencKey {
	ga1b2 := bls12381.G2Affine{}
	a1Big := scalarToBig(&owner.a1)
	ga1b2.ScalarMultiplication(&target.gb2, &a1Big)
	return ReencKey{ga1b2: ga1b2}
}

func (sl *SecondLevelEncryption) ReEncrypt(reencKey *ReencKey) (*FirstLevelEncryption, error) {
	zbak, err := bls12381.Pair([]bls12381.G1Affine{sl.gk}, []bls12381.G2Affine{reencKey.ga1b2})
	if err != nil {
		return nil, err
	}
	return &FirstLevelEncryption{
		zak: zbak,
		mzk: sl.mzak,
	}, nil
}
