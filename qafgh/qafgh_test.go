package qafgh

import (
	"bytes"
	"crypto/rand"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/stretchr/testify/require"
)

func TestFirstLevelEnc(t *testing.T) {
	sk, err := RandomSecretKey(rand.Reader)
	pk := sk.Pubkey()
	require.NoError(t, err)
	msg, err := RandomMessage(rand.Reader)
	require.NoError(t, err)
	fl, err := FirstLevelEncrypt(msg, &pk, rand.Reader)
	require.NoError(t, err)

	res, err := fl.Decrypt(sk)
	require.NoError(t, err)

	resBytes := res.ToBytes()
	msgBytes := msg.ToBytes()

	require.True(t, bytes.Equal(resBytes, msgBytes))
}

func TestSecondLevelEnc(t *testing.T) {
	ska, err := RandomSecretKey(rand.Reader)
	require.NoError(t, err)
	skb, err := RandomSecretKey(rand.Reader)
	require.NoError(t, err)
	pka := ska.Pubkey()
	pkb := skb.Pubkey()
	msg, err := RandomMessage(rand.Reader)
	require.NoError(t, err)

	sl, err := EncryptSecondLevel(msg, &pka, rand.Reader)
	require.NoError(t, err)

	rkab := NewReencKey(ska, &pkb)
	fl, err := sl.ReEncrypt(&rkab)
	require.NoError(t, err)

	res, err := fl.Decrypt(skb)
	require.NoError(t, err)

	require.True(t, res.m.Equal(&msg.m))

	resBytes := res.ToBytes()
	msgBytes := msg.ToBytes()

	require.Equal(t, resBytes, msgBytes)
}

func TestMessageSerialization(t *testing.T) {
	msg, err := RandomMessage(rand.Reader)
	require.NoError(t, err)
	cmp := msg.ToBytes()
	require.Len(t, cmp, 576/2)

	res, err := MessageFromBytes(cmp)
	require.NoError(t, err)
	require.True(t, msg.m.Equal(&res.m))
}

func TestMessageCompressionFromUnpaired(t *testing.T) {
	// from rand gt
	gt := randGt(t)
	m := &Message{m: gt}
	mB := m.ToBytes()

	_, err := MessageFromBytes(mB)
	require.Error(t, err)
}

func randGt(t *testing.T) (res bls12381.GT) {
	res.SetRandom()
	return
}

func TestIsValidPairing(t *testing.T) {
	for i := 0; i < 100; i++ {
		m, err := RandomMessage(rand.Reader)
		require.NoError(t, err)
		require.True(t, m.m.IsInSubGroup())
		cmp := m.m.CompressTorus()
		res := cmp.DecompressTorus()
		require.True(t, res.Equal(&m.m))
	}
	for i := 0; i < 100; i++ {
		g := randGt(t)
		require.False(t, g.IsInSubGroup())
	}
}

//func TestKeySerialization(t *testing.T) {
//	ska, err := SecretKeyFromBytes(skaBytes)
//	require.NoError(t, err)
//	skaBytesRes, err := ska.ToBytes()
//	require.NoError(t, err)
//	require.Equal(t, skaBytes, skaBytesRes)
//
//	pka := ska.Pubkey()
//	pkaBytesRes, err := pka.ToBytes()
//	require.NoError(t, err)
//	require.Equal(t, pkaBytes, pkaBytesRes)
//}

//
//func TestSerialization(t *testing.T) {
//	ska, err := SecretKeyFromBytes(skaBytes)
//	require.NoError(t, err)
//	skb, err := SecretKeyFromBytes(skbBytes)
//	require.NoError(t, err)
//
//	pka := ska.Pubkey()
//	pkaBytesRes, err := pka.ToBytes()
//	require.NoError(t, err)
//	require.Equal(t, pkaBytes, pkaBytesRes)
//
//	pkb := skb.Pubkey()
//	pkbBytesRes, err := pkb.ToBytes()
//	require.NoError(t, err)
//	require.Equal(t, pkbBytes, pkbBytesRes)
//
//	msg, err := MessageFromBytes(msgBytes)
//	require.NoError(t, err)
//
//	rkab, err := ReencKeyFromBytes(rkabBytes)
//	require.NoError(t, err)
//
//	sl, err := SecondLevelEncryptionFromBytes(slEncBytes)
//	require.NoError(t, err)
//
//	msgRes, err := sl.ReEncrypt(&rkab).Decrypt(&skb)
//	require.NoError(t, err)
//	require.True(t, msgRes.m.IsEqual(&msg.m))
//
//	resBytes, err := msgRes.ToBytes()
//	require.NoError(t, err)
//	require.Equal(t, resBytes, msgBytes)
//}

func TestGTSerialization(t *testing.T) {
	gt, err := RandGTInGroup(rand.Reader)
	require.NoError(t, err)

	compressed := CompressGtG(gt)
	decompress, err := DecompressGtG(compressed)
	require.NoError(t, err)
	require.True(t, decompress.Equal(&gt))
}

func TestThingy(t *testing.T) {
	m, _ := RandomMessage(rand.Reader)
	gt := m.m
	require.True(t, gt.IsInSubGroup())
	b1 := gt.CompressTorus()
	bytes21 := b1.B2.A1.Bytes()
	bytes20 := b1.B2.A0.Bytes()
	bytes11 := b1.B1.A1.Bytes()
	bytes10 := b1.B1.A0.Bytes()
	bytes01 := b1.B0.A1.Bytes()
	bytes00 := b1.B0.A0.Bytes()

	out := [288]byte{}
	// serialize big endian
	copy(out[0*48:1*48], bytes21[:])
	copy(out[1*48:2*48], bytes20[:])
	copy(out[2*48:3*48], bytes11[:])
	copy(out[3*48:4*48], bytes10[:])
	copy(out[4*48:5*48], bytes01[:])
	copy(out[5*48:6*48], bytes00[:])

	a := bls12381.GT{}
	b2 := a.C0

	b2.B2.A1.SetBytes(out[0*48 : 1*48])
	b2.B2.A0.SetBytes(out[1*48 : 2*48])
	b2.B1.A1.SetBytes(out[2*48 : 3*48])
	b2.B1.A0.SetBytes(out[3*48 : 4*48])
	b2.B0.A1.SetBytes(out[4*48 : 5*48])
	b2.B0.A0.SetBytes(out[5*48 : 6*48])

	require.True(t, b2.Equal(&b1))

	res1 := b1.DecompressTorus()
	res2 := b2.DecompressTorus()
	require.True(t, res1.IsInSubGroup())
	require.True(t, res2.IsInSubGroup())

	require.True(t, res1.Equal(&res2))
	require.True(t, res1.Equal(&gt))
	require.True(t, res2.Equal(&gt))
}
