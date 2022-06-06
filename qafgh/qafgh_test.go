package qafgh

import (
	"crypto/rand"
	"io"
	"math/big"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/stretchr/testify/require"
)

func TestSecondLevelEnc(t *testing.T) {
	ska, err := RandomEncryptionSecretKey(rand.Reader)
	require.NoError(t, err)
	skb, err := RandomDecryptionSecretKey(rand.Reader)
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

	res, err := MessageFromBytes(cmp[:])
	require.NoError(t, err)
	require.True(t, msg.m.Equal(&res.m))
}

func TestMessageCompressionFromUnpaired(t *testing.T) {
	// from rand gt
	gt := randGt(t)
	m := &Message{m: gt}
	mB := m.ToBytes()

	_, err := MessageFromBytes(mB[:])
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
	gt, err := randGTInGroup(rand.Reader)
	require.NoError(t, err)

	compressed := compressGt(gt)
	decompress, err := decompressGt(compressed[:])
	require.NoError(t, err)
	require.True(t, decompress.Equal(&gt))
}

func TestScalarMult(t *testing.T) {
	rb := [32]byte{}
	_, err := io.ReadFull(rand.Reader, rb[:])
	require.NoError(t, err)

	elem := fr.Element{}
	elem.SetBytes(rb[:])

	bi := big.Int{}
	bi.SetBytes(rb[:])
	bi.Mod(&bi, bls12381.ID.Info().Fr.Modulus())

	require.Equal(t, bi.Bytes(), elem.Marshal())

	elemBi := big.Int{}
	elem.ToBigInt(&elemBi)

	require.NotEqual(t, bi, elemBi)

	elemBir := big.Int{}
	elem.ToBigIntRegular(&elemBir)

	require.Equal(t, bi, elemBir)

	gtbi := GTZ
	gtbi.Exp(&gtbi, elemBir)

	gtelem := GTZ
	gtelem.Exp(&gtelem, scalarToBig(&elem))

	require.True(t, gtelem.Equal(&gtbi))

}
