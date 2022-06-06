package qafgh

import (
	"crypto/rand"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
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

func TestGTSerialization(t *testing.T) {
	gt, err := randGTInGroup(rand.Reader)
	require.NoError(t, err)

	compressed := compressGt(gt)
	decompress, err := decompressGt(compressed[:])
	require.NoError(t, err)
	require.True(t, decompress.Equal(&gt))
}
