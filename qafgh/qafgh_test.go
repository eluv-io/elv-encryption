package qafgh

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/cloudflare/circl/ecc/bls12381"
	"github.com/cloudflare/circl/ecc/bls12381/ff"
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

	res, err := fl.Decrypt(&sk)
	require.NoError(t, err)

	resBytes, err := res.ToBytes()
	require.NoError(t, err)

	msgBytes, err := msg.ToBytes()
	require.NoError(t, err)

	require.True(t, bytes.Equal(resBytes, msgBytes))
}

func TestSecondLevelEnc(t *testing.T) {
	ska, err := RandomSecretKey(rand.Reader)
	require.NoError(t, err)
	skb, err := RandomSecretKey(rand.Reader)
	require.NoError(t, err)
	pka := ska.Pubkey()
	pkb := ska.Pubkey()
	msg, err := RandomMessage(rand.Reader)
	require.NoError(t, err)

	sl, err := EncryptSecondLevel(msg, &pka, rand.Reader)
	require.NoError(t, err)

	rkab := NewReencKey(&ska, &pkb)
	fl := sl.ReEncrypt(&rkab)
	res, err := fl.Decrypt(&skb)
	require.NoError(t, err)

	require.True(t, res.m.IsEqual(&msg.m))

	resBytes, err := res.ToBytes()
	require.NoError(t, err)

	msgBytes, err := msg.ToBytes()
	require.NoError(t, err)

	require.True(t, bytes.Equal(resBytes, msgBytes))
}

func randFp(t *testing.T) (res ff.Fp) {
	err := res.Random(rand.Reader)
	require.NoError(t, err)
	return
}

func randFp2(t *testing.T) ff.Fp2 {
	return [2]ff.Fp{randFp(t), randFp(t)}
}

func randFp12(t *testing.T) (res ff.Fp12) {
	res[0][0] = randFp2(t)
	res[0][1] = randFp2(t)
	res[0][2] = randFp2(t)
	res[1][0] = randFp2(t)
	res[1][1] = randFp2(t)
	res[1][2] = randFp2(t)
	return
}

func noTestIsValidPairing(t *testing.T) {
	for i := 0; i < 500; i++ {
		m, err := RandomMessage(rand.Reader)
		require.NoError(t, err)
		res, err := isFromPairing(&m.m)
		require.NoError(t, err)
		require.True(t, res)
	}
	for i := 0; i < 500; i++ {
		rfp := randFp12(t)
		rfpBytes, err := rfp.MarshalBinary()
		require.NoError(t, err)
		g := bls12381.Gt{}
		err = g.UnmarshalBinary(rfpBytes)
		require.NoError(t, err)
		fp, err := isFromPairing(&g)
		require.NoError(t, err)
		require.False(t, fp)
	}
}

func TestSerialization(t *testing.T) {
	ska, _ := RandomSecretKey(rand.Reader)
	skb, _ := RandomSecretKey(rand.Reader)
	skaBytes, _ := ska.ToBytes()
	skbBytes, _ := skb.ToBytes()
	t.Log("ska", hex.EncodeToString(skaBytes))
	t.Log("skb", hex.EncodeToString(skbBytes))

	pka := ska.Pubkey()
	pkb := skb.Pubkey()
	pkaBytes, err := pka.ToBytes()
	require.NoError(t, err)
	pkbBytes, err := pkb.ToBytes()
	require.NoError(t, err)
	t.Log("pka", hex.EncodeToString(pkaBytes))
	t.Log("pkb", hex.EncodeToString(pkbBytes))

	msg, _ := RandomMessage(rand.Reader)
	msgBytes, _ := msg.ToBytes()
	t.Log("msg", hex.EncodeToString(msgBytes))

	sl, err := EncryptSecondLevel(msg, &pka, rand.Reader)
	require.NoError(t, err)
	slBytes, _ := sl.ToBytes()
	t.Log("sl", hex.EncodeToString(slBytes))

	rkab := NewReencKey(&ska, &pkb)
	t.Log("rkab", hex.EncodeToString(rkab.ToBytes()))
	t.Fail()
}
