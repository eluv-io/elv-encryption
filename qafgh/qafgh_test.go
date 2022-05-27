package qafgh

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/cloudflare/circl/ecc/bls12381"
	"github.com/cloudflare/circl/ecc/bls12381/ff"
	"github.com/stretchr/testify/assert"
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
	pkb := skb.Pubkey()
	msg, err := RandomMessage(rand.Reader)
	require.NoError(t, err)

	sl, err := EncryptSecondLevel(msg, &pka, rand.Reader)
	require.NoError(t, err)

	rkab := NewReencKey(&ska, &pkb)
	fl := sl.ReEncrypt(&rkab)
	res, err := fl.Decrypt(&skb)
	require.NoError(t, err)

	assert.True(t, res.m.IsEqual(&msg.m))

	resBytes, err := res.ToBytes()
	require.NoError(t, err)

	msgBytes, err := msg.ToBytes()
	require.NoError(t, err)

	assert.Equal(t, resBytes, msgBytes)
}

func TestMessageCompression(t *testing.T) {
	msg, err := RandomMessage(rand.Reader)
	require.NoError(t, err)
	cmp, err := msg.Compressed()
	require.NoError(t, err)
	require.Len(t, cmp, 576/2)

	res, err := DecompressMessage(cmp)
	require.NoError(t, err)
	require.True(t, msg.m.IsEqual(&res.m))
}

func TestMessageCompressionFromUnpaired(t *testing.T) {
	// from rand gt
	gt := randGt(t)
	m := &Message{m: gt}
	mB, err := m.Compressed()
	require.NoError(t, err)

	_, err = DecompressMessage(mB)
	require.Error(t, err)
	// from pairing result
	m, err = RandomMessage(rand.Reader)
	require.NoError(t, err)
	cmp, err := m.Compressed()
	require.NoError(t, err)

	res, err := DecompressMessage(cmp)
	require.NoError(t, err)
	require.True(t, m.m.IsEqual(&res.m))

	// Check recompressing gives the same bytes
	cmp2, err := res.Compressed()
	require.NoError(t, err)

	require.Equal(t, cmp, cmp2)
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

func randGt(t *testing.T) (res bls12381.Gt) {
	fp12 := randFp12(t)
	fp12B, err := fp12.MarshalBinary()
	require.NoError(t, err)
	err = res.UnmarshalBinary(fp12B)
	require.NoError(t, err)
	return
}

func TestIsValidPairing(t *testing.T) {
	for i := 0; i < 100; i++ {
		m, err := RandomMessage(rand.Reader)
		require.NoError(t, err)
		res, err := isFromPairing(&m.m)
		require.NoError(t, err)
		require.True(t, res)
	}
	for i := 0; i < 100; i++ {
		g := randGt(t)
		fp, err := isFromPairing(&g)
		require.NoError(t, err)
		require.False(t, fp)
	}
}

var skaBytes, _ = hex.DecodeString("0e6cfd632776c53d7d30ca85532bda02bc7bb9581c8d1a965b7266b1427d3f872da6ec9ad9dbfdb8ef3a37ef0753debc0d01932276e11b78c2a9d0e4564bab0c")
var pkaBytes, _ = hex.DecodeString("87acbe54f1faccacedc1f0fdd3225c811e4abb0ad5878a29710600b404b0e4ae809916186ba418103c43eeec4c088f9f0de1a2310836cc8d5208796b86f10ad25918f72e35f334a162c3b01c39815edc70a97f07e158fcedf5c89405b1070a7855017d15b53be47dcd1a7f718c4eb690b53ad24b3169d0a1965e82a7965879501f2e30e9c4f664aa7873a6cab7e24e0460bfb3fde3d1dc89a5cdbb2d9418e6c90ad5887712323cce3de0ae7ef13f5f8b1868a0b6e8a7bf50fe4f899b9baf350b54aeb296df5e9e0504dd503e8e1fc182a0566240e1d67687a68ab75f3ba872753d887396b4c41225f74b235bc7d66813cba9aae1846c41f4b30c43310d5b21a35c2ca7756d40660cda91be9218670db65ebdfac3df77e9585413ff9e5c937c1673d3d144eacc53a3879d96d87259a72789a8d9bf54e65386bc896b7e01eb358c7d69f7901aa8a410a156529fd484260db5f2602b83d239518f8160706ecc45665db49bda6b4be1a4894db8e56273bd9893f9dbd25a230c9746c9fd93e1cb690b")

func TestKeySerialization(t *testing.T) {
	ska, err := SecretKeyFromBytes(skaBytes)
	require.NoError(t, err)
	skaBytesRes, err := ska.ToBytes()
	require.NoError(t, err)
	require.Equal(t, skaBytes, skaBytesRes)

	pka := ska.Pubkey()
	pkaBytesRes, err := pka.ToBytes()
	require.NoError(t, err)
	require.Equal(t, pkaBytes, pkaBytesRes)
}

func noTestSerialization(t *testing.T) {
	ska, err := SecretKeyFromBytes(skaBytes)
	require.NoError(t, err)
	skb, _ := RandomSecretKey(rand.Reader)
	skaBytes, err := ska.ToBytes()
	require.NoError(t, err)
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
