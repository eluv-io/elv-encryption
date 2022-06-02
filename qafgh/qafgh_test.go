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
	pkb := skb.Pubkey()
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

	require.Equal(t, resBytes, msgBytes)
}

func TestMessageCompression(t *testing.T) {
	msg, err := RandomMessage(rand.Reader)
	require.NoError(t, err)
	cmp, err := msg.ToBytes()
	require.NoError(t, err)
	require.Len(t, cmp, 576/2)

	res, err := MessageFromBytes(cmp)
	require.NoError(t, err)
	require.True(t, msg.m.IsEqual(&res.m))
}

func TestMessageCompressionFromUnpaired(t *testing.T) {
	// from rand gt
	gt := randGt(t)
	m := &Message{m: gt}
	mB, err := m.ToBytes()
	require.NoError(t, err)

	_, err = MessageFromBytes(mB)
	require.Error(t, err)
	// from pairing result
	m, err = RandomMessage(rand.Reader)
	require.NoError(t, err)
	cmp, err := m.ToBytes()
	require.NoError(t, err)

	res, err := MessageFromBytes(cmp)
	require.NoError(t, err)
	require.True(t, m.m.IsEqual(&res.m))

	// Check recompressing gives the same bytes
	cmp2, err := res.ToBytes()
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
var skbBytes, _ = hex.DecodeString("6f3ef36ff8cdcfec7cbfe70d386d6bdb5b8779b58a9c06d7a546d03b56e31135447175b8d1cdec5b13f8379e4e2d4e8d0b12053ca2b6ba9f433269504642cedf")
var pkbBytes, _ = hex.DecodeString("b8b56a83ebad81d9b1e2a51b63c1f14fb17b709d75cd78e2735fdaf9e24d194fb577451df51ea196a2e9fb886abaf0231067a5f7d12fce685a9d5511b797f468a0b25767ab637b74ec2f8ff15ef4454f957a1bde159fad7f466d748d81246ed84b192b70e6a60693bc2eac4b7850ca06b485a3f9dbb9ecb78a4febee9abd739b7d64b1df668f58b06a61f1ef8491d411e52bd6e99701bb199afffc549044e8831321b44bb8900015b47f99696d50a65201b92059e093b82683fb27cfd2e11b117e32d3326d7bf0929e1baae2856758ab04d2080065eb7cabda8cf3648147f9b0f13d43c6907ebdc2c8d41d3e8eddf4078161fc9d6ced4eab746a6d6648d3d79069114a7e9cee16383530000e24fb2686cbbb0b7a53f85d2d3bfca071fc402d09199d064476e52ca20dde7ff25e8b1341b6c2ad3ec05adb8e63f551b1367932b863874a80eea03a0c751cde2e059b2415e7bcede5fe50cf70a4f0b92ee8696c56e118806f041125a2a03182448dbaf2d1f25576a6886f2676a9959d72dd618510")

var msgBytes, _ = hex.DecodeString("7071bb77f99c5670e160ea14214c154232dc2f9bd5bc9f9ce31c97a1bf10567a0d1a16ffa079c410c56d38970cd7031792d13b1ac39c1433c165cd1e3f157142c215d97b8622ee276adb3cdb41b627c70ccff26af1ed75626e131a0726c44b1395308194ed19dfc722620278e40bd656d5cb73842e3bc171c222a8ac496ccf53cee3d9db1cb3e90700b6886012f15114ee2fd40d098d388542a6fd7d8153916daea57238c2ee03b635acc90d844ec8a98660a0b0f081d8bbdc96e02f7415ec10ec4cf23d3ae12a0fac8fe9a31c3f14a86858ac83b01762bd86b4a8b3de6608a14508b71cdd8eccf1a5506afbd5b1340c2461b58745e69e00429060e1313f9ec288bd86158714a730d0c8897ffb3f8c66fdea14db3a197ff6354b496be4ae4e05")
var slEncBytes, _ = hex.DecodeString("ac370a5ca448c189bbbafd7b5fda273d66f3b62d877ea70db18a5c5293a70ee9b2acb3a33f3f7cb93f9b93ee62fd1fb278edf3fe10983f8fcb84b5045df0e22102dd6a9c2d179c156c899fa183fb04061660964853c60af45cebd5896abc610b09164680a6d9766af09ecf91a98b91ddaacacc7f9ed579f8c1932549a9e2f7424ad779653447508d08a9ceb456b1b212c67eff8cd27ec4bedc78e5de0188e6e6e27ec4fc923b459a3a26f99ef4c852f7b45f5bf0fad35ee294303530a015b90c8720204ed8f8cbab5e6dbd17f629513a94e0049474c866e255f0b6b43c2674567c6fc5c5122707de18a91513b7902a1471645324d29000c5baa88d104086eb0dd12f4808c0329708e699f7221c330e70ec6056d865e3adda4fde855594f23f163cb26cd753d1bd698966efb73cc289c1bb009ee32ef3fc079a162c99346bd2d9ea83a55d7258f1ae24cf2ca491906b07")
var rkabBytes, _ = hex.DecodeString("98e8fd82f8c803322afde4298b1aba5e9ee85f4b796f7ff4df7c1605a343cecb5efcc30f4e61d6b077c8ed2d297457a90c271c32282dd36f1916521b9fe13ee135fba7d9f0f3766a70156e454af2750dbd1367e26661c3a94f6147815927447b")

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

func TestSerialization(t *testing.T) {
	ska, err := SecretKeyFromBytes(skaBytes)
	require.NoError(t, err)
	skb, err := SecretKeyFromBytes(skbBytes)
	require.NoError(t, err)

	pka := ska.Pubkey()
	pkaBytesRes, err := pka.ToBytes()
	require.NoError(t, err)
	require.Equal(t, pkaBytes, pkaBytesRes)

	pkb := skb.Pubkey()
	pkbBytesRes, err := pkb.ToBytes()
	require.NoError(t, err)
	require.Equal(t, pkbBytes, pkbBytesRes)

	msg, err := MessageFromBytes(msgBytes)
	require.NoError(t, err)

	rkab, err := ReencKeyFromBytes(rkabBytes)
	require.NoError(t, err)

	sl, err := SecondLevelEncryptionFromBytes(slEncBytes)
	require.NoError(t, err)

	msgRes, err := sl.ReEncrypt(&rkab).Decrypt(&skb)
	require.NoError(t, err)
	require.True(t, msgRes.m.IsEqual(&msg.m))

	resBytes, err := msgRes.ToBytes()
	require.NoError(t, err)
	require.Equal(t, resBytes, msgBytes)
}
