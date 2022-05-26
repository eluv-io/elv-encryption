package qafgh

import (
	"bytes"
	"crypto/rand"
	"testing"

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

	resBytes, err := res.MarshalBinary()
	require.NoError(t, err)

	msgBytes, err := msg.MarshalBinary()
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

	resBytes, err := res.MarshalBinary()
	require.NoError(t, err)

	msgBytes, err := msg.MarshalBinary()
	require.NoError(t, err)

	require.True(t, bytes.Equal(resBytes, msgBytes))
}
