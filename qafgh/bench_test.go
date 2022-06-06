package qafgh

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func BenchmarkEncryptSecondLevel(b *testing.B) {
	ska, err := RandomEncryptionSecretKey(rand.Reader)
	require.NoError(b, err)
	pka := ska.Pubkey()
	msg, err := RandomMessage(rand.Reader)
	require.NoError(b, err)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		EncryptSecondLevel(msg, &pka, rand.Reader)
	}
}

func BenchmarkReEncrypt(b *testing.B) {
	ska, err := RandomEncryptionSecretKey(rand.Reader)
	require.NoError(b, err)
	skb, err := RandomDecryptionSecretKey(rand.Reader)
	require.NoError(b, err)
	pka := ska.Pubkey()
	pkb := skb.Pubkey()
	msg, err := RandomMessage(rand.Reader)
	require.NoError(b, err)

	sl, err := EncryptSecondLevel(msg, &pka, rand.Reader)
	require.NoError(b, err)

	rkab := NewReencKey(ska, &pkb)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sl.ReEncrypt(&rkab)
	}
}

func BenchmarkDecryptFirstLevel(b *testing.B) {
	ska, err := RandomEncryptionSecretKey(rand.Reader)
	require.NoError(b, err)
	skb, err := RandomDecryptionSecretKey(rand.Reader)
	require.NoError(b, err)
	pka := ska.Pubkey()
	pkb := skb.Pubkey()
	msg, err := RandomMessage(rand.Reader)
	require.NoError(b, err)

	sl, err := EncryptSecondLevel(msg, &pka, rand.Reader)
	require.NoError(b, err)

	rkab := NewReencKey(ska, &pkb)
	fl, err := sl.ReEncrypt(&rkab)
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fl.Decrypt(skb)
	}
}
