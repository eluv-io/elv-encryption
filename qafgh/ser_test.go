package qafgh

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSerFp6(t *testing.T) {
	a := randFp12(t)[0]
	ab, err := serFp6(a)
	require.NoError(t, err)
	require.Len(t, ab, 576/2)
	b, err := dsrFp6(ab)
	require.NoError(t, err)
	require.True(t, a.IsEqual(&b) == 1)
}

func TestSerFp2(t *testing.T) {
	a := randFp2(t)
	ab, err := serFp2(a)
	require.NoError(t, err)
	require.Len(t, ab, 576/6)
	b, err := dsrFp2(ab)
	require.NoError(t, err)
	require.True(t, a.IsEqual(&b) == 1)
}

func TestSerFp(t *testing.T) {
	a := randFp(t)
	ab, err := serFp(a)
	require.NoError(t, err)
	require.Len(t, ab, 576/12)
	b, err := dsrFp(ab)
	require.NoError(t, err)
	require.True(t, a.IsEqual(&b) == 1)
}
