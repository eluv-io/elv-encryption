package qafgh_test

import (
	"encoding/hex"
	"testing"

	"github.com/elv-will/elv-afgh/qafgh"
	"github.com/stretchr/testify/require"
)

var msgBytes, _ = hex.DecodeString("7071bb77f99c5670e160ea14214c154232dc2f9bd5bc9f9ce31c97a1bf10567a0d1a16ffa079c410c56d38970cd7031792d13b1ac39c1433c165cd1e3f157142c215d97b8622ee276adb3cdb41b627c70ccff26af1ed75626e131a0726c44b1395308194ed19dfc722620278e40bd656d5cb73842e3bc171c222a8ac496ccf53cee3d9db1cb3e90700b6886012f15114ee2fd40d098d388542a6fd7d8153916daea57238c2ee03b635acc90d844ec8a98660a0b0f081d8bbdc96e02f7415ec10ec4cf23d3ae12a0fac8fe9a31c3f14a86858ac83b01762bd86b4a8b3de6608a14508b71cdd8eccf1a5506afbd5b1340c2461b58745e69e00429060e1313f9ec288bd86158714a730d0c8897ffb3f8c66fdea14db3a197ff6354b496be4ae4e05")

func TestGNARK(t *testing.T) {
	// le to be
	for i, j := 0, len(msgBytes)-1; i < j; i, j = i+1, j-1 {
		msgBytes[i], msgBytes[j] = msgBytes[j], msgBytes[i]
	}

	_, err := qafgh.DecompressGtG(msgBytes)
	require.NoError(t, err)

}
