//go:build !libsecp256k1_sdk
// +build !libsecp256k1_sdk

package secp256k1

import (
	"encoding/hex"
	"strconv"
	"testing"

	secp256k1 "github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/stretchr/testify/require"
)

// Ensure that signature verification works, and that
// non-canonical signatures fail.
// Note: run with CGO_ENABLED=0 or go test -tags !cgo.
func TestSignatureVerificationAndRejectUpperS(t *testing.T) {
	msg := []byte("We have lingered long enough on the shores of the cosmic ocean.")
	for i := 0; i < 500; i++ {
		priv := GenPrivKey()
		sigStr, err := priv.Sign(msg)
		require.NoError(t, err)
		var r secp256k1.ModNScalar
		r.SetByteSlice(sigStr[:32])
		var s secp256k1.ModNScalar
		s.SetByteSlice(sigStr[32:64])
		require.False(t, s.IsOverHalfOrder())

		pub := priv.PubKey()
		require.True(t, pub.VerifySignature(msg, sigStr))

		// malleate:
		var S256 secp256k1.ModNScalar
		S256.SetByteSlice(secp256k1.S256().N.Bytes())
		s.Negate().Add(&S256)
		require.True(t, s.IsOverHalfOrder())

		rBytes := r.Bytes()
		sBytes := s.Bytes()
		malSigStr := make([]byte, 64)
		copy(malSigStr[32-len(rBytes):32], rBytes[:])
		copy(malSigStr[64-len(sBytes):64], sBytes[:])
		require.False(t, pub.VerifySignature(msg, malSigStr),
			"VerifyBytes incorrect with malleated & invalid S. sig=%v, key=%v",
			malSigStr,
			priv,
		)
	}
}

func SignEip191(priv *PrivKey, msg []byte) ([]byte, error) {
	msgHash := keccak256(msg)

	secp256k1Priv, _ := secp256k1.PrivKeyFromBytes(priv.Key)

	sig, err := ecdsa.SignCompact(secp256k1Priv, msgHash, false)
	if err != nil {
		return nil, err
	}
	return sig[1:], nil
}

func TestSignatureVerificationMetamask(t *testing.T) {
	msg := []byte("We have lingered long enough on the shores of the cosmic ocean.")
	priv := GenPrivKey()

	bz := append(
		[]byte("\x19Ethereum Signed Message:\n"),
		[]byte(strconv.Itoa(len(msg)))...,
	)

	bz = append(bz, msg...)

	sig, err := SignEip191(priv, bz)
	require.NoError(t, err)

	println("signature", hex.EncodeToString(sig))

	pub, _ := priv.PubKey().(*PubKey)
	require.True(t, pub.VerifySignatureEip191(bz, sig))
}
