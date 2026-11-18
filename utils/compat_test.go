package utils

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha512"
	"strings"
	"testing"

	b64 "encoding/base64"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The fixtures below were produced by the implementation as of commit 255a8dd,
// using b64PrivKeyOriginal / b64PubKeyOriginal from crypt_test.go. They pin the
// wire format: anything that stops accepting them is a breaking change for data
// already stored in a vault or for tokens issued by older clients.

var compatCiphertexts = map[string]string{
	"": "BABHnbTZ48eaQjnmvsGzjCuEP86eQKFEISYsXi8z9bI2PX/vJZZENTYc/iURnvJLREldPwEf5y/VP3cS3L1uSq4MmQD/rsVV/frnfaPQA3+lYt7F5hq8Io97dwev+WtIVmKRX0/xhg0lJiLsun+abXTzFQ46gLDKrF9TU3Ccub8n2+zcob2UuvGO0hT8r3MyEmC447GBmTReqrBPdXdvjLVCOkPE",

	"Test123": "BAEumGAxprP0CdvbfDYY8pFGUMC4xJfSTRxnS7WEGgfqLIj9Rpys8VA5ubmKDVXDabavSklWs+85PeHgZ9BkYDe0pwCdChCdUnF7x4eFSftAGHZl8ZVgcp+dGWdvI4p7fRHp0MtNSHU8OkvjYf6hY61Nqo9gBTu1eBu7SpXk13UVsOWMEESxtCCu61GEzJkmUvmSEOGSqNoCRScwo42lZ7WwjdQBBOwhXSZwNQ==",

	strings.Repeat("A", 64): "BADqsp78GUpqizNYLGGv8n7ErOfPF7Gonw53wpF7iRc8hc/0B+Z/IMppWnM5Th7CsKoGSTiidqIjFhL+k4y04WJ79gA+2ZjDPUpQ2mBFJLgrubyjAMHcJFSQY4kwBMFpuY0urIt9G/5mQHhqEBqSXG1IyPoAk7kx2Gz300yYAMckQFs9UMBTBxhrz6/CS3phSHzIWY2Ps6z82Ya5IVCGtI3xJSJUefrx5l3yQuLrK87z8ldGF0AYvEcF/N9v9BDfVHeaXNf5XJlGxtkhobWr3iJsrJSY3at+O3cVfL+UqEsOdkB/Vw==",

	"äöü-ümläut-𝄞-payload": "BAD/iaO6hmFdZvp2v+3tR5LvxN6yAiQZwRMaZ8yjv/5vEL6SlpkzPNObLJtMYw1wfVhwuwTD1WFKTXHysGJ+upiqjgFtkrdOvELY5RivR/FZn+P8EoGjnake+u7RNRmE99I7XELtT7saT5M74wrdGmSxdvqqt+XrmqduI1yAiFsmDnNKvTiFY6qLlQYjHl2ipe2prgCc/YsKVIwiy9gYVxm/u3MrVSCGpWcgAP277NPRxMm13HrDuhCeIfeCNhQRIg==",
}

const (
	compatSignedMessage = "Test123"
	compatSignature     = "AtVJ3HQsUhUlW645GRkaBDrJe5raTlz8JMksaIKF68GEw4StMdipyskaPsccMYoapzXXrCpmmBT1ymeuX3i7krE=-AbAXNj6lNy8OENpRii29CD320aQvif5OL7ofQuklO9Iv0HkWnuTYLnworYGher3KJaZBPnGf9moIanlTwmjJDh49"

	compatJWT = "eyJ0eXAiOiJKV1QiLCJhbGciOiJQLTUyMSJ9.eyJleHAiOiIyMDI2LTEwLTI4VDE3OjM4OjIxLjExOTc4NzgxNiswMTowMCIsImlhdCI6IjIwMjYtMTAtMjhUMTc6MzM6MjEuMTE5Nzg4MjE3KzAxOjAwIiwidmF1bHRfaWQiOiJ0ZXN0X3ZhdWx0IiwidG9rZW5faWQiOiIzOWM3NjY3MGRkZGNjODNmN2UzYmU2ZDMxNGU0ZWQwOTcyMmFjZmNjYjVmMzM3NDUzMTI5M2I4ZmI4YWY1YjJjIn0=.AfwxnBfg1Q4aa55TwiZspGTPTqPs23rj9EHd+VwogpbLgxt8xjTPGaKKJXR6h7bJEI44cmrjK7vXLcXALM5w6xst-AXjy3FkcDvHvfTYRtpsf/tYfby1WMVApTk/jdZ5pSA0d/obUOYYxW5nP6rL2KRDUoeytp9oYtnb5x/mcT4Wz9pT2"

	compatCreatorJWT = "eyJ0eXAiOiJKV1QiLCJhbGciOiJQLTUyMSJ9.eyJpYXQiOiIyMDI2LTEwLTI4VDE3OjMzOjIxLjEyMDQwMTQzNSswMTowMCIsInZhdWx0X2lkIjoidGVzdF92YXVsdCIsImNyZWF0b3JfdG9rZW5faWQiOiIzOWM3NjY3MGRkZGNjODNmN2UzYmU2ZDMxNGU0ZWQwOTcyMmFjZmNjYjVmMzM3NDUzMTI5M2I4ZmI4YWY1YjJjIiwidG9rZW5faWQiOiJuZXdJZGVudGl0eUlkIn0=.wn99e015TOpPe4TFD8/TdHJvOzykjSzMQcDmtI/QShccIpFNXWFMPQxKXyvANDk/1tUQ4Gz/YC78y2YJZRFwDo8=-lQH/gW5ozAVK/Cb82E/lYWus/08pEGPt2n88Oo8A4eXwSgCyM1ULehHnbMcozKJowHPglND3lOaKlPxr2LOjch0="

	// base64 of {"typ":"JWT","alg":"P-521"}
	compatJWTHeader = "eyJ0eXAiOiJKV1QiLCJhbGciOiJQLTUyMSJ9"

	compatVaultId = "test_vault"
	compatTokenId = "39c76670dddcc83f7e3be6d314e4ed09722acfccb5f3374531293b8fb8af5b2c"
)

func b64Std(in []byte) string {
	return b64.StdEncoding.EncodeToString(in)
}

func b64Decode(in string) ([]byte, error) {
	return b64.StdEncoding.DecodeString(in)
}

func compatKeys(t *testing.T) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	t.Helper()
	priv, err := GetPrivateKeyFromB64String(b64PrivKeyOriginal)
	require.NoError(t, err)
	pub, err := GetPublicKeyFromB64String(b64PubKeyOriginal)
	require.NoError(t, err)
	return priv, pub
}

func TestCompatDecryptStoredCiphertexts(t *testing.T) {
	priv, _ := compatKeys(t)
	for plain, cipher := range compatCiphertexts {
		t.Run(plain, func(t *testing.T) {
			got, err := Decrypt(priv, cipher)
			require.NoError(t, err)
			assert.Equal(t, plain, string(got))
		})
	}
}

func TestCompatVerifyStoredSignature(t *testing.T) {
	_, pub := compatKeys(t)
	ok, err := Verify(pub, compatSignedMessage, compatSignature)
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestCompatVerifyStoredCreatorJWT(t *testing.T) {
	_, pub := compatKeys(t)
	msg, err := VerifyCreatorJWT(pub, compatCreatorJWT)
	require.NoError(t, err)
	assert.Equal(t, compatVaultId, msg.VaultId)
	assert.Equal(t, compatTokenId, msg.CreatorTokenId)
	assert.Equal(t, "newIdentityId", msg.TokenId)
}

// The stored JWT carries a 5 minute expiry, so its signature is checked
// directly instead of through VerifyJWT.
func TestCompatStoredJWTSignature(t *testing.T) {
	_, pub := compatKeys(t)
	msg, payload, err := DecodeJWT(compatJWT)
	require.NoError(t, err)
	assert.Equal(t, compatVaultId, msg.VaultId)
	assert.Equal(t, compatTokenId, msg.TokenId)

	ok, err := Verify(pub, payload, strings.Split(compatJWT, ".")[2])
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestCompatJWTHeaderBytes(t *testing.T) {
	assert.Equal(t, compatJWTHeader, strings.Split(compatJWT, ".")[0])
	assert.Equal(t, compatJWTHeader, strings.Split(compatCreatorJWT, ".")[0])
}

func TestCompatIdentityId(t *testing.T) {
	_, pub := compatKeys(t)
	id, err := GetIdFromPublicKey(pub, compatVaultId)
	require.NoError(t, err)
	assert.Equal(t, compatTokenId, id)
}

// encryptLegacyShared reproduces what pre-ecdh clients produced: the shared
// secret was a big.Int byte slice, so leading zero bytes were dropped before
// the KDF. It brute forces an ephemeral key whose shared secret starts with a
// zero byte, which is the only case where the two derivations differ.
func encryptLegacyShared(t *testing.T, pub *ecdsa.PublicKey, message string) string {
	t.Helper()

	recipient, err := pub.ECDH()
	require.NoError(t, err)
	curve := recipient.Curve()

	for i := 0; i < 50000; i++ {
		eph, err := curve.GenerateKey(rand.Reader)
		require.NoError(t, err)
		shared, err := eph.ECDH(recipient)
		require.NoError(t, err)
		if shared[0] != 0 {
			continue
		}

		trimmed := shared
		for len(trimmed) > 0 && trimmed[0] == 0 {
			trimmed = trimmed[1:]
		}

		hashFunc := sha512.New()
		K := kdf(hashFunc, trimmed, nil)
		ke, km := K[:32], K[32:]

		c := encryptSymmetric(rand.Reader, []byte(message), ke)
		tag := sumTag(c, nil, to32ByteArray(km))

		out := append([]byte{}, eph.PublicKey().Bytes()...)
		out = append(out, c...)
		out = append(out, tag[:]...)
		return b64Std(out)
	}

	t.Skip("no ephemeral key with a leading zero shared secret found")
	return ""
}

func TestCompatDecryptLegacySharedSecret(t *testing.T) {
	priv, pub := compatKeys(t)
	const message = "legacy client payload"

	cipher := encryptLegacyShared(t, pub, message)
	got, err := Decrypt(priv, cipher)
	require.NoError(t, err)
	assert.Equal(t, message, string(got))
}

func TestDecryptRejectsMalformedInput(t *testing.T) {
	priv, pub := compatKeys(t)

	valid, err := Encrypt(pub, "Test123")
	require.NoError(t, err)
	raw, err := b64Decode(string(valid))
	require.NoError(t, err)

	cases := map[string]string{
		"empty":            "",
		"no valid base64":  "!!!not base64!!!",
		"only point":       b64Std(raw[:133]),
		"short ciphertext": b64Std(raw[:133+8]),
		"truncated tag":    b64Std(raw[:len(raw)-4]),
		"bad point prefix": b64Std(append([]byte{0x01}, raw[1:]...)),
	}

	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			assert.NotPanics(t, func() {
				_, err := Decrypt(priv, in)
				assert.Error(t, err)
			})
		})
	}
}
