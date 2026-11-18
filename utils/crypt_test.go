package utils

import (
	"testing"

	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var b64PrivKeyOriginal = "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSGNBZ0VCQkVJQUIwWnpRVjdIbXUreHE5UVpad1RKd3ErcXZ6ZmVmOEtNZG1GeUlLSlJHdlZ6dmYxeUg4S0IKVEVGV1NNSUtOWmplendNc1hBOFZHUXl1ekdqMnJzMUdRcStnQndZRks0RUVBQ09oZ1lrRGdZWUFCQUVHMXRmRAptQ0E3b0VOYnNOMGhtcmw4V2prc1dGa1FJSkdXWFJnQytFWjliNUFGaDV5aGlGazFZTXJzeVZRVWVvL0VJakliCk9ObEtkNWxid0NxblJpTHRXQUZEVVZLSERQZUNwVkNHbHNCcVRVVnprNFF6YlNFeWN3amdHSzQ1S2k0ZGpPR0MKR3JRbmtMVXQra2hablVnWHdNOU51Z3pCSjRWUDdrV2lnVzhKZE5ldHZ3PT0KLS0tLS1FTkQgUFJJVkFURSBLRVktLS0tLQo="
var b64PubKeyOriginal = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHYk1CQUdCeXFHU000OUFnRUdCU3VCQkFBakE0R0dBQVFCQnRiWHc1Z2dPNkJEVzdEZElacTVmRm81TEZoWgpFQ0NSbGwwWUF2aEdmVytRQlllY29ZaFpOV0RLN01sVUZIcVB4Q0l5R3pqWlNuZVpXOEFxcDBZaTdWZ0JRMUZTCmh3ejNncVZRaHBiQWFrMUZjNU9FTTIwaE1uTUk0Qml1T1NvdUhZemhnaHEwSjVDMUxmcElXWjFJRjhEUFRib00Kd1NlRlQrNUZvb0Z2Q1hUWHJiOD0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg=="

func TestDeAndEncrypt(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	msg := "Test123"
	privateKey, publicKey, err := GenerateNewKeyPair()
	require.NoError(err)
	encryptMsg, err := Encrypt(publicKey, msg)
	require.NoError(err)
	decryptMsg, err := Decrypt(privateKey, string(encryptMsg))
	require.NoError(err)
	assert.Equal(string(decryptMsg), msg)
}

func TestBase64DeAndEncode(t *testing.T) {
	require := require.New(t)
	privateKey, err := GetPrivateKeyFromB64String(b64PrivKeyOriginal)
	require.NoError(err)
	b64PrivKey, err := GetB64FromPrivateKey(privateKey)
	require.NoError(err)
	snaps.MatchSnapshot(t, b64PrivKey)
	publicKey, err := GetPublicKeyFromB64String(b64PubKeyOriginal)
	require.NoError(err)
	b64PubKey, err := GetB64FromPublicKey(publicKey)
	require.NoError(err)
	snaps.MatchSnapshot(t, b64PubKey)
}

func TestSignAndVerify(t *testing.T) {
	t.Run("valid signature", func(t *testing.T) {
		require := require.New(t)
		assert := assert.New(t)

		privateKey, err := GetPrivateKeyFromB64String(b64PrivKeyOriginal)
		require.NoError(err)

		signature, err := Sign(privateKey, "Test123")
		require.NoError(err)
		publicKey, err := GetPublicKeyFromB64String(b64PubKeyOriginal)
		require.NoError(err)
		isValid, err := Verify(publicKey, "Test123", signature)
		require.NoError(err)
		assert.True(isValid)
	})
	t.Run("unvalid signature", func(t *testing.T) {
		require := require.New(t)
		assert := assert.New(t)

		privateKey, _, err := GenerateNewKeyPair()
		require.NoError(err)
		signature, err := Sign(privateKey, "Test123")
		require.NoError(err)
		publicKey, err := GetPublicKeyFromB64String(b64PubKeyOriginal)
		require.NoError(err)
		isValid, err := Verify(publicKey, "Test123", signature)
		require.NoError(err)
		assert.False(isValid)
	})
}

func TestGetIdFromPublicKey(t *testing.T) {
	require := require.New(t)
	publicKey, err := GetPublicKeyFromB64String(b64PubKeyOriginal)
	require.NoError(err)
	id, err := GetIdFromPublicKey(publicKey, "test_vault")
	require.NoError(err)
	snaps.MatchSnapshot(t, id)
}

func TestSignAndVerifyCreatorJWT(t *testing.T) {
	require := require.New(t)
	privateKey, err := GetPrivateKeyFromB64String(b64PrivKeyOriginal)
	require.NoError(err)
	signature, err := SignCreatorJWT(privateKey, "newIdentityId", "test_vault")
	require.NoError(err)
	publicKey, err := GetPublicKeyFromB64String(b64PubKeyOriginal)
	require.NoError(err)
	msg, err := VerifyCreatorJWT(publicKey, signature)
	require.NoError(err)
	snaps.MatchSnapshot(t, msg.CreatorTokenId)
	snaps.MatchSnapshot(t, msg.TokenId)
	snaps.MatchSnapshot(t, msg.VaultId)
}

func TestSignAndVerifyJWT(t *testing.T) {
	require := require.New(t)
	privateKey, err := GetPrivateKeyFromB64String(b64PrivKeyOriginal)
	require.NoError(err)
	publicKey, err := GetPublicKeyFromB64String(b64PubKeyOriginal)
	require.NoError(err)
	jwt, err := SignJWT(privateKey, "test_vault")
	require.NoError(err)
	msg, err := VerifyJWT(publicKey, jwt)
	require.NoError(err)
	snaps.MatchSnapshot(t, msg.VaultId)
	snaps.MatchSnapshot(t, msg.TokenId)
}
