package utils

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	b64 "encoding/base64"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A token must only be accepted when its signature was made by the key it is
// verified against. Verify reports a wrong-but-well-formed signature as
// (false, nil), so discarding that bool accepts forgeries.

func TestVerifyJWTRejectsTokenSignedByAnotherKey(t *testing.T) {
	attacker, _, err := GenerateNewKeyPair()
	require.NoError(t, err)
	_, victimPub := compatKeys(t)

	jwt, err := SignJWT(attacker, compatVaultId)
	require.NoError(t, err)

	msg, err := VerifyJWT(victimPub, jwt)
	assert.Error(t, err, "token signed by a foreign key must not verify")
	assert.Nil(t, msg)
}

func TestVerifyCreatorJWTRejectsTokenSignedByAnotherKey(t *testing.T) {
	attacker, _, err := GenerateNewKeyPair()
	require.NoError(t, err)
	_, victimPub := compatKeys(t)

	jwt, err := SignCreatorJWT(attacker, "newIdentityId", compatVaultId)
	require.NoError(t, err)

	msg, err := VerifyCreatorJWT(victimPub, jwt)
	assert.Error(t, err, "creator token signed by a foreign key must not verify")
	assert.Nil(t, msg)
}

// forgeToken builds a token for arbitrary claims with a signature that is
// well formed base64 but belongs to nobody.
func forgeToken(t *testing.T, claims any, signature string) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	require.NoError(t, err)
	return fmt.Sprintf("%s.%s.%s", compatJWTHeader, b64.StdEncoding.EncodeToString(payload), signature)
}

func TestVerifyJWTRejectsUnsignedToken(t *testing.T) {
	_, victimPub := compatKeys(t)

	// everything here is public knowledge: the vault id and the token id,
	// which is derived from the identity public key
	tokenID, err := GetIdFromPublicKey(victimPub, compatVaultId)
	require.NoError(t, err)
	require.Equal(t, compatTokenId, tokenID)

	signatures := []string{
		"AA==-AA==",
		"-",
		b64.StdEncoding.EncodeToString([]byte("not a signature")) + "-" + b64.StdEncoding.EncodeToString([]byte("either")),
	}

	for _, sig := range signatures {
		t.Run(sig, func(t *testing.T) {
			jwt := forgeToken(t, Message{
				Expired:  time.Now().Add(time.Hour),
				IssuedAt: time.Now(),
				VaultId:  compatVaultId,
				TokenId:  tokenID,
			}, sig)

			msg, err := VerifyJWT(victimPub, jwt)
			assert.Error(t, err, "forged token must not verify")
			assert.Nil(t, msg)
		})
	}
}
