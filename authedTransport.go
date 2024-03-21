package api

import (
	"crypto/ecdsa"
	"fmt"
	"net/http"

	"github.com/cryptvault-cloud/helper"
)

type authedTransport struct {
	wrapped http.RoundTripper
	key     *ecdsa.PrivateKey
	vaultId string
}

func (t *authedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	jwt, err := helper.SignJWT(t.key, t.vaultId)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", jwt))
	return t.wrapped.RoundTrip(req)
}
