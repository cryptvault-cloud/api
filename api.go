package api

import (
	"crypto/ecdsa"
	"net/http"

	"github.com/Khan/genqlient/graphql"
	"github.com/cryptvault-cloud/helper"
)

var _ ApiHandler = (*Api)(nil)

type ApiHandler interface {
	VaultHandler
	GetProtectedApi(authKey *ecdsa.PrivateKey, vaultId string) ProtectedApiHandler
	GetNewIdentityKeyPair() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error)
}

type Api struct {
	endpoint   string
	client     graphql.Client
	httpClient *http.Client
}

func NewApi(endpoint string, httpClient *http.Client) ApiHandler {
	return &Api{
		endpoint:   endpoint,
		httpClient: httpClient,
		client:     graphql.NewClient(endpoint, httpClient),
	}
}

func (a *Api) GetProtectedApi(authKey *ecdsa.PrivateKey, vaultId string) ProtectedApiHandler {
	h := http.Client{
		Transport: &authedTransport{wrapped: http.DefaultTransport, key: authKey, vaultId: vaultId},
	}

	return &ProtectedApi{
		vaultId:  vaultId,
		authKey:  authKey,
		api:      a,
		endpoint: a.endpoint,
		client:   graphql.NewClient(a.endpoint, &h),
	}
}

func (a *Api) GetNewIdentityKeyPair() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	return helper.GenerateNewKeyPair()
}
