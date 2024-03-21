package api

import (
	"crypto/ecdsa"

	"github.com/Khan/genqlient/graphql"
)

var _ ProtectedApiHandler = (*ProtectedApi)(nil)

type ProtectedApi struct {
	vaultId  string
	authKey  *ecdsa.PrivateKey
	api      *Api
	endpoint string
	client   graphql.Client
}

type ProtectedApiHandler interface {
	ProtectedVaultHandler
	IdentityHandler
	ValueHandler
	RightHandler
}
