package api

import (
	"context"
	"crypto/ecdsa"

	"github.com/cryptvault-cloud/helper"
)

var _ VaultHandler = (*Api)(nil)

type VaultHandler interface {
	NewVaultByPublicKey(name, token string, publicKey *ecdsa.PublicKey) (vaultID string, err error)
	NewVault(name, token string) (private *ecdsa.PrivateKey, public *ecdsa.PublicKey, vaultID string, err error)
}

func (a *Api) NewVaultByPublicKey(name, token string, publicKey *ecdsa.PublicKey) (vaultID string, err error) {

	pubbase64, err := helper.NewBase64PublicPem(publicKey)
	if err != nil {
		return
	}

	resp, err := createNewVault(context.Background(), a.client, name, pubbase64, token)
	vaultID = resp.CreateVault
	return
}

func (a *Api) NewVault(name, token string) (private *ecdsa.PrivateKey, public *ecdsa.PublicKey, vaultID string, err error) {
	private, public, err = a.GetNewIdentityKeyPair()
	if err != nil {
		return
	}
	pubbase64, err := helper.NewBase64PublicPem(public)
	if err != nil {
		return
	}

	resp, err := createNewVault(context.Background(), a.client, name, pubbase64, token)
	vaultID = resp.CreateVault
	return
}
