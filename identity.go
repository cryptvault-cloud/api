package api

import (
	"context"
	"crypto/ecdsa"
	"errors"

	"github.com/cryptvault-cloud/helper"
)

var _ IdentityHandler = (*ProtectedApi)(nil)

type IdentityHandler interface {
	AddIdentity(name string, publicKey *ecdsa.PublicKey, rights []*RightInput) (*AddIdentityResponse, error)
	UpdateIdentity(id string, name string, rights []*RightInput) (*AddIdentityResponse, error)
	GetIdentity(id string) (*getIdentityGetIdentity, error)
	CreateIdentity(name string, rights []*RightInput) (*CreateIdentityResponse, error)
	DeleteIdentity(tokenId string) error
	GetAllIdentities() (*allIdentitiesResponse, error)
}

type AddIdentityResponse struct {
	IdentityId string
	RightIds   []string
	PublicKey  *ecdsa.PublicKey
}

type CreateIdentityResponse struct {
	*AddIdentityResponse
	PrivateKey *ecdsa.PrivateKey
}

func (a *ProtectedApi) AddIdentity(name string, publicKey *ecdsa.PublicKey, rights []*RightInput) (*AddIdentityResponse, error) {

	key, err := helper.NewBase64PublicPem(publicKey)
	if err != nil {
		return nil, err
	}

	newIdentityId, err := key.GetIdentityId(a.vaultId)
	if err != nil {
		return nil, err
	}

	creatorSign, err := helper.SignCreatorJWT(a.authKey, newIdentityId, a.vaultId)
	if err != nil {
		return nil, err
	}
	resp, err := addIdentity(context.Background(), a.client, name, key, creatorSign)
	if err != nil {
		return nil, err
	}
	identityId := resp.AddIdentity.Affected[0].Id

	rightIds, err := a.AddRights(rights, identityId)

	if err != nil {
		// ROLLBACK
		err2 := a.DeleteIdentity(identityId)
		if err2 != nil {
			e := errors.New("failed to rollback identity")
			return nil, errors.Join(e, err2, err)
		}
		return nil, err
	}

	return &AddIdentityResponse{IdentityId: identityId, RightIds: rightIds, PublicKey: publicKey}, nil
}

func (a *ProtectedApi) UpdateIdentity(id string, name string, rights []*RightInput) (*AddIdentityResponse, error) {
	uiresp, err := updateIdentity(context.Background(), a.client, id, name)
	if err != nil {
		return nil, err
	}
	_, err = deleteAllRightsFromIdentity(context.Background(), a.client, id)
	if err != nil {
		return nil, err
	}

	rightIds, err := a.AddRights(rights, id)
	if err != nil {
		return nil, err
	}
	pubKey, err := uiresp.UpdateIdentity.Affected[0].PublicKey.GetPublicKey()
	if err != nil {
		return nil, err
	}
	return &AddIdentityResponse{IdentityId: id, RightIds: rightIds, PublicKey: pubKey}, nil
}

func (a *ProtectedApi) GetIdentity(id string) (*getIdentityGetIdentity, error) {
	resp, err := getIdentity(context.Background(), a.client, id)
	return resp.GetIdentity, err
}

func (a *ProtectedApi) CreateIdentity(name string, rights []*RightInput) (*CreateIdentityResponse, error) {
	priv, pub, err := a.api.GetNewIdentityKeyPair()
	if err != nil {
		return nil, err
	}
	resp, err := a.AddIdentity(name, pub, rights)
	if err != nil {
		return nil, err
	}

	return &CreateIdentityResponse{
		AddIdentityResponse: resp,
		PrivateKey:          priv,
	}, nil
}

func (a *ProtectedApi) DeleteIdentity(tokenId string) error {

	_, err := deleteIdentity(context.Background(), a.client, tokenId)
	if err != nil {
		return err
	}
	return nil
}

func (a *ProtectedApi) GetAllIdentities() (*allIdentitiesResponse, error) {
	return allIdentities(context.Background(), a.client)
}
