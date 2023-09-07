package client

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"net/http"
	"strings"

	"github.com/Khan/genqlient/graphql"
	"github.com/fasibio/vaulthelper"
	"github.com/fasibio/vaulthelper/helper"
)

type Api struct {
	endpoint   string
	client     graphql.Client
	httpClient *http.Client
}

func NewApi(endpoint string, httpClient *http.Client) Api {
	return Api{
		endpoint:   endpoint,
		httpClient: httpClient,
		client:     graphql.NewClient(endpoint, httpClient),
	}
}

func (a *Api) NewVault(name, token string) (private *ecdsa.PrivateKey, public *ecdsa.PublicKey, vaultID string, err error) {
	private, public, err = a.GetNewIdentityKeyPair()
	if err != nil {
		return
	}
	pubbase64, err := vaulthelper.NewBase64PublicPem(public)
	if err != nil {
		return
	}

	resp, err := createNewVault(context.Background(), a.client, name, pubbase64, token)
	vaultID = resp.CreateVault
	return
}

func (a *ProtectedApi) GetVault() (*getVaultGetVault, error) {
	resp, err := getVault(context.Background(), a.client, a.vaultId)
	if err != nil {
		return nil, err
	}
	return resp.GetVault, nil
}

func (a *ProtectedApi) UpdateVault(name string) (*updateVaultUpdateVaultUpdateVaultPayloadAffectedVault, error) {
	resp, err := updateVault(context.Background(), a.client, name)
	if err != nil {
		return nil, err
	}
	return resp.UpdateVault.Affected[0], nil
}

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
	req.Header.Set("Authorization", "Bearer "+jwt)
	return t.wrapped.RoundTrip(req)
}

func (a *Api) GetProtectedApi(authKey *ecdsa.PrivateKey, vaultId string) *ProtectedApi {
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

type ProtectedApi struct {
	vaultId  string
	authKey  *ecdsa.PrivateKey
	api      *Api
	endpoint string
	client   graphql.Client
}

type AddIdentityResponse struct {
	IdentityId string
	RightIds   []string
	PublicKey  *ecdsa.PublicKey
}

func (a *ProtectedApi) DeleteVault(id string) error {
	_, err := deleteVault(context.Background(), a.client, id)
	return err
}

func (a *ProtectedApi) AddIdentity(name string, publicKey *ecdsa.PublicKey, rights []*RightInput) (*AddIdentityResponse, error) {

	key, err := vaulthelper.NewBase64PublicPem(publicKey)
	if err != nil {
		return nil, err
	}
	resp, err := addIdentity(context.Background(), a.client, name, key)
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

func (a *Api) GetNewIdentityKeyPair() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	return helper.GenerateNewKeyPair()
}

type CreateIdentityResponse struct {
	*AddIdentityResponse
	PrivateKey *ecdsa.PrivateKey
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

func (a *ProtectedApi) DeleteRight(rightId, identityId string) (int, error) {
	resp, err := deleteRight(context.Background(), a.client, rightId, identityId)
	if err != nil {
		return -1, err
	}
	return resp.DeleteRight.Count, err
}

func (a *ProtectedApi) AddRights(rights []*RightInput, identityId string) ([]string, error) {

	for _, v := range rights {
		v.IdentityID = identityId
	}

	rightResp, err := addRight(context.Background(), a.client, rights)
	rightIds := make([]string, 0)
	if err != nil {
		return nil, err
	}
	for _, v := range rightResp.AddRight.Affected {
		rightIds = append(rightIds, v.Id)
	}
	return rightIds, nil
}

func (a *ProtectedApi) AddValue(key, value string, valueType ValueType) (string, error) {
	if strings.Contains(value, "*") || strings.Contains(value, ">") {
		return "", errors.New("value can not have wildcard symbols * or >")
	}
	resp, err := getRelatedIdenties(context.Background(), a.client, key)
	if err != nil {
		return "", err
	}

	pemPubkey, err := vaulthelper.NewBase64PublicPem(&a.authKey.PublicKey)
	if err != nil {
		return "", err
	}
	ownId, err := pemPubkey.GetIdentityId(a.vaultId)
	if err != nil {
		return "", err
	}

	hasOwnId := false
	for _, v := range resp.IdentitiesWithValueAccess {
		if v.Id == ownId {
			hasOwnId = true
		}
	}
	if !hasOwnId {
		return "", errors.New("sender Identity has not the rights to create value")
	}

	identityValues := make([]*IdentityValueInput, 0)

	respaddValue, err := addValue(context.Background(), a.client, key, valueType)
	if err != nil {
		return "", err
	}
	valueId := respaddValue.AddValue.Affected[0].Id
	var forLoopErr error = nil
	for _, v := range resp.IdentitiesWithValueAccess {
		encrpytValue, err := v.PublicKey.Encrypt(value)
		if err != nil {
			forLoopErr = err
		}
		identityValues = append(identityValues, &IdentityValueInput{
			Passframe:  encrpytValue,
			IdentityID: v.Id,
			ValueID:    valueId,
		})

	}

	if forLoopErr != nil {
		err := a.DeleteValue(valueId)
		return "", errors.Join(err, forLoopErr)
	}

	_, err = addIdentityValue(context.Background(), a.client, identityValues)
	if err != nil {
		err2 := a.DeleteValue(valueId)
		return "", errors.Join(err, err2)
	}
	return valueId, err

}

func (a *ProtectedApi) DeleteValue(id string) error {
	_, err := deleteValue(context.Background(), a.client, id)
	return err
}

func (a *ProtectedApi) GetValueById(id string) (*getValueGetValue, error) {
	resp, err := getValue(context.Background(), a.client, id)
	return resp.GetValue, err
}

func (a *ProtectedApi) GetValueByName(name string) (*getValueByNameQueryValueValueQueryResultDataValue, error) {
	resp, err := getValueByName(context.Background(), a.client, name)
	if err != nil {
		return nil, err
	}
	if len(resp.QueryValue.Data) == 0 {
		return nil, errors.New("value not Found")
	}
	return resp.QueryValue.Data[0], err
}

func (a *ProtectedApi) UpdateValue(id, key, value string, valueType ValueType) (string, error) {
	if strings.Contains(value, "*") || strings.Contains(value, ">") {
		return "", errors.New("value can not have wildcard symbols * or >")
	}
	resp, err := a.GetValueById(id)
	if err != nil {
		return "", err
	}

	pemPubkey, err := vaulthelper.NewBase64PublicPem(&a.authKey.PublicKey)
	if err != nil {
		return "", err
	}
	ownId, err := pemPubkey.GetIdentityId(a.vaultId)
	if err != nil {
		return "", err
	}

	hasOwnId := false
	for _, v := range resp.Value {
		if v.IdentityID == ownId {
			hasOwnId = true
		}
	}
	if !hasOwnId {
		return "", errors.New("sender Identity has not the rights to update value")
	}

	respaddValue, err := updateValue(context.Background(), a.client, id, key, valueType)
	if err != nil {
		return "", err
	}
	valueId := respaddValue.UpdateValue.Affected[0].Id
	var forLoopErr error = nil
	for _, v := range resp.Value {
		encrpytValue, err := v.Identity.PublicKey.Encrypt(value)
		if err != nil {
			forLoopErr = errors.Join(err, forLoopErr)
			continue
		}
		identityId, err := v.Identity.PublicKey.GetIdentityId(a.vaultId)
		if err != nil {
			forLoopErr = errors.Join(err, forLoopErr)
			continue
		}
		_, err = updateIdentityValue(context.Background(), a.client, v.Id, &IdentityValuePatch{
			Passframe:  &encrpytValue,
			IdentityID: &identityId,
			ValueID:    &valueId,
		})
		if err != nil {
			forLoopErr = errors.Join(err, forLoopErr)
		}

	}

	if forLoopErr != nil {
		return "", forLoopErr
	}

	return valueId, err
}

func (a *ProtectedApi) SyncValue(id string) error {
	value, err := a.GetValueById(id)
	if err != nil {
		return err
	}
	resp, err := getRelatedIdenties(context.Background(), a.client, value.Name)
	if err != nil {
		return err
	}
	ownerPubKey, err := vaulthelper.NewBase64PublicPem(&a.authKey.PublicKey)
	if err != nil {
		return err
	}

	ownerId, err := ownerPubKey.GetIdentityId(a.vaultId)
	if err != nil {
		return err
	}

	hasOwnId := false

	for _, v := range resp.IdentitiesWithValueAccess {
		if v.Id == ownerId {
			hasOwnId = true
		}
	}
	if !hasOwnId {
		return errors.New("sender Identity has not the rights to update value")
	}

	values := make([]EncryptenValue, 0)
	for _, v := range value.GetValue() {
		values = append(values, v)
	}
	decryptedPassframe, err := a.getDecryptedPassframe(ownerId, values)
	if err != nil {
		return err
	}
	for _, identity := range resp.IdentitiesWithValueAccess {
		hasValueForIdentityFound := helper.Includes[*getValueGetValueValueIdentityValue](value.Value, func(gvgvv *getValueGetValueValueIdentityValue) bool {
			return gvgvv.IdentityID == identity.Id
		})
		if !hasValueForIdentityFound {
			encyptedPassframe, err := identity.PublicKey.Encrypt(decryptedPassframe)

			if err != nil {
				return err
			}
			_, err = a.AddIdentityValue(IdentityValueInput{
				ValueID:    id,
				IdentityID: identity.Id,
				Passframe:  encyptedPassframe,
			})
			if err != nil {
				return err
			}
		}
	}

	for _, v := range value.Value {
		res := helper.Filter[*getRelatedIdentiesIdentitiesWithValueAccessIdentity](resp.IdentitiesWithValueAccess, func(griiwvai *getRelatedIdentiesIdentitiesWithValueAccessIdentity) bool {
			return v.IdentityID == griiwvai.Id
		})
		if len(res) == 0 {
			_, err := deleteIdentityValue(context.Background(), a.client, v.Id)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (a *ProtectedApi) AddIdentityValue(input IdentityValueInput) (string, error) {
	resp, err := addIdentityValue(context.Background(), a.client, []*IdentityValueInput{{
		ValueID:    input.ValueID,
		IdentityID: input.IdentityID,
		Passframe:  input.Passframe,
	}})
	if err != nil {
		return "", err
	}
	return resp.AddIdentityValue.Affected[0].Id, err
}

type EncryptenValue interface {
	GetPassframe() string
	GetIdentityID() string
}

func (a *ProtectedApi) GetDecryptedPassframe(value []EncryptenValue) (string, error) {

	pemKey, err := vaulthelper.NewBase64PublicPem(&a.authKey.PublicKey)
	if err != nil {
		return "", err
	}
	identityId, err := pemKey.GetIdentityId(a.vaultId)
	if err != nil {
		return "", err
	}
	return a.getDecryptedPassframe(identityId, value)
}

func (a *ProtectedApi) getDecryptedPassframe(identityId string, value []EncryptenValue) (string, error) {
	for _, v := range value {
		if v.GetIdentityID() == identityId {
			key, err := helper.Decrypt(a.authKey, v.GetPassframe())
			return string(key), err
		}
	}
	return "", errors.New("getEncryptedPassframe: given Identity not found at saved values ")
}

func (a *ProtectedApi) GetAllRelatedValues(identityId string) ([]string, error) {
	resp, err := allRelatedValues(context.Background(), a.client, identityId)
	if err != nil {
		return nil, err
	}
	return helper.Map[*allRelatedValuesAllRelatedValuesValue, string](resp.AllRelatedValues, func(v *allRelatedValuesAllRelatedValuesValue) string {
		return v.Id
	}), nil
}
