package api

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cryptvault-cloud/helper"
)

var _ ValueHandler = (*ProtectedApi)(nil)

type ValueHandler interface {
	DeleteIdentityValue(id *string) (int, error)
	AddValue(key, value string, valueType ValueType) (string, error)
	DeleteValue(id string) error
	GetValueById(id string) (*getValueGetValue, error)
	GetIdentityValueById(id string) (*IdentityValue, error)
	GetIdentityValueByName(name string) (*IdentityValue, error)
	GetValueByName(name string) (*getValueByNameQueryValueValueQueryResultDataValue, error)
	UpdateValue(id, key, value string, valueType ValueType) (string, error)
	SyncValues(identityId string) error
	SyncValue(id string) error
	AddIdentityValue(input IdentityValueInput) (string, error)
	GetDecryptedPassframe(value []EncryptenValue) (string, error)
	GetAllRelatedValues(identityId string) ([]*allRelatedValuesAllRelatedValuesValue, error)
	GetAllRelatedValuesWithIdentityValues(identityId string) ([]*allRelatedValuesWithIdentityValuesAllRelatedValuesValue, error)
	GetAllRelatedValuesWithIdentityValuesAndPassframe(identityId string) ([]*allRelatedValuesWithIdentityValuesAndSecretAllRelatedValuesValue, error)
}

func (a *ProtectedApi) DeleteIdentityValue(id *string) (int, error) {
	resp, err := removeIdentityValue(context.Background(), a.client, id)
	if err != nil {
		return 0, err
	}
	return resp.DeleteIdentityValue.Count, nil
}

func (a *ProtectedApi) AddValue(key, value string, valueType ValueType) (string, error) {
	if strings.Contains(key, "*") || strings.Contains(key, ">") {
		return "", errors.New("key can not have wildcard symbols * or >")
	}
	resp, err := getRelatedIdenties(context.Background(), a.client, key)
	if err != nil {
		return "", err
	}

	pemPubkey, err := helper.NewBase64PublicPem(&a.authKey.PublicKey)
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

func (a *ProtectedApi) GetIdentityValueById(id string) (*IdentityValue, error) {
	resp, err := getValue(context.Background(), a.client, id)
	if err != nil {
		return nil, err
	}
	values := make([]EncryptenValue, 0)
	for _, v := range resp.GetValue.Value {
		values = append(values, v)
	}
	password, err := a.GetDecryptedPassframe(values)
	if err != nil {
		return nil, err
	}
	return &IdentityValue{
		Name:      resp.GetValue.Name,
		Type:      resp.GetValue.Type,
		Id:        resp.GetValue.Id,
		CreatedAt: resp.GetValue.CreatedAt,
		UpdatedAt: resp.GetValue.UpdatedAt,
		Value:     password,
	}, nil
}

type IdentityValue struct {
	Name      string     `json:"name"`
	Type      ValueType  `json:"type"`
	Id        string     `json:"id"`
	CreatedAt *time.Time `json:"createdAt"`
	UpdatedAt *time.Time `json:"updatedAt"`
	Value     string     `json:"value"`
}

func (a *ProtectedApi) GetIdentityValueByName(name string) (*IdentityValue, error) {
	valueResp, err := a.GetValueByName(name)
	if err != nil {
		return nil, err
	}

	values := make([]EncryptenValue, 0)
	for _, v := range valueResp.GetValue() {
		values = append(values, v)
	}
	password, err := a.GetDecryptedPassframe(values)
	if err != nil {
		return nil, err
	}
	return &IdentityValue{
		Name:      valueResp.Name,
		Type:      valueResp.Type,
		Id:        valueResp.Id,
		CreatedAt: valueResp.CreatedAt,
		UpdatedAt: valueResp.UpdatedAt,
		Value:     password,
	}, nil
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
	if strings.Contains(key, "*") || strings.Contains(key, ">") {
		return "", errors.New("explizit key can not have wildcard symbols * or >")
	}
	resp, err := a.GetValueById(id)
	if err != nil {
		return "", err
	}

	pemPubkey, err := helper.NewBase64PublicPem(&a.authKey.PublicKey)
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

// SyncValues sync all values by check identity and get all related identities wich also has access to this value.
func (a *ProtectedApi) SyncValues(identityId string) error {
	values, err := a.GetAllRelatedValues(identityId)
	if err != nil {
		return err
	}
	for _, v := range values {
		err := a.SyncValue(v.Id)
		if err != nil {
			return err
		}
	}
	return nil
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
	ownerPubKey, err := helper.NewBase64PublicPem(&a.authKey.PublicKey)
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
	if err := a.checkIdentitiesHaveRelatedSignatureChain(resp.GetIdentitiesWithValueAccess()); err != nil {
		return err
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

	pemKey, err := helper.NewBase64PublicPem(&a.authKey.PublicKey)
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

func (a *ProtectedApi) GetAllRelatedValues(identityId string) ([]*allRelatedValuesAllRelatedValuesValue, error) {
	resp, err := allRelatedValues(context.Background(), a.client, identityId)
	if err != nil {
		return nil, err
	}
	return resp.AllRelatedValues, nil
}

func (a *ProtectedApi) GetAllRelatedValuesWithIdentityValues(identityId string) ([]*allRelatedValuesWithIdentityValuesAllRelatedValuesValue, error) {
	resp, err := allRelatedValuesWithIdentityValues(context.Background(), a.client, identityId)
	if err != nil {
		return nil, err
	}
	return resp.AllRelatedValues, nil
}

func (a *ProtectedApi) GetAllRelatedValuesWithIdentityValuesAndPassframe(identityId string) ([]*allRelatedValuesWithIdentityValuesAndSecretAllRelatedValuesValue, error) {
	resp, err := allRelatedValuesWithIdentityValuesAndSecret(context.Background(), a.client, identityId)
	if err != nil {
		return nil, err
	}
	return resp.AllRelatedValues, nil
}

func (a *ProtectedApi) checkIdentityHaveRelatedSignatureChain(identity *getRelatedIdentiesIdentitiesWithValueAccessIdentity, other []*getRelatedIdentiesIdentitiesWithValueAccessIdentity) error {

	if identity.IsOperator {
		return nil
	}

	creator, _, err := helper.DecodeCreatorJWT(identity.GetCreatorVerification())
	if err != nil {
		return err
	}

	creatorIdentity := helper.Filter(other, func(griiwvai *getRelatedIdentiesIdentitiesWithValueAccessIdentity) bool {
		return griiwvai.Id == creator.CreatorTokenId
	})
	if len(creatorIdentity) != 1 {
		return fmt.Errorf("Something strange creator identity was not found, or more than one was found. this could not be possible, cause of permission chain")
	}
	creatorPubKey, err := creatorIdentity[0].GetPublicKey().GetPublicKey()
	if err != nil {
		return err
	}
	_, err = helper.VerifyCreatorJWT(creatorPubKey, identity.CreatorVerification)
	if err != nil {
		return err
	}
	return a.checkIdentityHaveRelatedSignatureChain(creatorIdentity[0], other)
}

func (a *ProtectedApi) checkIdentitiesHaveRelatedSignatureChain(identies []*getRelatedIdentiesIdentitiesWithValueAccessIdentity) error {
	for _, identity := range identies {
		if err := a.checkIdentityHaveRelatedSignatureChain(identity, identies); err != nil {
			return err
		}
	}
	return nil
}
