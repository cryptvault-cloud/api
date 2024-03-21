package api

import "context"

var _ ProtectedVaultHandler = (*ProtectedApi)(nil)

type ProtectedVaultHandler interface {
	GetVault() (*getVaultGetVault, error)
	UpdateVault(name string) (*updateVaultUpdateVaultUpdateVaultPayloadAffectedVault, error)
	DeleteVault(id string) error
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

func (a *ProtectedApi) DeleteVault(id string) error {
	_, err := deleteVault(context.Background(), a.client, id)
	return err
}
