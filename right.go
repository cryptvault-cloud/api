package api

import "context"

var _ RightHandler = (*ProtectedApi)(nil)

type RightHandler interface {
	DeleteRight(rightId, identityId string) (int, error)
	AddRights(rights []*RightInput, identityId string) ([]string, error)
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
