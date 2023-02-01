package setup

import "github.com/canow-co/cheqd-node/x/resource/types"

func (s *TestSetup) CollectionResources(collectionID string) (*types.QueryCollectionResourcesResponse, error) {
	req := &types.QueryCollectionResourcesRequest{
		CollectionId: collectionID,
	}

	return s.ResourceQueryServer.CollectionResources(s.StdCtx, req)
}
