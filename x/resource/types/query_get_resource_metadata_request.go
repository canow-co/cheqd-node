package types

import "github.com/canow-co/cheqd-node/x/did/utils"

func (query *QueryGetResourceMetadataRequest) Normalize() {
	query.CollectionId = utils.NormalizeId(query.CollectionId)
	query.Id = utils.NormalizeUUID(query.Id)
}
