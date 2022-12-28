package types

import (
	"github.com/canow-co/cheqd-node/x/did/utils"
)

func (query *QueryGetCollectionResourcesRequest) Normalize() {
	query.CollectionId = utils.NormalizeId(query.CollectionId)
}
