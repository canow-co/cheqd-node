package types

import (
	"github.com/canow-co/cheqd-node/x/did/utils"
)

func (query *QueryGetResourceRequest) Normalize() {
	query.CollectionId = utils.NormalizeId(query.CollectionId)
	query.Id = utils.NormalizeUUID(query.Id)
}