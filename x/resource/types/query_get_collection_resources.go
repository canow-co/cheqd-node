package types

import (
	"github.com/canow-co/cheqd-node/x/did/utils"
)

func (query *QueryCollectionResourcesRequest) Normalize() {
	query.CollectionId = utils.NormalizeID(query.CollectionId)
}
