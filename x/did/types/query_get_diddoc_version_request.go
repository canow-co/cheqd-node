package types

import (
	"github.com/canow-co/cheqd-node/x/did/utils"
)

func (query *QueryGetDidDocVersionRequest) Normalize() {
	query.Id = utils.NormalizeDID(query.Id)
	query.Version = utils.NormalizeUUID(query.Version)
}