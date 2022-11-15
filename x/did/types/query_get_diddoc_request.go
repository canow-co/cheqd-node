package types

import (
	"github.com/canow-co/cheqd-node/x/did/utils"
)

func (query *QueryGetDidDocRequest) Normalize() {
	query.Id = utils.NormalizeDID(query.Id)
}
