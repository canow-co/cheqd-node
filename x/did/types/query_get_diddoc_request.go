package types

import (
	"github.com/canow-co/cheqd-node/x/did/utils"
)

func (query *QueryDidDocRequest) Normalize() {
	query.Id = utils.NormalizeDID(query.Id)
}
