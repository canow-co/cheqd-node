package helpers

import (
	"github.com/canow-co/cheqd-node/app/params"
	"github.com/cosmos/cosmos-sdk/codec"
)

var Codec codec.Codec

func init() {
	Codec = params.MakeEncodingConfig().Codec
}
