package keeper

import (
	"github.com/canow-co/cheqd-node/x/did/types"
	. "github.com/canow-co/cheqd-node/x/did/utils"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// GetDidNamespace get did namespace
func (k Keeper) GetDidNamespace(ctx *sdk.Context) string {
	store := ctx.KVStore(k.storeKey)

	key := StrBytes(types.DidNamespaceKey)
	value := store.Get(key)

	return string(value)
}

// SetDidNamespace set did namespace
func (k Keeper) SetDidNamespace(ctx *sdk.Context, namespace string) {
	store := ctx.KVStore(k.storeKey)

	key := StrBytes(types.DidNamespaceKey)
	value := []byte(namespace)

	store.Set(key, value)
}