package resource

import (
	"fmt"

	didkeeper "github.com/canow-co/cheqd-node/x/did/keeper"

	"github.com/canow-co/cheqd-node/x/resource/keeper"
	"github.com/canow-co/cheqd-node/x/resource/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

func NewHandler(k keeper.Keeper, cheqdKeeper didkeeper.Keeper) sdk.Handler {
	msgServer := keeper.NewMsgServer(k, cheqdKeeper)

	return func(ctx sdk.Context, msg sdk.Msg) (*sdk.Result, error) {
		ctx = ctx.WithEventManager(sdk.NewEventManager())

		switch msg := msg.(type) {
		case *types.MsgCreateResource:
			res, err := msgServer.CreateResource(sdk.WrapSDKContext(ctx), msg)
			return sdk.WrapServiceResult(ctx, res, err)

		default:
			errMsg := fmt.Sprintf("unrecognized %s message type: %T", types.ModuleName, msg)
			return nil, sdkerrors.Wrap(sdkerrors.ErrUnknownRequest, errMsg)
		}
	}
}
