package migrations

import (
	"fmt"

	resourcetypes "github.com/canow-co/cheqd-node/x/resource/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

func MigrateResourceDefaultAlternativeURL(sctx sdk.Context, mctx MigrationContext) error {
	sctx.Logger().Debug("MigrateResourceDefaultAlternativeUrl: Starting migration")

	namespace := mctx.didKeeperNew.GetDidNamespace(&sctx)

	return MigrateResourceSimple(sctx, mctx, func(resource *resourcetypes.ResourceWithMetadata) {
		alternativeURI := resourcetypes.AlternativeUri{
			Uri:         fmt.Sprintf("did:canow:%s:%s/resources/%s", namespace, resource.Metadata.CollectionId, resource.Metadata.Id),
			Description: "did-url",
		}
		resource.Metadata.AlsoKnownAs = append(resource.Metadata.AlsoKnownAs, &alternativeURI)
		sctx.Logger().Debug(fmt.Sprintf(
			"MigrateResourceDefaultAlternativeUrl: Id: %s CollectionId: %s AlternativeUri: %s",
			resource.Metadata.Id,
			resource.Metadata.CollectionId,
			string(mctx.codec.MustMarshalJSON(&alternativeURI))))
	})
}
