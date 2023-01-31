package setup

import "github.com/canow-co/cheqd-node/x/did/types"

func (s *TestSetup) QueryDidDoc(did string) (*types.QueryDidDocResponse, error) {
	req := &types.QueryDidDocRequest{
		Id: did,
	}

	return s.QueryServer.DidDoc(s.StdCtx, req)
}
