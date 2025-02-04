package setup

import (
	"crypto/ed25519"

	"github.com/canow-co/cheqd-node/x/did/types"
	"github.com/canow-co/cheqd-node/x/did/utils"
	"github.com/google/uuid"
)

func (s *TestSetup) CreateDid(payload *types.MsgCreateDidDocPayload, signInputs []SignInput) (*types.MsgCreateDidDocResponse, error) {
	signBytes := payload.GetSignBytes()
	signatures := make([]*types.SignInfo, 0, len(signInputs))

	for _, input := range signInputs {
		signature := ed25519.Sign(input.Key, signBytes)

		signatures = append(signatures, &types.SignInfo{
			VerificationMethodId: input.VerificationMethodID,
			Signature:            signature,
		})
	}

	msg := &types.MsgCreateDidDoc{
		Payload:    payload,
		Signatures: signatures,
	}

	return s.MsgServer.CreateDidDoc(s.StdCtx, msg)
}

func (s *TestSetup) BuildDidDocWithCustomDID(did string) DidDocInfo {
	_, _, collectionID := utils.MustSplitDID(did)

	keyPair := GenerateKeyPair()
	keyID := did + "#key-1"

	msg := &types.MsgCreateDidDocPayload{
		Id: did,
		VerificationMethod: []*types.VerificationMethod{
			{
				Id:                     keyID,
				VerificationMethodType: types.Ed25519VerificationKey2020Type,
				Controller:             did,
				VerificationMaterial:   GenerateEd25519VerificationKey2020VerificationMaterial(keyPair.Public),
			},
		},
		Authentication: []*types.VerificationRelationship{
			{
				VerificationMethodId: keyID,
			},
		},
		VersionId: uuid.NewString(),
	}

	signInput := SignInput{
		VerificationMethodID: keyID,
		Key:                  keyPair.Private,
	}

	return DidDocInfo{
		Did:          did,
		CollectionID: collectionID,
		KeyPair:      keyPair,
		KeyID:        keyID,
		Msg:          msg,
		SignInput:    signInput,
	}
}

func (s *TestSetup) BuildDidDocWithCustomID(uuid string) DidDocInfo {
	did := "did:canow:" + DidNamespace + ":" + uuid
	return s.BuildDidDocWithCustomDID(did)
}

func (s *TestSetup) BuildSimpleDidDoc() DidDocInfo {
	did := GenerateDID(Base58_16bytes)
	return s.BuildDidDocWithCustomDID(did)
}

func (s *TestSetup) CreateCustomDidDoc(info DidDocInfo) CreatedDidDocInfo {
	created, err := s.CreateDid(info.Msg, []SignInput{info.SignInput})
	if err != nil {
		panic(err)
	}

	return CreatedDidDocInfo{
		DidDocInfo: info,
		VersionID:  created.Value.Metadata.VersionId,
	}
}

func (s *TestSetup) CreateSimpleDid() CreatedDidDocInfo {
	did := s.BuildSimpleDidDoc()
	return s.CreateCustomDidDoc(did)
}

func (s *TestSetup) CreateDidDocWithExternalDocAndMethodsController(controller string, controllerSignInput SignInput) CreatedDidDocInfo {
	did := s.BuildSimpleDidDoc()

	did.Msg.Controller = []string{controller}
	for _, vm := range did.Msg.VerificationMethod {
		vm.Controller = controller
	}
	setControllerInEmbeddedVerificationMethods(did.Msg.Authentication, controller)
	setControllerInEmbeddedVerificationMethods(did.Msg.AssertionMethod, controller)
	setControllerInEmbeddedVerificationMethods(did.Msg.CapabilityInvocation, controller)
	setControllerInEmbeddedVerificationMethods(did.Msg.CapabilityDelegation, controller)
	setControllerInEmbeddedVerificationMethods(did.Msg.KeyAgreement, controller)

	created, err := s.CreateDid(did.Msg, []SignInput{controllerSignInput})
	if err != nil {
		panic(err)
	}

	return CreatedDidDocInfo{
		DidDocInfo: did,
		VersionID:  created.Value.Metadata.VersionId,
	}
}

func (s *TestSetup) CreateDidDocWithExternalDocControllers(controllers []string, controllersSignInputs []SignInput) CreatedDidDocInfo {
	did := s.BuildSimpleDidDoc()
	did.Msg.Controller = controllers

	created, err := s.CreateDid(did.Msg, append(controllersSignInputs, did.SignInput))
	if err != nil {
		panic(err)
	}

	return CreatedDidDocInfo{
		DidDocInfo: did,
		VersionID:  created.Value.Metadata.VersionId,
	}
}

func setControllerInEmbeddedVerificationMethods(verificationRelationships []*types.VerificationRelationship, controller string) {
	for _, vr := range verificationRelationships {
		if vr.VerificationMethod != nil {
			vr.VerificationMethod.Controller = controller
		}
	}
}
