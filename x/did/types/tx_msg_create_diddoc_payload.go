package types

import (
	"github.com/canow-co/cheqd-node/x/did/utils"
	validation "github.com/go-ozzo/ozzo-validation/v4"
)

var _ IdentityMsg = &MsgCreateDidDocPayload{}

func (msg *MsgCreateDidDocPayload) GetSignBytes() []byte {
	bytes, err := msg.Marshal()
	if err != nil {
		panic(err)
	}

	return bytes
}

func (msg *MsgCreateDidDocPayload) ToDidDoc() DidDoc {
	return DidDoc{
		Context:              msg.Context,
		Id:                   msg.Id,
		Controller:           msg.Controller,
		VerificationMethod:   msg.VerificationMethod,
		Authentication:       msg.Authentication,
		AssertionMethod:      msg.AssertionMethod,
		CapabilityInvocation: msg.CapabilityInvocation,
		CapabilityDelegation: msg.CapabilityDelegation,
		KeyAgreement:         msg.KeyAgreement,
		AlsoKnownAs:          msg.AlsoKnownAs,
		Service:              msg.Service,
	}
}

// Validation

func (msg MsgCreateDidDocPayload) Validate(allowedNamespaces []string) error {
	err := msg.ToDidDoc().Validate(allowedNamespaces)
	if err != nil {
		return err
	}

	return validation.ValidateStruct(&msg,
		validation.Field(&msg.VersionId, validation.Required),
	)
}

func ValidMsgCreateDidPayloadRule(allowedNamespaces []string) *CustomErrorRule {
	return NewCustomErrorRule(func(value interface{}) error {
		casted, ok := value.(*MsgCreateDidDocPayload)
		if !ok {
			panic("ValidMsgCreateDidPayloadRule must be only applied on MsgCreateDidPayload properties")
		}

		return casted.Validate(allowedNamespaces)
	})
}

// Normalize

func (msg *MsgCreateDidDocPayload) Normalize() {
	msg.Id = utils.NormalizeDID(msg.Id)
	for _, vm := range msg.VerificationMethod {
		NormalizeVerificationMethod(vm)
	}
	msg.Controller = utils.NormalizeDIDList(msg.Controller)

	NormalizeVerificationRelationshipList(msg.Authentication)
	NormalizeVerificationRelationshipList(msg.AssertionMethod)
	NormalizeVerificationRelationshipList(msg.CapabilityInvocation)
	NormalizeVerificationRelationshipList(msg.CapabilityDelegation)
	NormalizeVerificationRelationshipList(msg.KeyAgreement)

	for _, s := range msg.Service {
		NormalizeService(s)
	}
	msg.VersionId = utils.NormalizeUUID(msg.VersionId)
}
