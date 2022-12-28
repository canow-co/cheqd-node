package types

import (
	"github.com/canow-co/cheqd-node/x/did/utils"
	validation "github.com/go-ozzo/ozzo-validation/v4"
)

func NewDidDoc(
	context []string,
	id string,
	controller []string,
	verificationMethod []*VerificationMethod,
	authentication []*VerificationRelationship,
	assertionMethod []*VerificationRelationship,
	capabilityInvocation []*VerificationRelationship,
	capabilityDelegation []*VerificationRelationship,
	keyAgreement []*VerificationRelationship,
	service []*Service,
	alsoKnownAs []string,
) *DidDoc {
	return &DidDoc{
		Context:              context,
		Id:                   id,
		Controller:           controller,
		VerificationMethod:   verificationMethod,
		Authentication:       authentication,
		AssertionMethod:      assertionMethod,
		CapabilityInvocation: capabilityInvocation,
		CapabilityDelegation: capabilityDelegation,
		KeyAgreement:         keyAgreement,
		Service:              service,
		AlsoKnownAs:          alsoKnownAs,
	}
}

// Helpers

// AllControllerDids returns controller DIDs used in both did.controllers and did.verification_method.controller
func (didDoc *DidDoc) AllControllerDids() []string {
	result := didDoc.Controller
	result = append(result, didDoc.GetVerificationMethodControllers()...)

	return utils.UniqueSorted(result)
}

// ReplaceDids replaces ids in all controller and id fields
func (didDoc *DidDoc) ReplaceDids(old, new string) {
	// Controllers
	utils.ReplaceInSlice(didDoc.Controller, old, new)

	// Id
	if didDoc.Id == old {
		didDoc.Id = new
	}

	for _, vm := range didDoc.VerificationMethod {
		vm.ReplaceDids(old, new)
	}
}

func (didDoc *DidDoc) GetControllersOrSubject() []string {
	result := didDoc.Controller

	if len(result) == 0 {
		result = append(result, didDoc.Id)
	}

	return result
}

func (didDoc *DidDoc) GetVerificationMethodControllers() []string {
	var result []string

	for _, vm := range didDoc.VerificationMethod {
		result = append(result, vm.Controller)
	}

	return result
}

// Validation

func (didDoc DidDoc) Validate(allowedNamespaces []string) error {
	return validation.ValidateStruct(&didDoc,
		validation.Field(&didDoc.Id, validation.Required, IsDID(allowedNamespaces)),
		validation.Field(&didDoc.Controller, IsUniqueStrList(), validation.Each(IsDID(allowedNamespaces))),
		validation.Field(&didDoc.VerificationMethod,
			IsUniqueVerificationMethodListByIdRule(), validation.Each(ValidVerificationMethodRule(didDoc.Id, allowedNamespaces)),
		),

		validation.Field(&didDoc.Authentication,
			validation.Each(ValidVerificationRelationshipRule(didDoc.Id, allowedNamespaces)), IsUniqueVerificationRelationshipListByIdRule(),
		),
		validation.Field(&didDoc.AssertionMethod,
			validation.Each(ValidVerificationRelationshipRule(didDoc.Id, allowedNamespaces)), IsUniqueVerificationRelationshipListByIdRule(),
		),
		validation.Field(&didDoc.CapabilityInvocation,
			validation.Each(ValidVerificationRelationshipRule(didDoc.Id, allowedNamespaces)), IsUniqueVerificationRelationshipListByIdRule(),
		),
		validation.Field(&didDoc.CapabilityDelegation,
			validation.Each(ValidVerificationRelationshipRule(didDoc.Id, allowedNamespaces)), IsUniqueVerificationRelationshipListByIdRule(),
		),
		validation.Field(&didDoc.KeyAgreement,
			validation.Each(ValidVerificationRelationshipRule(didDoc.Id, allowedNamespaces)), IsUniqueVerificationRelationshipListByIdRule(),
		),

		validation.Field(&didDoc.Service, IsUniqueServiceListByIdRule(), validation.Each(ValidServiceRule(didDoc.Id, allowedNamespaces))),
		validation.Field(&didDoc.AlsoKnownAs, IsUniqueStrList(), validation.Each(IsURI())),
	)
}
