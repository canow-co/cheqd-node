package types

import (
	"errors"

	"github.com/canow-co/cheqd-node/x/did/utils"
	validation "github.com/go-ozzo/ozzo-validation/v4"
)

func NewVerificationRelationship(verificationMethodId string, verificationMethod *VerificationMethod) *VerificationRelationship {
	return &VerificationRelationship{
		VerificationMethodId: verificationMethodId,
		VerificationMethod:   verificationMethod,
	}
}

// Validation

func (vm VerificationRelationship) Validate(baseDid string, allowedNamespaces []string) error {
	if vm.VerificationMethodId != "" && vm.VerificationMethod != nil {
		return errors.New("Only one of VerificationMethodId and VerificationMethod must be set in VerificationRelationship")
	} else if vm.VerificationMethodId != "" {
		return validation.Validate(vm.VerificationMethodId, IsSpecificDIDUrl(allowedNamespaces, Empty, Empty, Required), HasPrefix(baseDid))
	} else if vm.VerificationMethod != nil {
		return validation.Validate(vm.VerificationMethod, ValidVerificationMethodRule(baseDid, allowedNamespaces))
	} else {
		return errors.New("One of VerificationMethodId or VerificationMethod must be set in VerificationRelationship")
	}
}

func ValidVerificationRelationshipRule(baseDid string, allowedNamespaces []string) *CustomErrorRule {
	return NewCustomErrorRule(func(value interface{}) error {
		casted, ok := value.(VerificationRelationship)
		if !ok {
			panic("ValidVerificationRelationshipRule must be only applied on verification relationships")
		}

		return casted.Validate(baseDid, allowedNamespaces)
	})
}

func IsUniqueVerificationRelationshipListByIdRule() *CustomErrorRule {
	return NewCustomErrorRule(func(value interface{}) error {
		casted, ok := value.([]*VerificationRelationship)
		if !ok {
			panic("IsUniqueVerificationRelationshipListByIdRule must be only applied on VM lists")
		}

		ids := getVerificationRelationshipIds(casted)
		if !utils.IsUnique(ids) {
			return errors.New("there are verification relationships with same IDs")
		}

		return nil
	})
}

func getVerificationRelationshipIds(vrs []*VerificationRelationship) []string {
	res := make([]string, len(vrs))

	for i := range vrs {
		if vrs[i].VerificationMethod != nil {
			res[i] = vrs[i].VerificationMethod.Id
		} else {
			res[i] = vrs[i].VerificationMethodId
		}
	}

	return res
}