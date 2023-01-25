package types

import (
	"errors"

	"github.com/canow-co/cheqd-node/x/did/utils"
	validation "github.com/go-ozzo/ozzo-validation/v4"
)

func NewVerificationRelationship(verificationMethodID string, verificationMethod *VerificationMethod) *VerificationRelationship {
	return &VerificationRelationship{
		VerificationMethodId: verificationMethodID,
		VerificationMethod:   verificationMethod,
	}
}

// ReplaceDids replaces ids in all fields
func (vr *VerificationRelationship) ReplaceDids(old string, new string) {
	if vr.VerificationMethod != nil {
		vr.VerificationMethod.ReplaceDids(old, new)
	} else {
		did, path, query, fragment := utils.MustSplitDIDUrl(vr.VerificationMethodId)
		if did == old {
			did = new
		}
		vr.VerificationMethodId = utils.JoinDIDUrl(did, path, query, fragment)
	}
}

// Validation

func (vr VerificationRelationship) Validate(
	baseDid string,
	allowedNamespaces []string,
	sharedVerificationMethods []*VerificationMethod,
) error {
	if vr.VerificationMethodId != "" {
		if vr.VerificationMethod != nil {
			return errors.New("only one of VerificationMethodId and VerificationMethod must be set in VerificationRelationship")
		}
		return validation.Validate(vr.VerificationMethodId, IsValidVerificationMethodReference(sharedVerificationMethods))
	} 
	
	if vr.VerificationMethod != nil {
		return validation.Validate(*vr.VerificationMethod, ValidVerificationMethodRule(baseDid, allowedNamespaces))
	}
		return errors.New("one of VerificationMethodId or VerificationMethod must be set in VerificationRelationship")
}

func ValidVerificationRelationshipRule(
	baseDid string,
	allowedNamespaces []string,
	sharedVerificationMethods []*VerificationMethod,
) *CustomErrorRule {
	return NewCustomErrorRule(func(value interface{}) error {
		casted, ok := value.(VerificationRelationship)
		if !ok {
			panic("ValidVerificationRelationshipRule must be only applied on verification relationships")
		}

		return casted.Validate(baseDid, allowedNamespaces, sharedVerificationMethods)
	})
}

func IsUniqueVerificationRelationshipListByIDRule() *CustomErrorRule {
	return NewCustomErrorRule(func(value interface{}) error {
		casted, ok := value.([]*VerificationRelationship)
		if !ok {
			panic("IsUniqueVerificationRelationshipListByIDRule must be only applied on VM lists")
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
