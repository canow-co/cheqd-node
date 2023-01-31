package types_test

import (
	. "github.com/canow-co/cheqd-node/x/did/types"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type VerificationRelationshipTestCase struct {
	vr                        VerificationRelationship
	baseDid                   string
	allowedNamespaces         []string
	sharedVerificationMethods []*VerificationMethod
	isValid                   bool
	errorMsg                  string
}

var _ = DescribeTable("Verification Relationship validation tests", func(testCase VerificationRelationshipTestCase) {
	err := testCase.vr.Validate(testCase.baseDid, testCase.allowedNamespaces, testCase.sharedVerificationMethods)

	if testCase.isValid {
		Expect(err).To(BeNil())
	} else {
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring(testCase.errorMsg))
	}
},

	Entry(
		"Verification relationship with valid verification method reference",
		VerificationRelationshipTestCase{
			vr: VerificationRelationship{
				VerificationMethodId: "did:canow:zABCDEFG123456789abcd#qwe",
			},
			sharedVerificationMethods: []*VerificationMethod{
				{
					Id:                     "did:canow:zABCDEFG123456789abcd#rty",
					VerificationMethodType: "JsonWebKey2020",
					Controller:             "did:canow:zABCDEFG987654321abcd",
					VerificationMaterial:   ValidJwkVerificationMaterial,
				},
				{
					Id:                     "did:canow:zABCDEFG123456789abcd#qwe",
					VerificationMethodType: "Ed25519VerificationKey2020",
					Controller:             "did:canow:zABCDEFG987654321abcd",
					VerificationMaterial:   ValidEd25519VerificationKey2020VerificationMaterial,
				},
			},
			isValid: true,
		}),

	Entry(
		"Verification relationship with valid embedded verification method",
		VerificationRelationshipTestCase{
			vr: VerificationRelationship{
				VerificationMethod: &VerificationMethod{
					Id:                     "did:canow:zABCDEFG123456789abcd#rty",
					VerificationMethodType: "JsonWebKey2020",
					Controller:             "did:canow:zABCDEFG987654321abcd",
					VerificationMaterial:   ValidJwkVerificationMaterial,
				},
			},
			isValid: true,
		}),

	Entry(
		"Neither verification method reference nor embedded verification method is set",
		VerificationRelationshipTestCase{
			vr:       VerificationRelationship{},
			isValid:  false,
			errorMsg: "one of VerificationMethodId or VerificationMethod must be set in VerificationRelationship",
		}),

	Entry(
		"Both verification method reference and embedded verification method are set at the same time",
		VerificationRelationshipTestCase{
			vr: VerificationRelationship{
				VerificationMethodId: "did:canow:zABCDEFG123456789abcd#qwe",
				VerificationMethod: &VerificationMethod{
					Id:                     "did:canow:zABCDEFG123456789abcd#rty",
					VerificationMethodType: "JsonWebKey2020",
					Controller:             "did:canow:zABCDEFG987654321abcd",
					VerificationMaterial:   ValidJwkVerificationMaterial,
				},
			},
			sharedVerificationMethods: []*VerificationMethod{
				{
					Id:                     "did:canow:zABCDEFG123456789abcd#qwe",
					VerificationMethodType: "Ed25519VerificationKey2020",
					Controller:             "did:canow:zABCDEFG987654321abcd",
					VerificationMaterial:   ValidEd25519VerificationKey2020VerificationMaterial,
				},
			},
			isValid:  false,
			errorMsg: "only one of VerificationMethodId and VerificationMethod must be set in VerificationRelationship",
		}),

	Entry(
		"Verification relationship with invalid verification method reference",
		VerificationRelationshipTestCase{
			vr: VerificationRelationship{
				VerificationMethodId: "did:canow:zABCDEFG123456789abcd#qwe",
			},
			sharedVerificationMethods: []*VerificationMethod{
				{
					Id:                     "did:canow:zABCDEFG123456789abcd#rty",
					VerificationMethodType: "JsonWebKey2020",
					Controller:             "did:canow:zABCDEFG987654321abcd",
					VerificationMaterial:   ValidJwkVerificationMaterial,
				},
			},
			isValid:  false,
			errorMsg: "can't resolve verification method reference: did:canow:zABCDEFG123456789abcd#qwe",
		}),

	Entry(
		"Verification relationship with invalid embedded verification method",
		VerificationRelationshipTestCase{
			vr: VerificationRelationship{
				VerificationMethod: &VerificationMethod{
					Id:                     "did:canow:zABCDEFG123456789abcd#rty",
					VerificationMethodType: "JsonWebKey2020",
					Controller:             "did:canow:zABCDEFG987654321abcd",
					VerificationMaterial:   InvalidJwkVerificationMaterial,
				},
			},
			isValid:  false,
			errorMsg: "verification_material: can't parse jwk: invalid key type from JSON (SomeOtherKeyType)",
		}),
)
