package types_test

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	. "github.com/canow-co/cheqd-node/x/did/types"
)

type DIDDocTestCase struct {
	didDoc            *DidDoc
	allowedNamespaces []string
	isValid           bool
	errorMsg          string
}

var _ = DescribeTable("DIDDoc Validation tests", func(testCase DIDDocTestCase) {
	err := testCase.didDoc.Validate(testCase.allowedNamespaces)

	if testCase.isValid {
		Expect(err).To(BeNil())
	} else {
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring(testCase.errorMsg))
	}
},

	Entry(
		"DIDDoc is valid",
		DIDDocTestCase{
			didDoc: &DidDoc{
				Id: ValidTestDID,
				VerificationMethod: []*VerificationMethod{
					{
						Id:                   fmt.Sprintf("%s#fragment", ValidTestDID),
						Type:                 "Ed25519VerificationKey2020",
						Controller:           ValidTestDID,
						VerificationMaterial: ValidEd25519MultibaseVerificationMaterial,
					},
				},
			},
			isValid:  true,
			errorMsg: "",
		}),

	Entry(
		"DIDDoc is invalid",
		DIDDocTestCase{
			didDoc: &DidDoc{
				Id: InvalidTestDID,
				VerificationMethod: []*VerificationMethod{
					{
						Id:                   fmt.Sprintf("%s#fragment", ValidTestDID),
						Type:                 "Ed25519VerificationKey2020",
						Controller:           ValidTestDID,
						VerificationMaterial: ValidEd25519MultibaseVerificationMaterial,
					},
				},
			},
			isValid:  false,
			errorMsg: "id: unable to split did into method, namespace and id; verification_method: (0: (id: must have prefix: badDid.).).",
		}),

	Entry(
		"Verification method is Ed25519VerificationKey2020",
		DIDDocTestCase{
			didDoc: &DidDoc{
				Id: ValidTestDID,
				VerificationMethod: []*VerificationMethod{
					{
						Id:                   fmt.Sprintf("%s#fragment", ValidTestDID),
						Type:                 "Ed25519VerificationKey2020",
						Controller:           ValidTestDID,
						VerificationMaterial: ValidEd25519MultibaseVerificationMaterial,
					},
				},
			},
			isValid:  true,
			errorMsg: "",
		}),

	Entry(
		"Verification method is JWK",
		DIDDocTestCase{
			didDoc: &DidDoc{
				Id: ValidTestDID,
				VerificationMethod: []*VerificationMethod{
					{
						Id:                   fmt.Sprintf("%s#fragment", ValidTestDID),
						Type:                 "JsonWebKey2020",
						Controller:           ValidTestDID,
						VerificationMaterial: ValidJwkVerificationMaterial,
					},
				},
			},
			isValid:  true,
			errorMsg: "",
		}),

	Entry("Verification method has wrong ID",
		DIDDocTestCase{
			didDoc: &DidDoc{
				Id: ValidTestDID,
				VerificationMethod: []*VerificationMethod{
					{
						Id:                   InvalidTestDID,
						Type:                 "JsonWebKey2020",
						Controller:           ValidTestDID,
						VerificationMaterial: ValidJwkVerificationMaterial,
					},
				},
			},
			isValid:  false,
			errorMsg: "verification_method: (0: (id: unable to split did into method, namespace and id.).).",
		}),
	Entry(
		"Verification method has wrong controller",
		DIDDocTestCase{
			didDoc: &DidDoc{
				Id: ValidTestDID,
				VerificationMethod: []*VerificationMethod{
					{
						Id:                   fmt.Sprintf("%s#fragment", ValidTestDID),
						Type:                 "JsonWebKey2020",
						Controller:           InvalidTestDID,
						VerificationMaterial: ValidJwkVerificationMaterial,
					},
				},
			},
			isValid:  false,
			errorMsg: "verification_method: (0: (controller: unable to split did into method, namespace and id.).).",
		}),
	Entry(
		"List of DIDs in controller is allowed",
		DIDDocTestCase{
			didDoc: &DidDoc{
				Id:         ValidTestDID,
				Controller: []string{ValidTestDID, ValidTestDID2},
				VerificationMethod: []*VerificationMethod{
					{
						Id:                   fmt.Sprintf("%s#fragment", ValidTestDID),
						Type:                 "Ed25519VerificationKey2020",
						Controller:           ValidTestDID,
						VerificationMaterial: ValidEd25519MultibaseVerificationMaterial,
					},
				},
			},
			isValid:  true,
			errorMsg: "",
		}),
	Entry(
		"List of DIDs in controller is not allowed",
		DIDDocTestCase{
			didDoc: &DidDoc{
				Context:    nil,
				Id:         ValidTestDID,
				Controller: []string{ValidTestDID, InvalidTestDID},
				VerificationMethod: []*VerificationMethod{
					{
						Id:                   fmt.Sprintf("%s#fragment", ValidTestDID),
						Type:                 "Ed25519VerificationKey2020",
						Controller:           ValidTestDID,
						VerificationMaterial: ValidEd25519MultibaseVerificationMaterial,
					},
				},
			},
			isValid:  false,
			errorMsg: "controller: (1: unable to split did into method, namespace and id.).",
		}),
	Entry(
		"Namespace in controller is not in list of allowed",
		DIDDocTestCase{
			didDoc: &DidDoc{
				Id:         ValidTestDID,
				Controller: []string{ValidTestDID},
				VerificationMethod: []*VerificationMethod{
					{
						Id:                   fmt.Sprintf("%s#fragment", ValidTestDID),
						Type:                 "Ed25519VerificationKey2020",
						Controller:           ValidTestDID,
						VerificationMaterial: ValidEd25519MultibaseVerificationMaterial,
					},
				},
			},
			allowedNamespaces: []string{"mainnet"},
			isValid:           false,
			errorMsg:          "controller: (0: did namespace must be one of: mainnet.); id: did namespace must be one of: mainnet; verification_method: (0: (controller: did namespace must be one of: mainnet; id: did namespace must be one of: mainnet.).).",
		}),
	Entry(
		"Controller is duplicated",
		DIDDocTestCase{
			didDoc: &DidDoc{
				Id:         ValidTestDID,
				Controller: []string{ValidTestDID, ValidTestDID},
				VerificationMethod: []*VerificationMethod{
					{
						Id:                   fmt.Sprintf("%s#fragment", ValidTestDID),
						Type:                 "Ed25519VerificationKey2020",
						Controller:           ValidTestDID,
						VerificationMaterial: ValidEd25519MultibaseVerificationMaterial,
					},
				},
			},
			isValid:  false,
			errorMsg: "controller: there should be no duplicates.",
		}),
	Entry(
		"Verification Method list has double method definition",
		DIDDocTestCase{
			didDoc: &DidDoc{
				Id: ValidTestDID,
				VerificationMethod: []*VerificationMethod{
					{
						Id:                   fmt.Sprintf("%s#fragment", ValidTestDID),
						Type:                 "Ed25519VerificationKey2020",
						Controller:           ValidTestDID,
						VerificationMaterial: ValidEd25519MultibaseVerificationMaterial,
					},
					{
						Id:                   fmt.Sprintf("%s#fragment", ValidTestDID),
						Type:                 "Ed25519VerificationKey2020",
						Controller:           ValidTestDID,
						VerificationMaterial: ValidEd25519MultibaseVerificationMaterial,
					},
				},
			},
			isValid:  false,
			errorMsg: "verification_method: there are verification method duplicates.",
		}),

	Entry("Verification Relationship lists contain embedded methods and references",
		DIDDocTestCase{
			didDoc: &DidDoc{
				Id: ValidTestDID,
				VerificationMethod: []*VerificationMethod{
					{
						Id:                   fmt.Sprintf("%s#fragment0", ValidTestDID),
						Type:                 "JsonWebKey2020",
						Controller:           ValidTestDID,
						VerificationMaterial: ValidJwkVerificationMaterial,
					},
				},
				Authentication: []*VerificationRelationship{
					{
						VerificationMethod: &VerificationMethod{
							Id:                   fmt.Sprintf("%s#fragment1", ValidTestDID),
							Type:                 "JsonWebKey2020",
							Controller:           ValidTestDID,
							VerificationMaterial: ValidJwkVerificationMaterial,
						},
					},
					{
						VerificationMethodId: fmt.Sprintf("%s#fragment0", ValidTestDID),
					},
				},
				AssertionMethod: []*VerificationRelationship{
					{
						VerificationMethod: &VerificationMethod{
							Id:                   fmt.Sprintf("%s#fragment2", ValidTestDID),
							Type:                 "JsonWebKey2020",
							Controller:           ValidTestDID,
							VerificationMaterial: ValidJwkVerificationMaterial,
						},
					},
					{
						VerificationMethodId: fmt.Sprintf("%s#fragment0", ValidTestDID),
					},
				},
				CapabilityInvocation: []*VerificationRelationship{
					{
						VerificationMethod: &VerificationMethod{
							Id:                   fmt.Sprintf("%s#fragment3", ValidTestDID),
							Type:                 "JsonWebKey2020",
							Controller:           ValidTestDID,
							VerificationMaterial: ValidJwkVerificationMaterial,
						},
					},

					{
						VerificationMethodId: fmt.Sprintf("%s#fragment0", ValidTestDID),
					},
				},
				CapabilityDelegation: []*VerificationRelationship{
					{
						VerificationMethod: &VerificationMethod{
							Id:                   fmt.Sprintf("%s#fragment4", ValidTestDID),
							Type:                 "JsonWebKey2020",
							Controller:           ValidTestDID,
							VerificationMaterial: ValidJwkVerificationMaterial,
						},
					},
					{
						VerificationMethodId: fmt.Sprintf("%s#fragment0", ValidTestDID),
					},
				},
				KeyAgreement: []*VerificationRelationship{
					{
						VerificationMethod: &VerificationMethod{
							Id:                   fmt.Sprintf("%s#fragment5", ValidTestDID),
							Type:                 "JsonWebKey2020",
							Controller:           ValidTestDID,
							VerificationMaterial: ValidJwkVerificationMaterial,
						},
					},
					{
						VerificationMethodId: fmt.Sprintf("%s#fragment0", ValidTestDID),
					},
				},
			},
			isValid:  true,
			errorMsg: "",
		}),
	Entry("Verification Relationship embedded method has wrong ID",
		DIDDocTestCase{
			didDoc: &DidDoc{
				Id: ValidTestDID,
				Authentication: []*VerificationRelationship{
					{
						VerificationMethod: &VerificationMethod{
							Id:                   InvalidTestDID,
							Type:                 "JsonWebKey2020",
							Controller:           ValidTestDID,
							VerificationMaterial: ValidJwkVerificationMaterial,
						},
					},
				},
			},
			isValid:  false,
			errorMsg: "authentication: (0: (id: unable to split did into method, namespace and id.).).",
		}),
	Entry(
		"Verification Relationship embedded method has wrong controller",
		DIDDocTestCase{
			didDoc: &DidDoc{
				Id: ValidTestDID,
				Authentication: []*VerificationRelationship{
					{
						VerificationMethod: &VerificationMethod{
							Id:                   fmt.Sprintf("%s#fragment", ValidTestDID),
							Type:                 "JsonWebKey2020",
							Controller:           InvalidTestDID,
							VerificationMaterial: ValidJwkVerificationMaterial,
						},
					},
				},
			},
			isValid:  false,
			errorMsg: "authentication: (0: (controller: unable to split did into method, namespace and id.).).",
		}),
	Entry(
		"Verification Relationship list has double method definition",
		DIDDocTestCase{
			didDoc: &DidDoc{
				Id: ValidTestDID,
				VerificationMethod: []*VerificationMethod{
					{
						Id:                   fmt.Sprintf("%s#fragment0", ValidTestDID),
						Type:                 "JsonWebKey2020",
						Controller:           ValidTestDID,
						VerificationMaterial: ValidJwkVerificationMaterial,
					},
				},
				Authentication: []*VerificationRelationship{
					{
						VerificationMethod: &VerificationMethod{
							Id:                   fmt.Sprintf("%s#fragment1", ValidTestDID),
							Type:                 "JsonWebKey2020",
							Controller:           ValidTestDID,
							VerificationMaterial: ValidJwkVerificationMaterial,
						},
					},
					{
						VerificationMethod: &VerificationMethod{
							Id:                   fmt.Sprintf("%s#fragment1", ValidTestDID),
							Type:                 "JsonWebKey2020",
							Controller:           ValidTestDID,
							VerificationMaterial: ValidJwkVerificationMaterial,
						},
					},
				},
			},
			isValid:  false,
			errorMsg: "authentication: there are verification relationships with same IDs",
		}),
	Entry(
		"Verification Method and Relationship lists have double method definition",
		DIDDocTestCase{
			didDoc: &DidDoc{
				Id: ValidTestDID,
				VerificationMethod: []*VerificationMethod{
					{
						Id:                   fmt.Sprintf("%s#fragment", ValidTestDID),
						Type:                 "JsonWebKey2020",
						Controller:           ValidTestDID,
						VerificationMaterial: ValidJwkVerificationMaterial,
					},
				},
				Authentication: []*VerificationRelationship{
					{
						VerificationMethod: &VerificationMethod{
							Id:                   fmt.Sprintf("%s#fragment", ValidTestDID),
							Type:                 "JsonWebKey2020",
							Controller:           ValidTestDID,
							VerificationMaterial: ValidJwkVerificationMaterial,
						},
					},
				},
			},
			isValid:  false,
			errorMsg: "there are verification method duplicates",
		}),
	Entry(
		"Different Verification Relationships lists have double method definition",
		DIDDocTestCase{
			didDoc: &DidDoc{
				Id: ValidTestDID,
				VerificationMethod: []*VerificationMethod{
					{
						Id:                   fmt.Sprintf("%s#fragment0", ValidTestDID),
						Type:                 "JsonWebKey2020",
						Controller:           ValidTestDID,
						VerificationMaterial: ValidJwkVerificationMaterial,
					},
				},
				Authentication: []*VerificationRelationship{
					{
						VerificationMethod: &VerificationMethod{
							Id:                   fmt.Sprintf("%s#fragment1", ValidTestDID),
							Type:                 "JsonWebKey2020",
							Controller:           ValidTestDID,
							VerificationMaterial: ValidJwkVerificationMaterial,
						},
					},
				},
				AssertionMethod: []*VerificationRelationship{
					{
						VerificationMethod: &VerificationMethod{
							Id:                   fmt.Sprintf("%s#fragment1", ValidTestDID),
							Type:                 "JsonWebKey2020",
							Controller:           ValidTestDID,
							VerificationMaterial: ValidJwkVerificationMaterial,
						},
					},
				},
			},
			isValid:  false,
			errorMsg: "there are verification method duplicates",
		}),
	Entry("Verification Relationship list has duplicated references",
		DIDDocTestCase{
			didDoc: &DidDoc{
				Id: ValidTestDID,
				VerificationMethod: []*VerificationMethod{
					{
						Id:                   fmt.Sprintf("%s#fragment0", ValidTestDID),
						Type:                 "JsonWebKey2020",
						Controller:           ValidTestDID,
						VerificationMaterial: ValidJwkVerificationMaterial,
					},
				},
				Authentication: []*VerificationRelationship{
					{
						VerificationMethodId: fmt.Sprintf("%s#fragment0", ValidTestDID),
					},
					{
						VerificationMethod: &VerificationMethod{
							Id:                   fmt.Sprintf("%s#fragment1", ValidTestDID),
							Type:                 "JsonWebKey2020",
							Controller:           ValidTestDID,
							VerificationMaterial: ValidJwkVerificationMaterial,
						},
					},
					{
						VerificationMethodId: fmt.Sprintf("%s#fragment0", ValidTestDID),
					},
				},
			},
			isValid:  false,
			errorMsg: "authentication: there are verification relationships with same IDs.",
		}),
	Entry(
		"Verification Relationship reference points to not existing method",
		DIDDocTestCase{
			didDoc: &DidDoc{
				Id: ValidTestDID,
				VerificationMethod: []*VerificationMethod{
					{
						Id:                   fmt.Sprintf("%s#fragment1", ValidTestDID),
						Type:                 "JsonWebKey2020",
						Controller:           ValidTestDID,
						VerificationMaterial: ValidJwkVerificationMaterial,
					},
				},
				Authentication: []*VerificationRelationship{
					{
						VerificationMethodId: fmt.Sprintf("%s#fragment2", ValidTestDID),
					},
				},
			},
			isValid:  false,
			errorMsg: "authentication: (0: can't resolve verification method reference: did:canow:testnet:zABCDEFG123456789abcd#fragment2.).",
		}),
	Entry(
		"Verification Relationship reference points to embedded method from another Verification Relationship list",
		DIDDocTestCase{
			didDoc: &DidDoc{
				Id: ValidTestDID,
				VerificationMethod: []*VerificationMethod{
					{
						Id:                   fmt.Sprintf("%s#fragment0", ValidTestDID),
						Type:                 "JsonWebKey2020",
						Controller:           ValidTestDID,
						VerificationMaterial: ValidJwkVerificationMaterial,
					},
				},
				Authentication: []*VerificationRelationship{
					{
						VerificationMethod: &VerificationMethod{
							Id:                   fmt.Sprintf("%s#fragment1", ValidTestDID),
							Type:                 "JsonWebKey2020",
							Controller:           ValidTestDID,
							VerificationMaterial: ValidJwkVerificationMaterial,
						},
					},
				},
				AssertionMethod: []*VerificationRelationship{
					{
						VerificationMethodId: fmt.Sprintf("%s#fragment1", ValidTestDID),
					},
				},
			},
			isValid:  false,
			errorMsg: "assertion_method: (0: can't resolve verification method reference: did:canow:testnet:zABCDEFG123456789abcd#fragment1.).",
		}),
	Entry(
		"Verification Relationship reference points to embedded method from same Verification Relationship list",
		DIDDocTestCase{
			didDoc: &DidDoc{
				Id: ValidTestDID,
				VerificationMethod: []*VerificationMethod{
					{
						Id:                   fmt.Sprintf("%s#fragment0", ValidTestDID),
						Type:                 "JsonWebKey2020",
						Controller:           ValidTestDID,
						VerificationMaterial: ValidJwkVerificationMaterial,
					},
				},
				Authentication: []*VerificationRelationship{
					{
						VerificationMethod: &VerificationMethod{
							Id:                   fmt.Sprintf("%s#fragment1", ValidTestDID),
							Type:                 "JsonWebKey2020",
							Controller:           ValidTestDID,
							VerificationMaterial: ValidJwkVerificationMaterial,
						},
					},
					{
						VerificationMethodId: fmt.Sprintf("%s#fragment1", ValidTestDID),
					},
				},
			},
			isValid:  false,
			errorMsg: "authentication: (1: can't resolve verification method reference: did:canow:testnet:zABCDEFG123456789abcd#fragment1.).",
		}),
)
