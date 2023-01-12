package types_test

import (
	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	. "github.com/canow-co/cheqd-node/x/did/types"
)

var _ = Describe("Message for DID creation", func() {
	type TestCaseMsgCreateDID struct {
		msg      *MsgCreateDidDoc
		isValid  bool
		errorMsg string
	}

	DescribeTable("Tests for message for DID creation", func(testCase TestCaseMsgCreateDID) {
		err := testCase.msg.ValidateBasic()

		if testCase.isValid {
			Expect(err).To(BeNil())
		} else {
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring(testCase.errorMsg))
		}
	},

		Entry(
			"All fields are set properly",
			TestCaseMsgCreateDID{
				msg: &MsgCreateDidDoc{
					Payload: &MsgCreateDidDocPayload{
						Id: "did:canow:testnet:zABCDEFG123456789abcd",
						VerificationMethod: []*VerificationMethod{
							{
								Id:                   "did:canow:testnet:zABCDEFG123456789abcd#key1",
								Type:                 "Ed25519VerificationKey2020",
								Controller:           "did:canow:testnet:zABCDEFG123456789abcd",
								VerificationMaterial: ValidEd25519MultibaseVerificationMaterial,
							},
						},
						Authentication: []*VerificationRelationship{
							{
								VerificationMethodId: "did:canow:testnet:zABCDEFG123456789abcd#key1",
							},
						},
						VersionId: uuid.NewString(),
					},
					Signatures: nil,
				},
				isValid: true,
			}),

		Entry(
			"IDs are duplicated",
			TestCaseMsgCreateDID{
				msg: &MsgCreateDidDoc{
					Payload: &MsgCreateDidDocPayload{
						Id: "did:canow:testnet:zABCDEFG123456789abcd",
						VerificationMethod: []*VerificationMethod{
							{
								Id:                   "did:canow:testnet:zABCDEFG123456789abcd#key1",
								Type:                 "Ed25519VerificationKey2020",
								Controller:           "did:canow:testnet:zABCDEFG123456789abcd",
								VerificationMaterial: ValidEd25519MultibaseVerificationMaterial,
							},
						},
						Authentication: []*VerificationRelationship{
							{
								VerificationMethodId: "did:canow:testnet:zABCDEFG123456789abcd#key1",
							},
							{
								VerificationMethodId: "did:canow:testnet:zABCDEFG123456789abcd#key1",
							},
						},
					},
					Signatures: nil,
				},
				isValid:  false,
				errorMsg: "payload: (authentication: there are verification relationships with same IDs.).: basic validation failed",
			}),
	)
})
