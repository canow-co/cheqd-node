package types_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	. "github.com/canow-co/cheqd-node/x/did/types"
)

var _ = Describe("Message for DID updating", func() {
	type TestCaseMsgUpdateDID struct {
		msg      *MsgUpdateDidDoc
		isValid  bool
		errorMsg string
	}

	DescribeTable("Tests for message for DID updating", func(testCase TestCaseMsgUpdateDID) {
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
			TestCaseMsgUpdateDID{
				msg: &MsgUpdateDidDoc{
					Payload: &MsgUpdateDidDocPayload{
						Id: "did:canow:testnet:zABCDEFG123456789abcd",
						VerificationMethod: []*VerificationMethod{
							{
								Id:                     "did:canow:testnet:zABCDEFG123456789abcd#key1",
								VerificationMethodType: "Ed25519VerificationKey2020",
								Controller:             "did:canow:testnet:zABCDEFG123456789abcd",
								VerificationMaterial:   ValidEd25519VerificationKey2020VerificationMaterial,
							},
						},
						Authentication: []*VerificationRelationship{
							{
								VerificationMethodId: "did:canow:testnet:zABCDEFG123456789abcd#key1",
							},
						},
						VersionId: "version1",
					},
					Signatures: nil,
				},
				isValid: true,
			}),

		Entry(
			"IDs are duplicated",
			TestCaseMsgUpdateDID{
				msg: &MsgUpdateDidDoc{
					Payload: &MsgUpdateDidDocPayload{
						Id: "did:canow:testnet:zABCDEFG123456789abcd",
						VerificationMethod: []*VerificationMethod{
							{
								Id:                     "did:canow:testnet:zABCDEFG123456789abcd#key1",
								VerificationMethodType: "Ed25519VerificationKey2020",
								Controller:             "did:canow:testnet:zABCDEFG123456789abcd",
								VerificationMaterial:   ValidEd25519VerificationKey2020VerificationMaterial,
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
						VersionId: "version1",
					},
					Signatures: nil,
				},
				isValid:  false,
				errorMsg: "payload: (authentication: there are verification relationships with same IDs.).: basic validation failed",
			}),
		Entry(
			"VersionId is empty",
			TestCaseMsgUpdateDID{
				msg: &MsgUpdateDidDoc{
					Payload: &MsgUpdateDidDocPayload{
						Id: "did:canow:testnet:zABCDEFG123456789abcd",
						VerificationMethod: []*VerificationMethod{
							{
								Id:                     "did:canow:testnet:zABCDEFG123456789abcd#key1",
								VerificationMethodType: "Ed25519VerificationKey2020",
								Controller:             "did:canow:testnet:zABCDEFG123456789abcd",
								VerificationMaterial:   ValidEd25519VerificationKey2020VerificationMaterial,
							},
						},
						Authentication: []*VerificationRelationship{
							{
								VerificationMethodId: "did:canow:testnet:zABCDEFG123456789abcd#key1",
							},
						},
					},
					Signatures: nil,
				},
				isValid:  false,
				errorMsg: "payload: (version_id: cannot be blank.).: basic validation failed",
			}),
	)
})
