package tests

import (
	"fmt"

	"github.com/google/uuid"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	testsetup "github.com/canow-co/cheqd-node/x/did/tests/setup"
	"github.com/canow-co/cheqd-node/x/did/types"
)

var _ = Describe("Create DID tests", func() {
	var setup testsetup.TestSetup

	BeforeEach(func() {
		setup = testsetup.Setup()
	})

	It("Valid: Works for simple DIDDoc (Ed25519VerificationKey2020)", func() {
		did := testsetup.GenerateDID(testsetup.Base58_16bytes)
		keypair := testsetup.GenerateKeyPair()
		keyID := did + "#key-1"

		msg := &types.MsgCreateDidDocPayload{
			Id: did,
			Authentication: []*types.VerificationRelationship{
				{
					VerificationMethodId: keyID,
				},
			},
			VerificationMethod: []*types.VerificationMethod{
				{
					Id:                     keyID,
					VerificationMethodType: types.Ed25519VerificationKey2020Type,
					Controller:             did,
					VerificationMaterial:   testsetup.GenerateEd25519VerificationKey2020VerificationMaterial(keypair.Public),
				},
			},
			VersionId: uuid.NewString(),
		}

		signatures := []testsetup.SignInput{
			{
				VerificationMethodID: keyID,
				Key:                  keypair.Private,
			},
		}

		_, err := setup.CreateDid(msg, signatures)
		Expect(err).To(BeNil())

		// check
		created, err := setup.QueryDidDoc(did)
		Expect(err).To(BeNil())
		Expect(msg.ToDidDoc()).To(Equal(*created.Value.DidDoc))
	})

	It("Valid: Works for simple DIDDoc (JsonWebKey2020)", func() {
		did := testsetup.GenerateDID(testsetup.Base58_16bytes)
		keypair := testsetup.GenerateKeyPair()
		keyID := did + "#key-1"

		msg := &types.MsgCreateDidDocPayload{
			Id: did,
			Authentication: []*types.VerificationRelationship{
				{
					VerificationMethodId: keyID,
				},
			},
			VerificationMethod: []*types.VerificationMethod{
				{
					Id:                     keyID,
					VerificationMethodType: types.JSONWebKey2020Type,
					Controller:             did,
					VerificationMaterial:   testsetup.GenerateJSONWebKey2020VerificationMaterial(keypair.Public),
				},
			},
			VersionId: uuid.NewString(),
		}

		signatures := []testsetup.SignInput{
			{
				VerificationMethodID: keyID,
				Key:                  keypair.Private,
			},
		}

		_, err := setup.CreateDid(msg, signatures)
		Expect(err).To(BeNil())

		// check
		created, err := setup.QueryDidDoc(did)
		Expect(err).To(BeNil())
		Expect(msg.ToDidDoc()).To(Equal(*created.Value.DidDoc))
	})

	It("Valid: Works for simple DIDDoc (Ed25519VerificationKey2018)", func() {
		did := testsetup.GenerateDID(testsetup.Base58_16bytes)
		keypair := testsetup.GenerateKeyPair()
		keyID := did + "#key-1"

		msg := &types.MsgCreateDidDocPayload{
			Id: did,
			Authentication: []*types.VerificationRelationship{
				{
					VerificationMethodId: keyID,
				},
			},
			VerificationMethod: []*types.VerificationMethod{
				{
					Id:                     keyID,
					VerificationMethodType: types.Ed25519VerificationKey2018Type,
					Controller:             did,
					VerificationMaterial:   testsetup.GenerateEd25519VerificationKey2018VerificationMaterial(keypair.Public),
				},
			},
			VersionId: uuid.NewString(),
		}

		signatures := []testsetup.SignInput{
			{
				VerificationMethodID: keyID,
				Key:                  keypair.Private,
			},
		}

		_, err := setup.CreateDid(msg, signatures)
		Expect(err).To(BeNil())

		// check
		created, err := setup.QueryDidDoc(did)
		Expect(err).To(BeNil())
		Expect(msg.ToDidDoc()).To(Equal(*created.Value.DidDoc))
	})

	It("Valid: Signature by method referenced from Authentication", func() {
		did := testsetup.GenerateDID(testsetup.Base58_16bytes)
		keypair := testsetup.GenerateKeyPair()
		keyID := did + "#key-1"

		msg := &types.MsgCreateDidDocPayload{
			Id: did,
			Authentication: []*types.VerificationRelationship{
				{
					VerificationMethodId: keyID,
				},
			},
			VerificationMethod: []*types.VerificationMethod{
				{
					Id:                     keyID,
					VerificationMethodType: types.Ed25519VerificationKey2020Type,
					Controller:             did,
					VerificationMaterial:   testsetup.GenerateEd25519VerificationKey2020VerificationMaterial(keypair.Public),
				},
			},
			VersionId: uuid.NewString(),
		}

		signatures := []testsetup.SignInput{
			{
				VerificationMethodID: keyID,
				Key:                  keypair.Private,
			},
		}

		_, err := setup.CreateDid(msg, signatures)
		Expect(err).To(BeNil())

		// check
		created, err := setup.QueryDidDoc(did)
		Expect(err).To(BeNil())
		Expect(msg.ToDidDoc()).To(Equal(*created.Value.DidDoc))
	})

	It("Valid: Signature by method embedded in Authentication", func() {
		did := testsetup.GenerateDID(testsetup.Base58_16bytes)
		keypair := testsetup.GenerateKeyPair()
		keyID := did + "#key-1"

		msg := &types.MsgCreateDidDocPayload{
			Id: did,
			Authentication: []*types.VerificationRelationship{
				{
					VerificationMethod: &types.VerificationMethod{
						Id:                     keyID,
						VerificationMethodType: types.Ed25519VerificationKey2020Type,
						Controller:             did,
						VerificationMaterial:   testsetup.GenerateEd25519VerificationKey2020VerificationMaterial(keypair.Public),
					},
				},
			},
			VersionId: uuid.NewString(),
		}

		signatures := []testsetup.SignInput{
			{
				VerificationMethodID: keyID,
				Key:                  keypair.Private,
			},
		}

		_, err := setup.CreateDid(msg, signatures)
		Expect(err).To(BeNil())

		// check
		created, err := setup.QueryDidDoc(did)
		Expect(err).To(BeNil())
		Expect(msg.ToDidDoc()).To(Equal(*created.Value.DidDoc))
	})

	// When searching for the authentication method, the current implementation must fall back
	// into `verificationMethod` list in case the method is not found in `authentication` list.
	It("Valid: Signature by method from VerificationMethod not referenced from Authentication", func() {
		did := testsetup.GenerateDID(testsetup.Base58_16bytes)

		keypair1 := testsetup.GenerateKeyPair()
		keyID1 := did + "#key-1"

		keypair2 := testsetup.GenerateKeyPair()
		keyID2 := did + "#key-2"

		msg := &types.MsgCreateDidDocPayload{
			Id: did,
			Authentication: []*types.VerificationRelationship{
				{
					VerificationMethodId: keyID1,
				},
			},
			VerificationMethod: []*types.VerificationMethod{
				{
					Id:                     keyID1,
					VerificationMethodType: types.Ed25519VerificationKey2020Type,
					Controller:             did,
					VerificationMaterial:   testsetup.GenerateEd25519VerificationKey2020VerificationMaterial(keypair1.Public),
				},
				{
					Id:                     keyID2,
					VerificationMethodType: types.Ed25519VerificationKey2020Type,
					Controller:             did,
					VerificationMaterial:   testsetup.GenerateEd25519VerificationKey2020VerificationMaterial(keypair2.Public),
				},
			},
			VersionId: uuid.NewString(),
		}

		signatures := []testsetup.SignInput{
			{
				VerificationMethodID: keyID2,
				Key:                  keypair2.Private,
			},
		}

		_, err := setup.CreateDid(msg, signatures)
		Expect(err).To(BeNil())

		// check
		created, err := setup.QueryDidDoc(did)
		Expect(err).To(BeNil())
		Expect(msg.ToDidDoc()).To(Equal(*created.Value.DidDoc))
	})

	// When searching for the authentication method, the current implementation must fall back
	// into `verificationMethod` list in case the method is not found in `authentication` list.
	It("Valid: Signature by method from VerificationMethod not referenced from Authentication but referenced from other verification relationships", func() {
		did := testsetup.GenerateDID(testsetup.Base58_16bytes)

		keypair1 := testsetup.GenerateKeyPair()
		keyID1 := did + "#key-1"

		keypair2 := testsetup.GenerateKeyPair()
		keyID2 := did + "#key-2"

		msg := &types.MsgCreateDidDocPayload{
			Id: did,
			Authentication: []*types.VerificationRelationship{
				{
					VerificationMethodId: keyID1,
				},
			},
			AssertionMethod: []*types.VerificationRelationship{
				{
					VerificationMethodId: keyID2,
				},
			},
			CapabilityInvocation: []*types.VerificationRelationship{
				{
					VerificationMethodId: keyID2,
				},
			},
			VerificationMethod: []*types.VerificationMethod{
				{
					Id:                     keyID1,
					VerificationMethodType: types.Ed25519VerificationKey2020Type,
					Controller:             did,
					VerificationMaterial:   testsetup.GenerateEd25519VerificationKey2020VerificationMaterial(keypair1.Public),
				},
				{
					Id:                     keyID2,
					VerificationMethodType: types.Ed25519VerificationKey2020Type,
					Controller:             did,
					VerificationMaterial:   testsetup.GenerateEd25519VerificationKey2020VerificationMaterial(keypair2.Public),
				},
			},
			VersionId: uuid.NewString(),
		}

		signatures := []testsetup.SignInput{
			{
				VerificationMethodID: keyID2,
				Key:                  keypair2.Private,
			},
		}

		_, err := setup.CreateDid(msg, signatures)
		Expect(err).To(BeNil())

		// check
		created, err := setup.QueryDidDoc(did)
		Expect(err).To(BeNil())
		Expect(msg.ToDidDoc()).To(Equal(*created.Value.DidDoc))
	})

	It("Valid: DID with external controllers", func() {
		// Alice
		alice := setup.CreateSimpleDid()
		anna := setup.CreateSimpleDid()

		// Bob
		bobDid := testsetup.GenerateDID(testsetup.Base58_16bytes)
		bobKeypair := testsetup.GenerateKeyPair()
		bobKeyID := bobDid + "#key-1"

		msg := &types.MsgCreateDidDocPayload{
			Id:         bobDid,
			Controller: []string{alice.Did, anna.Did},
			Authentication: []*types.VerificationRelationship{
				{
					VerificationMethodId: bobKeyID,
				},
			},
			VerificationMethod: []*types.VerificationMethod{
				{
					Id:                     bobKeyID,
					VerificationMethodType: types.Ed25519VerificationKey2020Type,
					Controller:             anna.Did,
					VerificationMaterial:   testsetup.GenerateEd25519VerificationKey2020VerificationMaterial(bobKeypair.Public),
				},
			},
			VersionId: uuid.NewString(),
		}

		signatures := []testsetup.SignInput{alice.SignInput, anna.SignInput}

		_, err := setup.CreateDid(msg, signatures)
		Expect(err).To(BeNil())

		// check
		created, err := setup.QueryDidDoc(bobDid)
		Expect(err).To(BeNil())
		Expect(msg.ToDidDoc()).To(Equal(*created.Value.DidDoc))
	})

	It("Valid: Works for DIDDoc with all properties", func() {
		did := testsetup.GenerateDID(testsetup.Base58_16bytes)

		keypair1 := testsetup.GenerateKeyPair()
		keyID1 := did + "#key-1"

		keypair2 := testsetup.GenerateKeyPair()
		keyID2 := did + "#key-2"

		keypair3 := testsetup.GenerateKeyPair()
		keyID3 := did + "#key-3"

		keypair4 := testsetup.GenerateKeyPair()
		keyID4 := did + "#key-4"

		keypair5 := testsetup.GenerateKeyPair()
		keyID5 := did + "#key-5"

		keypair6 := testsetup.GenerateKeyPair()
		keyID6 := did + "#key-6"

		msg := &types.MsgCreateDidDocPayload{
			Context:    []string{"abc", "def"},
			Id:         did,
			Controller: []string{did},
			VerificationMethod: []*types.VerificationMethod{
				{
					Id:                     keyID1,
					VerificationMethodType: types.Ed25519VerificationKey2020Type,
					Controller:             did,
					VerificationMaterial:   testsetup.GenerateEd25519VerificationKey2020VerificationMaterial(keypair1.Public),
				},
				{
					Id:                     keyID2,
					VerificationMethodType: types.Ed25519VerificationKey2020Type,
					Controller:             did,
					VerificationMaterial:   testsetup.GenerateEd25519VerificationKey2020VerificationMaterial(keypair2.Public),
				},
				{
					Id:                     keyID3,
					VerificationMethodType: types.Ed25519VerificationKey2020Type,
					Controller:             did,
					VerificationMaterial:   testsetup.GenerateEd25519VerificationKey2020VerificationMaterial(keypair3.Public),
				},
				{
					Id:                     keyID4,
					VerificationMethodType: types.Ed25519VerificationKey2020Type,
					Controller:             did,
					VerificationMaterial:   testsetup.GenerateEd25519VerificationKey2020VerificationMaterial(keypair4.Public),
				},
			},
			Authentication: []*types.VerificationRelationship{
				{
					VerificationMethodId: keyID1,
				},
				{
					VerificationMethodId: keyID2,
				},
				{
					VerificationMethod: &types.VerificationMethod{
						Id:                     keyID5,
						VerificationMethodType: types.Ed25519VerificationKey2020Type,
						Controller:             did,
						VerificationMaterial:   testsetup.GenerateEd25519VerificationKey2020VerificationMaterial(keypair5.Public),
					},
				},
			},
			AssertionMethod: []*types.VerificationRelationship{
				{
					VerificationMethodId: keyID3,
				},
			},
			CapabilityInvocation: []*types.VerificationRelationship{
				{
					VerificationMethod: &types.VerificationMethod{
						Id:                     keyID6,
						VerificationMethodType: types.Ed25519VerificationKey2020Type,
						Controller:             did,
						VerificationMaterial:   testsetup.GenerateEd25519VerificationKey2020VerificationMaterial(keypair6.Public),
					},
				},
				{
					VerificationMethodId: keyID4,
				},
				{
					VerificationMethodId: keyID1,
				},
			},
			CapabilityDelegation: []*types.VerificationRelationship{
				{
					VerificationMethodId: keyID4,
				},
				{
					VerificationMethodId: keyID2,
				},
			},
			KeyAgreement: []*types.VerificationRelationship{
				{
					VerificationMethodId: keyID1,
				},
				{
					VerificationMethodId: keyID2,
				},
				{
					VerificationMethodId: keyID3,
				},
				{
					VerificationMethodId: keyID4,
				},
			},
			Service: []*types.Service{
				{
					Id:              did + "#service-1",
					ServiceType:     "type-1",
					ServiceEndpoint: []string{"endpoint-1"},
					Accept:          []string{"accept-1"},
					RoutingKeys:     []string{"did:example:HPXoCUSjrSvWC54SLWQjsm#somekey"},
				},
			},
			AlsoKnownAs: []string{"alias-1", "alias-2"},
			VersionId:   uuid.NewString(),
		}

		signatures := []testsetup.SignInput{
			{
				VerificationMethodID: keyID1,
				Key:                  keypair1.Private,
			},
		}

		_, err := setup.CreateDid(msg, signatures)
		Expect(err).To(BeNil())

		// check
		created, err := setup.QueryDidDoc(did)
		Expect(err).To(BeNil())
		Expect(msg.ToDidDoc()).To(Equal(*created.Value.DidDoc))
	})

	// **************************
	// ***** Negative cases *****
	// **************************

	It("Not Valid: Signature by method embedded in verification relationship other than Authentication", func() {
		did := testsetup.GenerateDID(testsetup.Base58_16bytes)
		keypair := testsetup.GenerateKeyPair()
		keyID := did + "#key-1"

		msg := &types.MsgCreateDidDocPayload{
			Id: did,
			CapabilityInvocation: []*types.VerificationRelationship{
				{
					VerificationMethod: &types.VerificationMethod{
						Id:                     keyID,
						VerificationMethodType: types.Ed25519VerificationKey2020Type,
						Controller:             did,
						VerificationMaterial:   testsetup.GenerateEd25519VerificationKey2020VerificationMaterial(keypair.Public),
					},
				},
			},
			VersionId: uuid.NewString(),
		}

		signatures := []testsetup.SignInput{
			{
				VerificationMethodID: keyID,
				Key:                  keypair.Private,
			},
		}

		_, err := setup.CreateDid(msg, signatures)
		Expect(err.Error()).To(ContainSubstring(fmt.Sprintf("%s: authentication method not found", keyID)))
	})

	It("Not Valid: Second controller did not sign request", func() {
		// Alice
		alice := setup.CreateSimpleDid()

		// Bob
		bobDid := testsetup.GenerateDID(testsetup.Base58_16bytes)
		bobKeypair := testsetup.GenerateKeyPair()
		bobKeyID := bobDid + "#key-1"

		msg := &types.MsgCreateDidDocPayload{
			Id:         bobDid,
			Controller: []string{alice.Did, bobDid},
			Authentication: []*types.VerificationRelationship{
				{
					VerificationMethodId: bobKeyID,
				},
			},
			VerificationMethod: []*types.VerificationMethod{
				{
					Id:                     bobKeyID,
					VerificationMethodType: types.Ed25519VerificationKey2020Type,
					Controller:             bobDid,
					VerificationMaterial:   testsetup.GenerateEd25519VerificationKey2020VerificationMaterial(bobKeypair.Public),
				},
			},
			VersionId: uuid.NewString(),
		}

		signatures := []testsetup.SignInput{
			{
				VerificationMethodID: bobKeyID,
				Key:                  bobKeypair.Private,
			},
		}

		_, err := setup.CreateDid(msg, signatures)
		Expect(err.Error()).To(ContainSubstring(fmt.Sprintf("signer: %s: signature is required but not found", alice.Did)))
	})

	It("Not Valid: No signature", func() {
		did := testsetup.GenerateDID(testsetup.Base58_16bytes)
		keypair := testsetup.GenerateKeyPair()
		keyID := did + "#key-1"

		msg := &types.MsgCreateDidDocPayload{
			Id:         did,
			Controller: []string{did},
			Authentication: []*types.VerificationRelationship{
				{
					VerificationMethodId: keyID,
				},
			},
			VerificationMethod: []*types.VerificationMethod{
				{
					Id:                     keyID,
					VerificationMethodType: types.Ed25519VerificationKey2020Type,
					Controller:             did,
					VerificationMaterial:   testsetup.GenerateEd25519VerificationKey2020VerificationMaterial(keypair.Public),
				},
			},
			VersionId: uuid.NewString(),
		}

		signatures := []testsetup.SignInput{}

		_, err := setup.CreateDid(msg, signatures)
		Expect(err.Error()).To(ContainSubstring(fmt.Sprintf("signer: %s: signature is required but not found", did)))
	})

	It("Not Valid: Controller not found", func() {
		did := testsetup.GenerateDID(testsetup.Base58_16bytes)
		keypair := testsetup.GenerateKeyPair()
		keyID := did + "#key-1"

		nonExistingDid := testsetup.GenerateDID(testsetup.Base58_16bytes)

		msg := &types.MsgCreateDidDocPayload{
			Id:         did,
			Controller: []string{nonExistingDid},
			Authentication: []*types.VerificationRelationship{
				{
					VerificationMethodId: keyID,
				},
			},
			VerificationMethod: []*types.VerificationMethod{
				{
					Id:                     keyID,
					VerificationMethodType: types.Ed25519VerificationKey2020Type,
					Controller:             did,
					VerificationMaterial:   testsetup.GenerateEd25519VerificationKey2020VerificationMaterial(keypair.Public),
				},
			},
			VersionId: uuid.NewString(),
		}

		signatures := []testsetup.SignInput{
			{
				VerificationMethodID: keyID,
				Key:                  keypair.Private,
			},
		}

		_, err := setup.CreateDid(msg, signatures)
		Expect(err).ToNot(BeNil())
		Expect(err.Error()).To(ContainSubstring(fmt.Sprintf("%s: DID Doc not found", nonExistingDid)))
	})

	It("Not Valid: Wrong signature", func() {
		did := testsetup.GenerateDID(testsetup.Base58_16bytes)
		keypair := testsetup.GenerateKeyPair()
		keyID := did + "#key-1"

		msg := &types.MsgCreateDidDocPayload{
			Id:         did,
			Controller: []string{did},
			Authentication: []*types.VerificationRelationship{
				{
					VerificationMethodId: keyID,
				},
			},
			VerificationMethod: []*types.VerificationMethod{
				{
					Id:                     keyID,
					VerificationMethodType: types.Ed25519VerificationKey2020Type,
					Controller:             did,
					VerificationMaterial:   testsetup.GenerateEd25519VerificationKey2020VerificationMaterial(keypair.Public),
				},
			},
			VersionId: uuid.NewString(),
		}

		invalidKey := testsetup.GenerateKeyPair()

		signatures := []testsetup.SignInput{
			{
				VerificationMethodID: keyID,
				Key:                  invalidKey.Private,
			},
		}

		_, err := setup.CreateDid(msg, signatures)
		Expect(err.Error()).To(ContainSubstring(fmt.Sprintf("method id: %s: invalid signature detected", keyID)))
	})

	It("Not Valid: DID signed by wrong controller", func() {
		// Alice
		alice := setup.CreateSimpleDid()

		// Bob
		bobDid := testsetup.GenerateDID(testsetup.Base58_16bytes)
		bobKeypair := testsetup.GenerateKeyPair()
		bobKeyID := bobDid + "#key-1"

		msg := &types.MsgCreateDidDocPayload{
			Id:         bobDid,
			Controller: []string{bobDid},
			Authentication: []*types.VerificationRelationship{
				{
					VerificationMethodId: bobKeyID,
				},
			},
			VerificationMethod: []*types.VerificationMethod{
				{
					Id:                     bobKeyID,
					VerificationMethodType: types.Ed25519VerificationKey2020Type,
					Controller:             bobDid,
					VerificationMaterial:   testsetup.GenerateEd25519VerificationKey2020VerificationMaterial(bobKeypair.Public),
				},
			},
			VersionId: uuid.NewString(),
		}

		signatures := []testsetup.SignInput{alice.SignInput}

		_, err := setup.CreateDid(msg, signatures)
		Expect(err.Error()).To(ContainSubstring(fmt.Sprintf("signer: %s: signature is required but not found", bobDid)))
	})

	It("Not Valid: DID signed by invalid verification method", func() {
		did := testsetup.GenerateDID(testsetup.Base58_16bytes)
		keypair := testsetup.GenerateKeyPair()
		keyID := did + "#key-1"

		msg := &types.MsgCreateDidDocPayload{
			Id:         did,
			Controller: []string{did},
			Authentication: []*types.VerificationRelationship{
				{
					VerificationMethodId: keyID,
				},
			},
			VerificationMethod: []*types.VerificationMethod{
				{
					Id:                     keyID,
					VerificationMethodType: types.Ed25519VerificationKey2020Type,
					Controller:             did,
					VerificationMaterial:   testsetup.GenerateEd25519VerificationKey2020VerificationMaterial(keypair.Public),
				},
			},
			VersionId: uuid.NewString(),
		}

		invalidKeyID := did + "#key-2"

		signatures := []testsetup.SignInput{
			{
				VerificationMethodID: invalidKeyID,
				Key:                  keypair.Private,
			},
		}

		_, err := setup.CreateDid(msg, signatures)
		Expect(err.Error()).To(ContainSubstring(fmt.Sprintf("%s: authentication method not found", invalidKeyID)))
	})

	It("Not Valid: DIDDoc already exists", func() {
		// Alice
		alice := setup.CreateSimpleDid()

		msg := &types.MsgCreateDidDocPayload{
			Id: alice.Did,
			Authentication: []*types.VerificationRelationship{
				{
					VerificationMethodId: alice.KeyID,
				},
			},
			VerificationMethod: []*types.VerificationMethod{
				{
					Id:                     alice.KeyID,
					VerificationMethodType: types.Ed25519VerificationKey2020Type,
					Controller:             alice.Did,
					VerificationMaterial:   testsetup.GenerateEd25519VerificationKey2020VerificationMaterial(alice.KeyPair.Public),
				},
			},
		}

		signatures := []testsetup.SignInput{alice.SignInput}

		_, err := setup.CreateDid(msg, signatures)
		Expect(err.Error()).To(ContainSubstring(fmt.Sprintf("%s: DID Doc exists", alice.Did)))
	})

	It("Not Valid: DIDDoc Service Routing Keys field", func() {
		did := testsetup.GenerateDID(testsetup.Base58_16bytes)
		keypair := testsetup.GenerateKeyPair()
		keyID := did + "#key-1"

		msg := &types.MsgCreateDidDocPayload{
			Id: did,
			Authentication: []*types.VerificationRelationship{
				{
					VerificationMethodId: keyID,
				},
			},
			VerificationMethod: []*types.VerificationMethod{
				{
					Id:                     keyID,
					VerificationMethodType: types.Ed25519VerificationKey2020Type,
					Controller:             did,
					VerificationMaterial:   testsetup.GenerateEd25519VerificationKey2020VerificationMaterial(keypair.Public),
				},
			},
			VersionId: uuid.NewString(),
			Service: []*types.Service{
				{
					Id:              did + "#service-1",
					ServiceType:     "type-1",
					ServiceEndpoint: []string{"endpoint-1"},
					Accept:          []string{"accept-1"},
					RoutingKeys:     []string{"invalid value"},
				},
			},
		}

		signatures := []testsetup.SignInput{
			{
				VerificationMethodID: keyID,
				Key:                  keypair.Private,
			},
		}
		_, err := setup.CreateDid(msg, signatures)
		Expect(err.Error()).To(ContainSubstring("unable to split did into method, namespace and id"))
	})

	It("Not Valid: DIDDoc Service Routing Keys field (cannot be same keys in Routing Keys)", func() {
		did := testsetup.GenerateDID(testsetup.Base58_16bytes)
		keypair := testsetup.GenerateKeyPair()
		keyID := did + "#key-1"

		newRoutingKeys := []string{"did:example:HPXoCUSjrSvWC53SLWQjsm#somekey", "did:example:HPXoCUSjrSvWC53SLWQjsm#somekey"}

		msg := &types.MsgCreateDidDocPayload{
			Id: did,
			Authentication: []*types.VerificationRelationship{
				{
					VerificationMethodId: keyID,
				},
			},
			VerificationMethod: []*types.VerificationMethod{
				{
					Id:                     keyID,
					VerificationMethodType: types.Ed25519VerificationKey2020Type,
					Controller:             did,
					VerificationMaterial:   testsetup.GenerateEd25519VerificationKey2020VerificationMaterial(keypair.Public),
				},
			},
			VersionId: uuid.NewString(),
			Service: []*types.Service{
				{
					Id:              did + "#service-1",
					ServiceType:     "type-1",
					ServiceEndpoint: []string{"endpoint-1"},
					Accept:          []string{"accept-1"},
					RoutingKeys:     newRoutingKeys,
				},
			},
		}

		signatures := []testsetup.SignInput{
			{
				VerificationMethodID: keyID,
				Key:                  keypair.Private,
			},
		}
		_, err := setup.CreateDid(msg, signatures)
		Expect(err.Error()).To(ContainSubstring("there should be no duplicates"))
	})
})

var _ = Describe("Check upper/lower case for DID creation", func() {
	var setup testsetup.TestSetup
	didPrefix := "did:canow:testnet:"

	type TestCaseUUIDDidStruct struct {
		inputID  string
		resultID string
	}

	DescribeTable("Check upper/lower case for DID creation", func(testCase TestCaseUUIDDidStruct) {
		setup = testsetup.Setup()
		did := testCase.inputID
		keypair := testsetup.GenerateKeyPair()
		keyID := did + "#key-1"

		msg := &types.MsgCreateDidDocPayload{
			Id: did,
			Authentication: []*types.VerificationRelationship{
				{
					VerificationMethodId: keyID,
				},
			},
			VerificationMethod: []*types.VerificationMethod{
				{
					Id:                     keyID,
					VerificationMethodType: types.Ed25519VerificationKey2020Type,
					Controller:             did,
					VerificationMaterial:   testsetup.GenerateEd25519VerificationKey2020VerificationMaterial(keypair.Public),
				},
			},
			VersionId: uuid.NewString(),
		}

		signatures := []testsetup.SignInput{
			{
				VerificationMethodID: keyID,
				Key:                  keypair.Private,
			},
		}

		_, err := setup.CreateDid(msg, signatures)
		Expect(err).To(BeNil())

		// check
		created, err := setup.QueryDidDoc(did)
		Expect(err).To(BeNil())
		Expect(created.Value.DidDoc.Id).To(Equal(testCase.resultID))
	},

		Entry("Lowercase UUIDs", TestCaseUUIDDidStruct{
			inputID:  didPrefix + "a86f9cae-0902-4a7c-a144-96b60ced2fc9",
			resultID: didPrefix + "a86f9cae-0902-4a7c-a144-96b60ced2fc9",
		}),
		Entry("Uppercase UUIDs", TestCaseUUIDDidStruct{
			inputID:  didPrefix + "A86F9CAE-0902-4A7C-A144-96B60CED2FC9",
			resultID: didPrefix + "a86f9cae-0902-4a7c-a144-96b60ced2fc9",
		}),
		Entry("Mixed case UUIDs", TestCaseUUIDDidStruct{
			inputID:  didPrefix + "A86F9CAE-0902-4a7c-a144-96b60ced2FC9",
			resultID: didPrefix + "a86f9cae-0902-4a7c-a144-96b60ced2fc9",
		}),
		Entry("Indy-style IDs", TestCaseUUIDDidStruct{
			inputID:  didPrefix + "zABCDEFG123456789abcd",
			resultID: didPrefix + "zABCDEFG123456789abcd",
		}),
	)
})
