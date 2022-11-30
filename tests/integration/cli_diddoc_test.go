//go:build integration

package integration

import (
	"crypto/ed25519"
	"fmt"

	"github.com/canow-co/cheqd-node/tests/integration/cli"
	"github.com/canow-co/cheqd-node/tests/integration/network"
	"github.com/canow-co/cheqd-node/tests/integration/testdata"
	cli_types "github.com/canow-co/cheqd-node/x/did/client/cli"
	"github.com/canow-co/cheqd-node/x/did/types"
	"github.com/google/uuid"
	"github.com/multiformats/go-multibase"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("cheqd cli - positive did", func() {
	var tmpDir string

	BeforeEach(func() {
		tmpDir = GinkgoT().TempDir()
	})

	It("can create diddoc, update it and query the result", func() {
		AddReportEntry("Integration", fmt.Sprintf("%sPositive: %s", cli.GREEN, "can create diddoc"))
		// Create a new DID Doc
		did := "did:canow:" + network.DID_NAMESPACE + ":" + uuid.NewString()
		keyId := did + "#key1"

		pubKey, privKey, err := ed25519.GenerateKey(nil)
		Expect(err).To(BeNil())

		pubKeyMultibase58, err := multibase.Encode(multibase.Base58BTC, pubKey)
		Expect(err).To(BeNil())

		payload := types.MsgCreateDidDocPayload{
			Id: did,
			VerificationMethod: []*types.VerificationMethod{
				{
					Id:                   keyId,
					Type:                 "Ed25519VerificationKey2020",
					Controller:           did,
					VerificationMaterial: "{\"publicKeyMultibase\": \"" + string(pubKeyMultibase58) + "\"}",
				},
			},
			Authentication: []string{keyId},
			VersionId:      uuid.NewString(),
		}

		signInputs := []cli_types.SignInput{
			{
				VerificationMethodId: keyId,
				PrivKey:              privKey,
			},
		}

		res, err := cli.CreateDidDoc(tmpDir, payload, signInputs, testdata.BASE_ACCOUNT_1)
		Expect(err).To(BeNil())
		Expect(res.Code).To(BeEquivalentTo(0))

		AddReportEntry("Integration", fmt.Sprintf("%sPositive: %s", cli.GREEN, "can update diddoc"))
		// Update the DID Doc
		newPubKey, newPrivKey, err := ed25519.GenerateKey(nil)
		Expect(err).To(BeNil())

		newPubKeyMultibase58, err := multibase.Encode(multibase.Base58BTC, newPubKey)
		Expect(err).To(BeNil())

		payload2 := types.MsgUpdateDidDocPayload{
			Id: did,
			VerificationMethod: []*types.VerificationMethod{
				{
					Id:                   keyId,
					Type:                 "Ed25519VerificationKey2020",
					Controller:           did,
					VerificationMaterial: "{\"publicKeyMultibase\": \"" + string(newPubKeyMultibase58) + "\"}",
				},
			},
			Authentication: []string{keyId},
			VersionId:      uuid.NewString(),
		}

		signInputs2 := []cli_types.SignInput{
			{
				VerificationMethodId: keyId,
				PrivKey:              privKey,
			},
			{
				VerificationMethodId: keyId,
				PrivKey:              newPrivKey,
			},
		}

		res2, err := cli.UpdateDidDoc(tmpDir, payload2, signInputs2, testdata.BASE_ACCOUNT_1)
		Expect(err).To(BeNil())
		Expect(res2.Code).To(BeEquivalentTo(0))

		AddReportEntry("Integration", fmt.Sprintf("%sPositive: %s", cli.GREEN, "can query diddoc"))
		// Query the DID Doc
		resp, err := cli.QueryDidDoc(did)
		Expect(err).To(BeNil())

		didDoc := resp.Value.DidDoc
		Expect(didDoc.Id).To(BeEquivalentTo(did))
		Expect(didDoc.Authentication).To(HaveLen(1))
		Expect(didDoc.Authentication[0]).To(BeEquivalentTo(keyId))
		Expect(didDoc.VerificationMethod).To(HaveLen(1))
		Expect(didDoc.VerificationMethod[0].Id).To(BeEquivalentTo(keyId))
		Expect(didDoc.VerificationMethod[0].Type).To(BeEquivalentTo("Ed25519VerificationKey2020"))
		Expect(didDoc.VerificationMethod[0].Controller).To(BeEquivalentTo(did))
		Expect(didDoc.VerificationMethod[0].VerificationMaterial).To(BeEquivalentTo("{\"publicKeyMultibase\": \"" + string(newPubKeyMultibase58) + "\"}"))
	})

	It("can create and update diddoc with not required Service fields", func() {
		AddReportEntry("Integration", fmt.Sprintf("%sPositive: %s", cli.GREEN, "can create diddoc"))
		// Create a new DID Doc
		did := "did:canow:" + network.DID_NAMESPACE + ":" + uuid.NewString()
		keyId := did + "#key1"

		pubKey, privKey, err := ed25519.GenerateKey(nil)
		Expect(err).To(BeNil())

		pubKeyMultibase58, err := multibase.Encode(multibase.Base58BTC, pubKey)
		Expect(err).To(BeNil())

		routingKeys := []string{"did:example:HPXoCUSjrSvWC54SLWQjsm#somekey"}

		payload := types.MsgCreateDidDocPayload{
			Id: did,
			VerificationMethod: []*types.VerificationMethod{
				{
					Id:                   keyId,
					Type:                 "Ed25519VerificationKey2020",
					Controller:           did,
					VerificationMaterial: "{\"publicKeyMultibase\": \"" + string(pubKeyMultibase58) + "\"}",
				},
			},
			Authentication: []string{keyId},
			VersionId:      uuid.NewString(),
			Service: []*types.Service{
				{
					Id:              did + "#service-1",
					Type:            "type-1",
					ServiceEndpoint: []string{"endpoint-1"},
					Accept:          []string{"accept-1"},
					RoutingKeys:     routingKeys,
				},
			},
		}

		signInputs := []cli_types.SignInput{
			{
				VerificationMethodId: keyId,
				PrivKey:              privKey,
			},
		}

		res, err := cli.CreateDidDoc(tmpDir, payload, signInputs, testdata.BASE_ACCOUNT_1)
		Expect(err).To(BeNil())
		Expect(res.Code).To(BeEquivalentTo(0))

		AddReportEntry("Integration", fmt.Sprintf("%sPositive: %s", cli.GREEN, "can query diddoc"))
		// Query the DID Doc
		resp, err := cli.QueryDidDoc(did)
		Expect(err).To(BeNil())

		didDoc := resp.Value.DidDoc
		Expect(didDoc.Id).To(BeEquivalentTo(did))
		Expect(didDoc.Authentication).To(HaveLen(1))
		Expect(didDoc.Authentication[0]).To(BeEquivalentTo(keyId))
		Expect(didDoc.VerificationMethod).To(HaveLen(1))
		Expect(didDoc.VerificationMethod[0].Id).To(BeEquivalentTo(keyId))
		Expect(didDoc.VerificationMethod[0].Type).To(BeEquivalentTo("Ed25519VerificationKey2020"))
		Expect(didDoc.VerificationMethod[0].Controller).To(BeEquivalentTo(did))
		Expect(didDoc.VerificationMethod[0].VerificationMaterial).To(BeEquivalentTo("{\"publicKeyMultibase\": \"" + string(pubKeyMultibase58) + "\"}"))
		Expect(didDoc.Service[0].Id).To(BeEquivalentTo(did + "#service-1"))
		Expect(didDoc.Service[0].Type).To(BeEquivalentTo("type-1"))
		Expect(didDoc.Service[0].ServiceEndpoint[0]).To(BeEquivalentTo("endpoint-1"))
		Expect(didDoc.Service[0].Accept).To(BeEquivalentTo([]string{"accept-1"}))
		Expect(didDoc.Service[0].RoutingKeys).To(BeEquivalentTo(routingKeys))

		AddReportEntry("Integration", fmt.Sprintf("%sPositive: %s", cli.GREEN, "can update diddoc"))
		// Update the DID Doc
		payload2 := types.MsgUpdateDidDocPayload{
			Id: did,
			VerificationMethod: []*types.VerificationMethod{
				{
					Id:                   keyId,
					Type:                 "Ed25519VerificationKey2020",
					Controller:           did,
					VerificationMaterial: "{\"publicKeyMultibase\": \"" + string(pubKeyMultibase58) + "\"}",
				},
			},
			Authentication: []string{keyId},
			VersionId:      uuid.NewString(),
		}

		res2, err := cli.UpdateDidDoc(tmpDir, payload2, signInputs, testdata.BASE_ACCOUNT_1)
		Expect(err).To(BeNil())
		Expect(res2.Code).To(BeEquivalentTo(0))

		AddReportEntry("Integration", fmt.Sprintf("%sPositive: %s", cli.GREEN, "can query diddoc"))
		// Query the DID Doc
		resp, err = cli.QueryDidDoc(did)
		Expect(err).To(BeNil())

		didDoc = resp.Value.DidDoc
		Expect(didDoc.Id).To(BeEquivalentTo(did))
		Expect(didDoc.Authentication).To(HaveLen(1))
		Expect(didDoc.Authentication[0]).To(BeEquivalentTo(keyId))
		Expect(didDoc.VerificationMethod).To(HaveLen(1))
		Expect(didDoc.VerificationMethod[0].Id).To(BeEquivalentTo(keyId))
		Expect(didDoc.VerificationMethod[0].Type).To(BeEquivalentTo("Ed25519VerificationKey2020"))
		Expect(didDoc.VerificationMethod[0].Controller).To(BeEquivalentTo(did))
		Expect(didDoc.VerificationMethod[0].VerificationMaterial).To(BeEquivalentTo("{\"publicKeyMultibase\": \"" + string(pubKeyMultibase58) + "\"}"))
		Expect(didDoc.Service).To(HaveLen(0))
	})
})
