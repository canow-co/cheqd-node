package cli

import (
	"encoding/json"

	"github.com/canow-co/cheqd-node/x/did/types"
	"github.com/canow-co/cheqd-node/x/did/utils"
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/client/tx"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

func CmdCreateDidDoc() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create-did [payload-file] --version-id [version-id]",
		Short: "Create a new DID and associated DID Document.",
		Long: `Creates a new DID and associated DID Document.
[payload-file] is JSON encoded DID Document alongside with sign inputs.
Version ID is optional and is determined by the '--version-id' flag.
If not provided, a random UUID will be used as version-id.

NOTES:
1. Fee used for the transaction will ALWAYS take the fixed fee for DID Document creation, REGARDLESS of what value is passed in '--fees' flag.
2. Payload file should be a JSON file containing properties specified in the DID Core Specification. Rules from DID Core spec are followed on which properties are mandatory and which ones are optional.
3. Private key provided in sign inputs is ONLY used locally to generate signature(s) and not sent to the ledger.

Example payload file:
{
    "payload": {
        "context": [ "https://www.w3.org/ns/did/v1" ],
        "id": "did:canow:<namespace>:<unique-identifier>",
        "controller": [
            "did:canow:<namespace>:<unique-identifier>"
        ],
        "authentication": [
            "did:canow:<namespace>:<unique-identifier>#<key-id>"
        ],
        "assertionMethod": [],
        "capabilityInvocation": [],
        "capabilityDelegation": [],
        "keyAgreement": [],
        "alsoKnownAs": [],
        "verificationMethod": [
            {
                "id": "did:canow:<namespace>:<unique-identifier>#<key-id>",
                "type": "<verification-method-type>",
                "controller": "did:canow:<namespace>:<unique-identifier>",
                "publicKeyMultibase": "<public-key>"
            }
        ],
        "service": [
			{
                "id": "did:canow:<namespace>:<unique-identifier>#<service-id>",
                "type": "<service-type>",
                "serviceEndpoint": [
                    "<service-endpoint>"
                ]
            }
		]
    },
	"signInputs": [
        {
            "verificationMethodId": "did:canow:<namespace>:<unique-identifier>#<key-id>",
            "privKey": "<private-key-bytes-encoded-to-base64>"
        }
    ]
}
`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}

			payloadFile := args[0]
			versionID, err := cmd.Flags().GetString(FlagVersionID)
			if err != nil {
				return err
			}

			if versionID != "" {
				err = utils.ValidateUUID(versionID)
				if err != nil {
					return err
				}
			} else {
				versionID = uuid.NewString()
			}

			payloadJSON, signInputs, err := ReadPayloadWithSignInputsFromFile(payloadFile)
			if err != nil {
				return err
			}

			// Unmarshal spec-compliant payload
			var specPayload DIDDocument
			err = json.Unmarshal([]byte(payloadJSON), &specPayload)
			if err != nil {
				return err
			}

			// Validate spec-compliant payload & get verification methods
			verificationMethod, service, err := GetFromSpecCompliantPayload(specPayload)
			if err != nil {
				return err
			}

			authentication, err := GetMixedVerificationMethodList(specPayload.Authentication)
			if err != nil {
				return err
			}
			assertionMethod, err := GetMixedVerificationMethodList(specPayload.AssertionMethod)
			if err != nil {
				return err
			}
			capabilityInvocation, err := GetMixedVerificationMethodList(specPayload.CapabilityInvocation)
			if err != nil {
				return err
			}
			capabilityDelegation, err := GetMixedVerificationMethodList(specPayload.CapabilityDelegation)
			if err != nil {
				return err
			}
			keyAgreement, err := GetMixedVerificationMethodList(specPayload.KeyAgreement)
			if err != nil {
				return err
			}

			// Construct MsgCreateDidDocPayload
			payload := types.MsgCreateDidDocPayload{
				Context:              specPayload.Context,
				Id:                   specPayload.ID,
				Controller:           specPayload.Controller,
				VerificationMethod:   verificationMethod,
				Authentication:       authentication,
				AssertionMethod:      assertionMethod,
				CapabilityInvocation: capabilityInvocation,
				CapabilityDelegation: capabilityDelegation,
				KeyAgreement:         keyAgreement,
				Service:              service,
				AlsoKnownAs:          specPayload.AlsoKnownAs,
				VersionId:            versionID,
			}

			// Build identity message
			signBytes := payload.GetSignBytes()
			identitySignatures := SignWithSignInputs(signBytes, signInputs)

			msg := types.MsgCreateDidDoc{
				Payload:    &payload,
				Signatures: identitySignatures,
			}

			// Set fee-payer if not set
			err = SetFeePayerFromSigner(&clientCtx)
			if err != nil {
				return err
			}

			return tx.GenerateOrBroadcastTxCLI(clientCtx, cmd.Flags(), &msg)
		},
	}

	// add standard tx flags
	AddTxFlagsToCmd(cmd)

	// add custom / override flags
	cmd.Flags().String(FlagVersionID, "", "Version ID of the DID Document")
	cmd.Flags().String(flags.FlagFees, sdk.NewCoin(types.BaseMinimalDenom, sdk.NewInt(types.DefaultCreateDidTxFee)).String(), "Fixed fee for DID creation, e.g., 50000000000ncheq. Please check what the current fees are by running 'cheqd-noded query params subspace cheqd feeparams'")

	_ = cmd.MarkFlagRequired(flags.FlagFees)
	_ = cmd.MarkFlagRequired(flags.FlagGas)
	_ = cmd.MarkFlagRequired(flags.FlagGasAdjustment)

	return cmd
}
