package types_test

import (
	. "github.com/canow-co/cheqd-node/x/did/types"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type VerificationMaterialTestCase struct {
	vm       VerificationMaterial
	isValid  bool
	errorMsg string
}

var _ = DescribeTable("Verification Method material validation tests", func(testCase VerificationMaterialTestCase) {
	err := testCase.vm.Validate()

	if testCase.isValid {
		Expect(err).To(BeNil())
	} else {
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring(testCase.errorMsg))
	}
},

	Entry(
		"Valid Ed25519VerificationKey2020 verification material",
		VerificationMaterialTestCase{
			vm: Ed25519VerificationKey2020{
				PublicKeyMultibase: ValidEd25519PublicKeyMultibase,
			},
			isValid:  true,
			errorMsg: "",
		}),

	Entry(
		"Valid Bls12381G2Key2020 verification material (publicKeyJwk)",
		VerificationMaterialTestCase{
			vm: Bls12381G2Key2020{
				PublicKeyJwk: ValidBls12381G2PublicKeyJwk,
			},
			isValid:  true,
			errorMsg: "",
		}),

	Entry(
		"Valid EC JsonWebKey2020 verification material",
		VerificationMaterialTestCase{
			vm: JsonWebKey2020{
				PublicKeyJwk: ValidEcPublicKeyJwk,
			},
			isValid:  true,
			errorMsg: "",
		}),

	Entry(
		"Valid RSA JsonWebKey2020 verification material",
		VerificationMaterialTestCase{
			vm: JsonWebKey2020{
				PublicKeyJwk: ValidRsaPublicKeyJwk,
			},
			isValid:  true,
			errorMsg: "",
		}),

	Entry(
		"Valid Ed25519 JsonWebKey2020 verification material",
		VerificationMaterialTestCase{
			vm: JsonWebKey2020{
				PublicKeyJwk: ValidEd25519PublicKeyJwk,
			},
			isValid:  true,
			errorMsg: "",
		}),

	Entry(
		"Valid Bls12381G2 JsonWebKey2020 verification material",
		VerificationMaterialTestCase{
			vm: JsonWebKey2020{
				PublicKeyJwk: ValidBls12381G2PublicKeyJwk,
			},
			isValid:  true,
			errorMsg: "",
		}),

	Entry(
		"Invalid Ed25519VerificationKey2020 verification material",
		VerificationMaterialTestCase{
			vm: Ed25519VerificationKey2020{
				PublicKeyMultibase: InvalidEd25519PublicKeyMultibase,
			},
			isValid:  false,
			errorMsg: "publicKeyMultibase: ed25519: bad public key length: 18",
		}),

	Entry(
		"Invalid Bls12381G2Key2020 verification material (neither publicKeyMultibase, nor publicKeyJwk is set)",
		VerificationMaterialTestCase{
			vm:       Bls12381G2Key2020{},
			isValid:  false,
			errorMsg: "One of publicKeyMultibase or publicKeyJwk must be set for Bls12381G2Key2020",
		}),

	Entry(
		"Invalid Bls12381G2Key2020 verification material (publicKeyJwk)",
		VerificationMaterialTestCase{
			vm: Bls12381G2Key2020{
				PublicKeyJwk: ValidEd25519PublicKeyJwk, // Ed25519 instead of Bls12381G2
			},
			isValid:  false,
			errorMsg: "Bls12381G2Key2020 curve must be Bls12381G2 rather than Ed25519",
		}),

	Entry(
		"Invalid JsonWebKey2020 verification material",
		VerificationMaterialTestCase{
			vm: JsonWebKey2020{
				PublicKeyJwk: InvalidPublicKeyJwk,
			},
			isValid:  false,
			errorMsg: "can't parse jwk: invalid key type from JSON (SomeOtherKeyType)",
		}),

	Entry(
		"Invalid OKP JsonWebKey2020 verification material",
		VerificationMaterialTestCase{
			vm: JsonWebKey2020{
				PublicKeyJwk: InvalidOkpPublicKeyJwk,
			},
			isValid:  false,
			errorMsg: "unsupported jwk cryptographic curve: SomeOtherCurve. supported curves are: Ed25519, Bls12381G2",
		}),
)
