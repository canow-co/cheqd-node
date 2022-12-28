package utils_test

import (
	"github.com/multiformats/go-multibase"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	. "github.com/canow-co/cheqd-node/x/did/utils"
)

var _ = Describe("Crypto", func() {
	Describe("ValidateEd25519PubKey", func() {
		Context("Valid: General Ed25519 public key", func() {
			It("should return no error", func() {
				_, keyBytes, _ := multibase.Decode("zF1hVGXXK9rmx5HhMTpGnGQJiab9qrFJbQXBRhSmYjQWX")
				err := ValidateEd25519PubKey(keyBytes)
				Expect(err).To(BeNil())
			})
		})

		Context("NotValid: Bad Ed25519 public key length", func() {
			It("should return error", func() {
				_, keyBytes, _ := multibase.Decode("zF1hVGXXK9rmx5HhMTpGnGQJiab9qr1111111111111")
				err := ValidateEd25519PubKey(keyBytes)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("ed25519: bad public key length: 31"))
			})
		})
	})

	Describe("ValidateBls12381G2PubKey", func() {
		Context("Valid: General Bls12381G2 public key", func() {
			It("should return no error", func() {
				_, keyBytes, _ := multibase.Decode("zoqpWYKaZD9M1Kbe94BVXpr8WTdFBNZyKv48cziTiQUeuhm7sBhCABMyYG4kcMrseC68YTFFgyhiNeBKjzdKk9MiRWuLv5H4FFujQsQK2KTAtzU8qTBiZqBHMmnLF4PL7Ytu")
				err := ValidateBls12381G2PubKey(keyBytes)
				Expect(err).To(BeNil())
			})
		})

		Context("NotValid: Bad Bls12381G2 public key length", func() {
			It("should return error", func() {
				_, keyBytes, _ := multibase.Decode("zoqpWYKaZD9M1Kbe94BVXpr8WTdFBNZyKv48cziTiQUeuhm7sBhCABMyYG4kcMrseC68YTFFgyhiNeBKjzdKk9MiRWuLv5H4FFujQsQK222222222222222222222222222222")
				err := ValidateBls12381G2PubKey(keyBytes)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("Bls12381G2: invalid size of public key"))
			})
		})
	})

	Describe("ValidateJWKKey", func() {
		Context("Positive ed25519", func() {
			It("should return no error", func() {
				err := ValidateJWK([]byte("{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"9Ov80OqMlNrILAUG8DBBlYQ1rUhp7wDomr2I5muzpTc\"}"))
				Expect(err).To(BeNil())
			})
		})

		Context("Positive Bls12381G2", func() {
			It("should return no error", func() {
				err := ValidateJWK([]byte("{\"crv\":\"Bls12381G2\",\"kty\":\"OKP\",\"x\":\"h_rkcTKXXzRbOPr9UxSfegCbid2U_cVNXQUaKeGF7UhwrMJFP70uMH0VQ9-3-_2zDPAAjflsdeLkOXW3-ShktLxuPy8UlXSNgKNmkfb-rrj-FRwbs13pv_WsIf-eV66-\"}"))
				Expect(err).To(BeNil())
			})
		})

		Context("Positive ecdsa", func() {
			It("should return no error", func() {
				err := ValidateJWK([]byte("{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"tcEgxIPyYMiyR2_Vh_YMYG6Grg7axhK2N8JjWta5C0g\",\"y\":\"imiXD9ahVA_MKY066TrNA9r6l35lRrerP6JRey5SryQ\"}"))
				Expect(err).To(BeNil())
			})
		})

		Context("Positive rsa", func() {
			It("should return no error", func() {
				err := ValidateJWK([]byte("{\"e\":\"AQAB\",\"kty\":\"RSA\",\"n\":\"skKXRn44WN2DpXDwm4Ip25kIAGRA8y3iXlaoAhPmFiuSDkx97lXcJYrjxX0wSfehgCiSoZOBv6mFzgSVv0_pXQ6zI35xi2dsbexrc87m7Q24q2chpG33ttnVwQkoXrrm0zDzSX32EVxYQyTu9aWp-zxUdAWcrWUarT24RmgjU78v8JmUzkLmwbzsEImnIZ8Hce2ruisAmuAQBVVA4bWwQm_x1KPoQW-TP5_UR3gGugvf0XrQfMJaVpcxcJ9tduMUw6ffZOsqgbvAiZYnrezxSIjnd5lFTFBIEYdGR6ZgjYZoWvQB7U72o_TJoka-zfSODOUbxNBvxvFhA3uhoo3ZKw\"}"))
				Expect(err).To(BeNil())
			})
		})
	})
})
