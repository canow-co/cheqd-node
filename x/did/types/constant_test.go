package types_test

import (
	"encoding/json"
)

var (
	ValidTestDID   = "did:canow:testnet:zABCDEFG123456789abcd"
	ValidTestDID2  = "did:canow:testnet:zABCDEFG987654321abcd"
	InvalidTestDID = "badDid"
)

var (
	ValidEd25519PublicKeyMultibase      = "zF1hVGXXK9rmx5HhMTpGnGQJiab9qrFJbQXBRhSmYjQWX"
	ValidBls12381G2PublicKeyMultibase   = "zUC73gNPc1EnZmDDjYJzE8Bk89VRhuZPQYXFnSiSUZvX9N1i7N5VtMbJyowDR46rtARHLJYRVf7WMbGLb43s9tfTyKF9KFF22vBjXZRomcwtoQJmMNUSY7tfzyhLEy58dwUz3WD"
	InvalidEd25519PublicKeyMultibase    = "zF1hVGXXK9rmx5HhMTpGnGQJi"
	InvalidBls12381G2PublicKeyMultibase = "zUC73gNPc1EnZmDDjYJzE8Bk89VRhuZPQYXFnSiSUZvX9N1i7N5VtMbJyowDR46rtARHLJYRVf7WMbGLb43s9tfTyKF9KFF22vBjXZRomcwtoQJmMNUSY7t"
)

type TestJWK struct {
	Kty string `json:"kty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	Kid string `json:"kid,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
}

var ValidJWK = TestJWK{
	Kty: "RSA",
	N:   "o76AudS2rsCvlz_3D47sFkpuz3NJxgLbXr1cHdmbo9xOMttPMJI97f0rHiSl9stltMi87KIOEEVQWUgMLaWQNaIZThgI1seWDAGRw59AO5sctgM1wPVZYt40fj2Qw4KT7m4RLMsZV1M5NYyXSd1lAAywM4FT25N0RLhkm3u8Hehw2Szj_2lm-rmcbDXzvjeXkodOUszFiOqzqBIS0Bv3c2zj2sytnozaG7aXa14OiUMSwJb4gmBC7I0BjPv5T85CH88VOcFDV51sO9zPJaBQnNBRUWNLh1vQUbkmspIANTzj2sN62cTSoxRhSdnjZQ9E_jraKYEW5oizE9Dtow4EvQ",
	Use: "sig",
	Alg: "RS256",
	E:   "AQAB",
	Kid: "6a8ba5652a7044121d4fedac8f14d14c54e4895b",
}

// Example from https://www.rfc-editor.org/rfc/rfc7517#appendix-A.1
var ValidEcJWK = TestJWK{
	Kty: "EC",
	Crv: "P-256",
	X:   "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
	Y:   "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
	Use: "enc",
	Kid: "1",
}

// Example from https://www.rfc-editor.org/rfc/rfc7517#appendix-A.1
var ValidRsaJWK = TestJWK{
	Kty: "RSA",
	N:   "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
	E:   "AQAB",
	Alg: "RS256",
	Kid: "2011-04-29",
}

// Example from https://www.rfc-editor.org/rfc/rfc8037#appendix-A.2
var ValidEd25519JWK = TestJWK{
	Kty: "OKP",
	Crv: "Ed25519",
	X:   "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
}

// Based on example from https://www.ietf.org/archive/id/draft-ietf-cose-bls-key-representations-01.html#name-appendix
var ValidBls12381G2JWK = TestJWK{
	Kty: "OKP",
	Crv: "Bls12381G2",
	X:   "rvdKcdkxwlj0Y-XZsFpz1hDPJGjnLN27IJipbmaLlaKdYfICGG6dzakG6EkdcvW0AtVV6hXBSKtdFnKQKmmD759tMYYuvKYf5o2cZnROLN5iWQ2H6vp6FlLi71a_AE5I",
}

var InvalidJWK = TestJWK{
	Kty: "SomeOtherKeyType",
	N:   "o76AudS2rsCvlz_3D47sFkpuz3NJxgLbXr1cHdmbo9xOMttPMJI97f0rHiSl9stltMi87KIOEEVQWUgMLaWQNaIZThgI1seWDAGRw59AO5sctgM1wPVZYt40fj2Qw4KT7m4RLMsZV1M5NYyXSd1lAAywM4FT25N0RLhkm3u8Hehw2Szj_2lm-rmcbDXzvjeXkodOUszFiOqzqBIS0Bv3c2zj2sytnozaG7aXa14OiUMSwJb4gmBC7I0BjPv5T85CH88VOcFDV51sO9zPJaBQnNBRUWNLh1vQUbkmspIANTzj2sN62cTSoxRhSdnjZQ9E_jraKYEW5oizE9Dtow4EvQ",
	Use: "sig",
	Alg: "RS256",
	E:   "AQAB",
	Kid: "6a8ba5652a7044121d4fedac8f14d14c54e4895b",
}

var InvalidOkpJWK = TestJWK{
	Kty: "OKP",
	Crv: "SomeOtherCurve",
	X:   "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
}

var (
	ValidPublicKeyJWK, _           = json.Marshal(ValidJWK)
	ValidEcPublicKeyJWK, _         = json.Marshal(ValidEcJWK)
	ValidRsaPublicKeyJWK, _        = json.Marshal(ValidRsaJWK)
	ValidEd25519PublicKeyJWK, _    = json.Marshal(ValidEd25519JWK)
	ValidBls12381G2PublicKeyJWK, _ = json.Marshal(ValidBls12381G2JWK)
	InvalidPublicKeyJWK, _         = json.Marshal(InvalidJWK)
	InvalidOkpPublicKeyJWK, _      = json.Marshal(InvalidOkpJWK)
)

var (
	// bytes in hex: ed01c92d1e8f9cfa03f63be3489accb0c2704bb7da3f2e4e94509d8ff9202d564c12
	ValidEd25519VerificationKey2020VerificationMaterial = "z6MkszZtxCmA2Ce4vUV132PCuLQmwnaDD5mw2L23fGNnsiX3"

	// bytes in hex: 020076a50fe5e0c3616c1b4d85a308c104a1c99d8d3d92c18c1f4e0179202d564c12
	InvalidEd25519VerificationKey2020VerificationMaterialBadPrefix = "z3dEYJrMxWigf9boyeJMTRN4Ern8DJMoCXaLK77pzQmxVjf"

	// bytes in hex: ed01c92d1e8f9cfa03f63be3489accb0c2704bb7da3f2e4e94509d8ff9
	InvalidEd25519VerificationKey2020VerificationMaterialBadlength = "zBm3emgJHyjidq7HsZFTx3PCjYHayy7SxisBeVCa4"

	// bytes in hex: 0a04f18e1a12b6af626bde47be47a1800d211712af9e2c0fd43990c7073121ce
	ValidEd25519VerificationKey2018VerificationMaterial = "g7T3moSG5mwFvazr5gi8AyUETXTkZ9E6PZxAZVhWN93"

	// bytes in hex: 2c392158b9b3b3935a22ba9dc371211ab58939b39461dcf66aec6d5cd04b9e
	InvalidEd25519VerificationKey2018VerificationMaterialBadLength = "g7T3moSG5mwFvazr5gi8AyUETXTkZ9E6PZxAZVhWN9"

	ValidJWK2020VerificationMaterial   = string(ValidPublicKeyJWK)
	InvalidJWK2020VerificationMaterial = string(InvalidPublicKeyJWK)
)

var (
	ValidEd25519MultibaseVerificationMaterial      = ValidEd25519PublicKeyMultibase
	ValidBls12381G2MultibaseVerificationMaterial   = ValidBls12381G2PublicKeyMultibase
	InvalidEd25519MultibaseVerificationMaterial    = InvalidEd25519PublicKeyMultibase
	InvalidBls12381G2MultibaseVerificationMaterial = InvalidBls12381G2PublicKeyMultibase
)

var (
	ValidJwkVerificationMaterial           = string(ValidPublicKeyJWK)
	ValidEcJwkVerificationMaterial         = string(ValidEcPublicKeyJWK)
	ValidRsaJwkVerificationMaterial        = string(ValidRsaPublicKeyJWK)
	ValidEd25519JwkVerificationMaterial    = string(ValidEd25519PublicKeyJWK)
	ValidBls12381G2JwkVerificationMaterial = string(ValidBls12381G2PublicKeyJWK)
	InvalidJwkVerificationMaterial         = string(InvalidPublicKeyJWK)
	InvalidOkpJwkVerificationMaterial      = string(InvalidOkpPublicKeyJWK)
)
