package types_test

import (
	"encoding/json"
)

var (
	ValidTestDID         = "did:canow:testnet:zABCDEFG123456789abcd"
	ValidTestDID2        = "did:canow:testnet:zABCDEFG987654321abcd"
	InvalidTestDID       = "badDid"
	ValidEd25519PubKey   = "zF1hVGXXK9rmx5HhMTpGnGQJiab9qrFJbQXBRhSmYjQWX"
	InvalidEd25519PubKey = "zF1hVGXXK9rmx5HhMTpGnGQJi"
)

type TestJWKKey struct {
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

var ValidJWKKey = TestJWKKey{
	Kty: "RSA",
	N:   "o76AudS2rsCvlz_3D47sFkpuz3NJxgLbXr1cHdmbo9xOMttPMJI97f0rHiSl9stltMi87KIOEEVQWUgMLaWQNaIZThgI1seWDAGRw59AO5sctgM1wPVZYt40fj2Qw4KT7m4RLMsZV1M5NYyXSd1lAAywM4FT25N0RLhkm3u8Hehw2Szj_2lm-rmcbDXzvjeXkodOUszFiOqzqBIS0Bv3c2zj2sytnozaG7aXa14OiUMSwJb4gmBC7I0BjPv5T85CH88VOcFDV51sO9zPJaBQnNBRUWNLh1vQUbkmspIANTzj2sN62cTSoxRhSdnjZQ9E_jraKYEW5oizE9Dtow4EvQ",
	Use: "sig",
	Alg: "RS256",
	E:   "AQAB",
	Kid: "6a8ba5652a7044121d4fedac8f14d14c54e4895b",
}

// Example from https://www.rfc-editor.org/rfc/rfc7517#appendix-A.1
var EcJWKKey = TestJWKKey{
	Kty: "EC",
	Crv: "P-256",
	X:   "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
	Y:   "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
	Use: "enc",
	Kid: "1",
}

// Example from https://www.rfc-editor.org/rfc/rfc7517#appendix-A.1
var RsaJWKKey = TestJWKKey{
	Kty: "RSA",
	N:   "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
	E:   "AQAB",
	Alg: "RS256",
	Kid: "2011-04-29",
}

// Example from https://www.rfc-editor.org/rfc/rfc8037#appendix-A.2
var Ed25519JWKKey = TestJWKKey{
	Kty: "OKP",
	Crv: "Ed25519",
	X:   "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
}

// Based on example from https://www.ietf.org/archive/id/draft-ietf-cose-bls-key-representations-01.html#name-appendix
var Bls12381G2JWKKey = TestJWKKey{
	Kty: "OKP",
	Crv: "Bls12381G2",
	X:   "rvdKcdkxwlj0Y-XZsFpz1hDPJGjnLN27IJipbmaLlaKdYfICGG6dzakG6EkdcvW0AtVV6hXBSKtdFnKQKmmD759tMYYuvKYf5o2cZnROLN5iWQ2H6vp6FlLi71a_AE5I",
}

var InvalidJWKKey = TestJWKKey{
	Kty: "SomeOtherKeyType",
	N:   "o76AudS2rsCvlz_3D47sFkpuz3NJxgLbXr1cHdmbo9xOMttPMJI97f0rHiSl9stltMi87KIOEEVQWUgMLaWQNaIZThgI1seWDAGRw59AO5sctgM1wPVZYt40fj2Qw4KT7m4RLMsZV1M5NYyXSd1lAAywM4FT25N0RLhkm3u8Hehw2Szj_2lm-rmcbDXzvjeXkodOUszFiOqzqBIS0Bv3c2zj2sytnozaG7aXa14OiUMSwJb4gmBC7I0BjPv5T85CH88VOcFDV51sO9zPJaBQnNBRUWNLh1vQUbkmspIANTzj2sN62cTSoxRhSdnjZQ9E_jraKYEW5oizE9Dtow4EvQ",
	Use: "sig",
	Alg: "RS256",
	E:   "AQAB",
	Kid: "6a8ba5652a7044121d4fedac8f14d14c54e4895b",
}

var InvalidOkpJWKKey = TestJWKKey{
	Kty: "OKP",
	Crv: "SomeOtherCurve",
	X:   "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
}

var (
	ValidPublicKeyJWK, _      = json.Marshal(ValidJWKKey)
	EcPublicKeyJWK, _         = json.Marshal(EcJWKKey)
	RsaPublicKeyJWK, _        = json.Marshal(RsaJWKKey)
	Ed25519PublicKeyJWK, _    = json.Marshal(Ed25519JWKKey)
	Bls12381G2PublicKeyJWK, _ = json.Marshal(Bls12381G2JWKKey)
	InvalidPublicKeyJWK, _    = json.Marshal(InvalidJWKKey)
	InvalidOkpPublicKeyJWK, _ = json.Marshal(InvalidOkpJWKKey)
)

var (
	ValidEd25519VerificationMaterial   = "{\"publicKeyMultibase\":\"" + ValidEd25519PubKey + "\"}"
	InvalidEd25519VerificationMaterial = "{\"publicKeyMultibase\":\"" + InvalidEd25519PubKey + "\"}"

	ValidJWKKeyVerificationMaterial      = "{\"publicKeyJwk\":" + string(ValidPublicKeyJWK) + "}"
	EcJWKKeyVerificationMaterial         = "{\"publicKeyJwk\":" + string(EcPublicKeyJWK) + "}"
	RsaJWKKeyVerificationMaterial        = "{\"publicKeyJwk\":" + string(RsaPublicKeyJWK) + "}"
	Ed25519JWKKeyVerificationMaterial    = "{\"publicKeyJwk\":" + string(Ed25519PublicKeyJWK) + "}"
	Bls12381G2JWKKeyVerificationMaterial = "{\"publicKeyJwk\":" + string(Bls12381G2PublicKeyJWK) + "}"
	InvalidJWKKeyVerificationMaterial    = "{\"publicKeyJwk\":" + string(InvalidPublicKeyJWK) + "}"
	InvalidOkpJWKKeyVerificationMaterial = "{\"publicKeyJwk\":" + string(InvalidOkpPublicKeyJWK) + "}"
)
