package types

import (
	"encoding/json"

	validation "github.com/go-ozzo/ozzo-validation/v4"
)

type VerificationMaterial interface {
	Type() string
	Validate() error
}

// Ed25519VerificationKey2020

type Ed25519VerificationKey2020 struct {
	PublicKeyMultibase string `json:"publicKeyMultibase"`
}

var _ VerificationMaterial = (*Ed25519VerificationKey2020)(nil)

func (vm Ed25519VerificationKey2020) Type() string {
	return "Ed25519VerificationKey2020"
}

func (vm Ed25519VerificationKey2020) Validate() error {
	return validation.ValidateStruct(&vm,
		validation.Field(&vm.PublicKeyMultibase, validation.Required, IsMultibase(), IsMultibaseEncodedEd25519PubKey()),
	)
}

// Bls12381G2Key2020

type Bls12381G2Key2020 struct {
	PublicKeyMultibase string `json:"publicKeyMultibase"`
}

var _ VerificationMaterial = (*Bls12381G2Key2020)(nil)

func (vm Bls12381G2Key2020) Type() string {
	return "Bls12381G2Key2020"
}

func (vm Bls12381G2Key2020) Validate() error {
	return validation.ValidateStruct(&vm,
		validation.Field(&vm.PublicKeyMultibase, validation.Required, IsMultibase(), IsMultibaseMulticodecBls12381G2PubKey()),
	)
}

// JsonWebKey2020

type JsonWebKey2020 struct {
	PublicKeyJwk json.RawMessage `json:"publicKeyJwk"`
}

var _ VerificationMaterial = (*JsonWebKey2020)(nil)

func (vm JsonWebKey2020) Type() string {
	return "JsonWebKey2020"
}

func (vm JsonWebKey2020) Validate() error {
	return validation.Validate([]byte(vm.PublicKeyJwk), validation.Required, IsJWK())
}

// Validation

func ValidEd25519VerificationKey2020Rule() *CustomErrorRule {
	return NewCustomErrorRule(func(value interface{}) error {
		casted, ok := value.(string)
		if !ok {
			panic("ValidEd25519VerificationKey2020Rule must be only applied on string properties")
		}

		var vm Ed25519VerificationKey2020
		err := json.Unmarshal([]byte(casted), &vm)
		if err != nil {
			return err
		}

		return vm.Validate()
	})
}

func ValidBls12381G2Key2020Rule() *CustomErrorRule {
	return NewCustomErrorRule(func(value interface{}) error {
		casted, ok := value.(string)
		if !ok {
			panic("ValidBls12381G2Key2020Rule must be only applied on string properties")
		}

		var vm Bls12381G2Key2020
		err := json.Unmarshal([]byte(casted), &vm)
		if err != nil {
			return err
		}

		return vm.Validate()
	})
}

func ValidJsonWebKey2020Rule() *CustomErrorRule {
	return NewCustomErrorRule(func(value interface{}) error {
		casted, ok := value.(string)
		if !ok {
			panic("ValidJsonWebKey2020Rule must be only applied on string properties")
		}

		var vm JsonWebKey2020
		err := json.Unmarshal([]byte(casted), &vm)
		if err != nil {
			return err
		}

		return vm.Validate()
	})
}
