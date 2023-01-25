package types

import (
	"errors"
	"fmt"
	"strings"

	validation "github.com/go-ozzo/ozzo-validation/v4"

	"github.com/canow-co/cheqd-node/x/did/utils"
	"github.com/multiformats/go-multibase"
)

// Helper enums

type ValidationType int

const (
	Optional ValidationType = iota
	Required ValidationType = iota
	Empty    ValidationType = iota
)

// Custom error rule

var _ validation.Rule = &CustomErrorRule{}

type CustomErrorRule struct {
	fn func(value interface{}) error
}

func NewCustomErrorRule(fn func(value interface{}) error) *CustomErrorRule {
	return &CustomErrorRule{fn: fn}
}

func (c CustomErrorRule) Validate(value interface{}) error {
	return c.fn(value)
}

// Validation helpers

func IsID() *CustomErrorRule {
	return NewCustomErrorRule(func(value interface{}) error {
		casted, ok := value.(string)
		if !ok {
			panic("IsID must be only applied on string properties")
		}

		return utils.ValidateID(casted)
	})
}

func IsDID(allowedNamespaces []string) *CustomErrorRule {
	return NewCustomErrorRule(func(value interface{}) error {
		casted, ok := value.(string)
		if !ok {
			panic("IsDID must be only applied on string properties")
		}

		return utils.ValidateDID(casted, DidMethod, allowedNamespaces)
	})
}

func IsSpecificDIDUrl(allowedNamespaces []string, pathRule, queryRule, fragmentRule ValidationType) *CustomErrorRule {
	return NewCustomErrorRule(func(value interface{}) error {
		casted, ok := value.(string)
		if !ok {
			panic("IsSpecificDIDUrl must be only applied on string properties")
		}

		return validateDIDUrl(casted, DidMethod, allowedNamespaces, pathRule, queryRule, fragmentRule)
	})
}

func IsDIDUrl(method string, allowedNamespaces []string, pathRule, queryRule, fragmentRule ValidationType) *CustomErrorRule {
	return NewCustomErrorRule(func(value interface{}) error {
		casted, ok := value.(string)
		if !ok {
			panic("IsDIDUrl must be only applied on string properties")
		}

		return validateDIDUrl(casted, method, allowedNamespaces, pathRule, queryRule, fragmentRule)
	})
}

func IsValidVerificationMethodReference(sharedVerificationMethods []*VerificationMethod) *CustomErrorRule {
	return NewCustomErrorRule(func(value interface{}) error {
		casted, ok := value.(string)
		if !ok {
			panic("IsValidVerificationMethodReference must be only applied on string properties")
		}

		return validateVerificationMethodReference(casted, sharedVerificationMethods)
	})
}

func IsURI() *CustomErrorRule {
	return NewCustomErrorRule(func(value interface{}) error {
		casted, ok := value.(string)
		if !ok {
			panic("IsURI must be only applied on string properties")
		}

		return utils.ValidateURI(casted)
	})
}

func IsMultibase() *CustomErrorRule {
	return NewCustomErrorRule(func(value interface{}) error {
		casted, ok := value.(string)
		if !ok {
			panic("IsMultibase must be only applied on string properties")
		}

		return utils.ValidateMultibase(casted)
	})
}

func IsMultibaseEd25519VerificationKey2020() *CustomErrorRule {
	return NewCustomErrorRule(func(value interface{}) error {
		casted, ok := value.(string)
		if !ok {
			panic("IsMultibaseEd25519VerificationKey2020 must be only applied on string properties")
		}

		return utils.ValidateMultibaseEd25519VerificationKey2020(casted)
	})
}

func IsMultibaseBls12381G2Key2020Rule() *CustomErrorRule {
	return NewCustomErrorRule(func(value interface{}) error {
		casted, ok := value.(string)
		if !ok {
			panic("ValidBls12381G2Key2020Rule must be only applied on string properties")
		}

		return utils.ValidateMultibaseMulticodecBls12381G2PubKey(casted)
	})
}

func IsBase58Ed25519VerificationKey2018() *CustomErrorRule {
	return NewCustomErrorRule(func(value interface{}) error {
		casted, ok := value.(string)
		if !ok {
			panic("IsBase58Ed25519VerificationKey2018 must be only applied on string properties")
		}

		return utils.ValidateBase58Ed25519VerificationKey2018(casted)
	})
}

func IsMultibaseEncodedEd25519PubKey() *CustomErrorRule {
	return NewCustomErrorRule(func(value interface{}) error {
		casted, ok := value.(string)
		if !ok {
			panic("IsMultibaseEncodedEd25519PubKey must be only applied on string properties")
		}

		_, keyBytes, err := multibase.Decode(casted)
		if err != nil {
			return err
		}

		err = utils.ValidateEd25519PubKey(keyBytes)
		if err != nil {
			return err
		}

		return nil
	})
}

func IsMultibaseMulticodecBls12381G2PubKey() *CustomErrorRule {
	return NewCustomErrorRule(func(value interface{}) error {
		casted, ok := value.(string)
		if !ok {
			panic("IsMultibaseMulticodecBls12381G2PubKey must be only applied on string properties")
		}

		return utils.ValidateMultibaseMulticodecBls12381G2PubKey(casted)
	})
}

func IsJWK() *CustomErrorRule {
	return NewCustomErrorRule(func(value interface{}) error {
		casted, ok := value.([]byte)
		if !ok {
			panic("IsJWK must be only applied on byte array properties")
		}

		return utils.ValidateJWK(casted)
	})
}

func HasPrefix(prefix string) *CustomErrorRule {
	return NewCustomErrorRule(func(value interface{}) error {
		casted, ok := value.(string)
		if !ok {
			panic("HasPrefix must be only applied on string properties")
		}

		if !strings.HasPrefix(casted, prefix) {
			return fmt.Errorf("must have prefix: %s", prefix)
		}

		return nil
	})
}

func IsUniqueStrList() *CustomErrorRule {
	return NewCustomErrorRule(func(value interface{}) error {
		casted, ok := value.([]string)
		if !ok {
			panic("IsUniqueStrList must be only applied on string array properties")
		}

		if !utils.IsUnique(casted) {
			return errors.New("there should be no duplicates")
		}

		return nil
	})
}

func IsUUID() *CustomErrorRule {
	return NewCustomErrorRule(func(value interface{}) error {
		casted, ok := value.(string)
		if !ok {
			panic("IsUUID must be only applied on string properties")
		}

		return utils.ValidateUUID(casted)
	})
}

func validateDIDUrl(did string, method string, allowedNamespaces []string, pathRule, queryRule, fragmentRule ValidationType) error {
	if err := utils.ValidateDIDUrl(did, method, allowedNamespaces); err != nil {
		return err
	}

	_, path, query, fragment, err := utils.TrySplitDIDUrl(did)
	if err != nil {
		return err
	}

	if pathRule == Required && path == "" {
		return errors.New("path is required")
	}

	if pathRule == Empty && path != "" {
		return errors.New("path must be empty")
	}

	if queryRule == Required && query == "" {
		return errors.New("query is required")
	}

	if queryRule == Empty && query != "" {
		return errors.New("query must be empty")
	}

	if fragmentRule == Required && fragment == "" {
		return errors.New("fragment is required")
	}

	if fragmentRule == Empty && fragment != "" {
		return errors.New("fragment must be empty")
	}

	return nil
}

func validateVerificationMethodReference(verificationMethodReference string, sharedVerificationMethods []*VerificationMethod) error {
	_, found := FindVerificationMethod(sharedVerificationMethods, verificationMethodReference)
	if !found {
		return fmt.Errorf("can't resolve verification method reference: %s", verificationMethodReference)
	}

	return nil
}
