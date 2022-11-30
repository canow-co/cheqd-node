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

func IsJWK() *CustomErrorRule {
	return NewCustomErrorRule(func(value interface{}) error {
		casted, ok := value.(string)
		if !ok {
			panic("IsJWK must be only applied on string properties")
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
			panic("IsSet must be only applied on string array properties")
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
			panic("IsDID must be only applied on string properties")
		}

		return utils.ValidateUUID(casted)
	})
}
