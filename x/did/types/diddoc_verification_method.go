package types

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/canow-co/cheqd-node/x/did/utils"
	"github.com/canow-co/cheqd-node/x/did/utils/bls12381g2"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/mr-tron/base58"
	"github.com/multiformats/go-multibase"
)

const (
	JSONWebKey2020Type             = "JsonWebKey2020"
	Ed25519VerificationKey2020Type = "Ed25519VerificationKey2020"
	Ed25519VerificationKey2018Type = "Ed25519VerificationKey2018"
	Bls12381G2Key2020Type		   = "Bls12381G2Key2020"
)

var SupportedMethodTypes = []string{
	JSONWebKey2020Type,
	Ed25519VerificationKey2020Type,
	Ed25519VerificationKey2018Type,
	Bls12381G2Key2020Type,
}

func NewVerificationMethod(id string, vmType string, controller string, verificationMaterial string) *VerificationMethod {
	return &VerificationMethod{
		Id:                     id,
		VerificationMethodType: vmType,
		Controller:             controller,
		VerificationMaterial:   verificationMaterial,
	}
}

// Helpers

func FindVerificationMethod(vms []*VerificationMethod, id string) (*VerificationMethod, bool) {
	for _, vm := range vms {
		if vm.Id == id {
			return vm, true
		}
	}

	return &VerificationMethod{}, false
}

func GetVerificationMethodIds(vms []*VerificationMethod) []string {
	res := make([]string, len(vms))

	for i := range vms {
		res[i] = vms[i].Id
	}

	return res
}

func VerifySignature(vm VerificationMethod, message []byte, signature []byte) error {
	var verificationError error

	switch vm.VerificationMethodType {
	case Ed25519VerificationKey2020Type:

		_, multibaseBytes, err := multibase.Decode(vm.VerificationMaterial)
		if err != nil {
			return err
		}

		keyBytes := utils.GetEd25519VerificationKey2020(multibaseBytes)
		verificationError = utils.VerifyED25519Signature(keyBytes, message, signature)

	case Bls12381G2Key2020Type:
		
		_, multicodec, err := multibase.Decode(vm.VerificationMaterial)
		if err != nil {
			return err
		}

		code, codePrefixLength := binary.Uvarint(multicodec)
		if codePrefixLength <= 0 {
			return errors.New("Invalid multicodec value")
		}
		if code != bls12381g2.Bls12381G2PubCode {
			return errors.New("Not a Bls12381G2 public key")
		}

		keyBytes, err := multicodec[codePrefixLength:], nil
		if err != nil {
			return err
		}

		verificationError = utils.VerifyBLS12381G2Signature(keyBytes, message, signature)

	case JSONWebKey2020Type:
		key, err := jwk.ParseKey([]byte(vm.VerificationMaterial))
		if err != nil {
			return fmt.Errorf("can't parse jwk: %s", err.Error())
		}

		switch key.KeyType() {
		case jwa.RSA:
			var rsaPubKey rsa.PublicKey
			err := key.Raw(&rsaPubKey)
			if err != nil {
				return fmt.Errorf("can't convert jwk to %T: %s", rsaPubKey, err.Error())
			}
			verificationError = utils.VerifyRSASignature(rsaPubKey, message, signature)

		case jwa.EC:
			var ecPubKey ecdsa.PublicKey
			err := key.Raw(&ecPubKey)
			if err != nil {
				return fmt.Errorf("can't convert jwk to %T: %s", ecPubKey, err.Error())
			}
			verificationError = utils.VerifyECDSASignature(ecPubKey, message, signature)

		case jwa.OKP:
			okpPubKey := key.(jwk.OKPPublicKey)

			switch okpPubKey.Crv() {
			case jwa.Ed25519:
				var ed25519PubKey ed25519.PublicKey
				err := okpPubKey.Raw(&ed25519PubKey)
				if err != nil {
					return fmt.Errorf("can't convert jwk to %T: %s", ed25519PubKey, err.Error())
				}
				verificationError = utils.VerifyED25519Signature(ed25519PubKey, message, signature)
			case bls12381g2.Bls12381G2:
				bls12381G2PubKey := bls12381g2.PublicKey(okpPubKey.X())
				verificationError = utils.VerifyBLS12381G2Signature(bls12381G2PubKey, message, signature)
			default:
				panic("unsupported jwk cryptographic curve") // This should have been checked during basic validation
			}

		default:
			panic("unsupported jwk key type") // This should have been checked during basic validation
		}

	case Ed25519VerificationKey2018Type:
		publicKeyBytes, err := base58.Decode(vm.VerificationMaterial)
		if err != nil {
			return err
		}

		verificationError = utils.VerifyED25519Signature(publicKeyBytes, message, signature)

	default:
		panic("unsupported verification method type") // This should have also been checked during basic validation
	}

	if verificationError != nil {
		return ErrInvalidSignature.Wrapf("verification method: %s, err: %s", vm.Id, verificationError.Error())
	}

	return nil
}

func VerificationMethodListToMapByFragment(vms []*VerificationMethod) map[string]VerificationMethod {
	result := map[string]VerificationMethod{}

	for _, vm := range vms {
		_, _, _, fragment := utils.MustSplitDIDUrl(vm.Id)
		result[fragment] = *vm
	}

	return result
}

// ReplaceDids replaces ids in all fields
func (vm *VerificationMethod) ReplaceDids(old, new string) {
	// Controller
	if vm.Controller == old {
		vm.Controller = new
	}

	// Id
	vm.Id = utils.ReplaceDidInDidURL(vm.Id, old, new)
}

// Validation
func (vm VerificationMethod) Validate(baseDid string, allowedNamespaces []string) error {
	return validation.ValidateStruct(&vm,
		validation.Field(&vm.Id, validation.Required, IsSpecificDIDUrl(allowedNamespaces, Empty, Empty, Required), HasPrefix(baseDid)),
		validation.Field(&vm.Controller, validation.Required, IsDID(allowedNamespaces)),
		validation.Field(&vm.VerificationMethodType, validation.Required, validation.In(utils.ToInterfaces(SupportedMethodTypes)...)),
		validation.Field(&vm.VerificationMaterial,
			validation.When(vm.VerificationMethodType == Ed25519VerificationKey2020Type, validation.Required, IsMultibaseEd25519VerificationKey2020()),
		),
		validation.Field(&vm.VerificationMaterial,
			validation.When(vm.VerificationMethodType == Bls12381G2Key2020Type, validation.Required, ValidBls12381G2Key2020Rule()),
		),
		validation.Field(&vm.VerificationMaterial,
			validation.When(vm.VerificationMethodType == Ed25519VerificationKey2018Type, validation.Required, IsBase58Ed25519VerificationKey2018()),
		),
		validation.Field(&vm.VerificationMaterial,
			validation.When(vm.VerificationMethodType == JSONWebKey2020Type, validation.Required, IsJWK()),
		),
	)
}

func ValidVerificationMethodRule(baseDid string, allowedNamespaces []string) *CustomErrorRule {
	return NewCustomErrorRule(func(value interface{}) error {
		casted, ok := value.(VerificationMethod)
		if !ok {
			panic("ValidVerificationMethodRule must be only applied on verification methods")
		}

		return casted.Validate(baseDid, allowedNamespaces)
	})
}

func IsUniqueVerificationMethodListByIDRule() *CustomErrorRule {
	return NewCustomErrorRule(func(value interface{}) error {
		casted, ok := value.([]*VerificationMethod)
		if !ok {
			panic("IsUniqueVerificationMethodListByIDRule must be only applied on VM lists")
		}

		ids := GetVerificationMethodIds(casted)
		if !utils.IsUnique(ids) {
			return errors.New("there are verification method duplicates")
		}

		return nil
	})
}
