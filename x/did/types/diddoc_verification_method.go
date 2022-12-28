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
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/multiformats/go-multibase"
)

var SupportedMethodTypes = []string{
	JsonWebKey2020{}.Type(),
	Ed25519VerificationKey2020{}.Type(),
	Bls12381G2Key2020{}.Type(),
}

func NewVerificationMethod(id string, type_ string, controller string, verificationMaterial string) *VerificationMethod {
	return &VerificationMethod{
		Id:                   id,
		Type:                 type_,
		Controller:           controller,
		VerificationMaterial: verificationMaterial,
	}
}

// Helpers

func FindVerificationMethod(vms []VerificationMethod, id string) (VerificationMethod, bool) {
	for _, vm := range vms {
		if vm.Id == id {
			return vm, true
		}
	}

	return VerificationMethod{}, false
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

	switch vm.Type {
	case Ed25519VerificationKey2020{}.Type():
		var ed25519VerificationKey2020 Ed25519VerificationKey2020
		err := json.Unmarshal([]byte(vm.VerificationMaterial), &ed25519VerificationKey2020)
		if err != nil {
			return sdkerrors.Wrapf(err, "failed to unmarshal verification material for %s", vm.Id)
		}

		_, keyBytes, err := multibase.Decode(ed25519VerificationKey2020.PublicKeyMultibase)
		if err != nil {
			return err
		}

		verificationError = utils.VerifyED25519Signature(keyBytes, message, signature)

	case Bls12381G2Key2020{}.Type():
		var bls12381G2Key2020 Bls12381G2Key2020
		err := json.Unmarshal([]byte(vm.VerificationMaterial), &bls12381G2Key2020)
		if err != nil {
			return sdkerrors.Wrapf(err, "failed to unmarshal verification material for %s", vm.Id)
		}

		var keyBytes bls12381g2.PublicKey

		if bls12381G2Key2020.PublicKeyMultibase != "" {
			keyBytes, err = extractKeyBytesFromBls12381G2PublicKeyMultibase(bls12381G2Key2020.PublicKeyMultibase)
		} else {
			keyBytes, err = extractKeyBytesFromBls12381G2PublicKeyJwk(bls12381G2Key2020.PublicKeyJwk)
		}

		if err != nil {
			return err
		}

		verificationError = utils.VerifyBLS12381G2Signature(keyBytes, message, signature)

	case JsonWebKey2020{}.Type():
		var jsonWebKey2020 JsonWebKey2020
		err := json.Unmarshal([]byte(vm.VerificationMaterial), &jsonWebKey2020)
		if err != nil {
			return sdkerrors.Wrapf(err, "failed to unmarshal verification material for %s", vm.Id)
		}

		key, err := jwk.ParseKey([]byte(jsonWebKey2020.PublicKeyJwk))
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
	vm.Id = utils.ReplaceDidInDidUrl(vm.Id, old, new)
}

// Validation

func (vm VerificationMethod) Validate(baseDid string, allowedNamespaces []string) error {
	return validation.ValidateStruct(&vm,
		validation.Field(&vm.Id, validation.Required, IsSpecificDIDUrl(allowedNamespaces, Empty, Empty, Required), HasPrefix(baseDid)),
		validation.Field(&vm.Controller, validation.Required, IsDID(allowedNamespaces)),
		validation.Field(&vm.Type, validation.Required, validation.In(utils.ToInterfaces(SupportedMethodTypes)...)),
		validation.Field(&vm.VerificationMaterial,
			validation.When(vm.Type == Ed25519VerificationKey2020{}.Type(), validation.Required, ValidEd25519VerificationKey2020Rule()),
		),
		validation.Field(&vm.VerificationMaterial,
			validation.When(vm.Type == Bls12381G2Key2020{}.Type(), validation.Required, ValidBls12381G2Key2020Rule()),
		),
		validation.Field(&vm.VerificationMaterial,
			validation.When(vm.Type == JsonWebKey2020{}.Type(), validation.Required, ValidJsonWebKey2020Rule()),
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

func IsUniqueVerificationMethodListByIdRule() *CustomErrorRule {
	return NewCustomErrorRule(func(value interface{}) error {
		casted, ok := value.([]*VerificationMethod)
		if !ok {
			panic("IsUniqueVerificationMethodListByIdRule must be only applied on VM lists")
		}

		ids := GetVerificationMethodIds(casted)
		if !utils.IsUnique(ids) {
			return errors.New("there are verification method duplicates")
		}

		return nil
	})
}

func extractKeyBytesFromBls12381G2PublicKeyMultibase(publicKeyMultibase string) (bls12381g2.PublicKey, error) {
	_, multicodec, err := multibase.Decode(publicKeyMultibase)
	if err != nil {
		return nil, err
	}

	code, codePrefixLength := binary.Uvarint(multicodec)
	if codePrefixLength <= 0 {
		return nil, errors.New("Invalid multicodec value")
	}
	if code != bls12381g2.Bls12381G2PubCode {
		return nil, errors.New("Not a Bls12381G2 public key")
	}

	return multicodec[codePrefixLength:], nil
}

func extractKeyBytesFromBls12381G2PublicKeyJwk(publicKeyJwk json.RawMessage) (bls12381g2.PublicKey, error) {
	key, err := jwk.ParseKey(publicKeyJwk)
	if err != nil {
		return nil, fmt.Errorf("can't parse jwk: %s", err.Error())
	}

	if key.KeyType() != jwa.OKP {
		return nil, fmt.Errorf("Bls12381G2Key2020 key type must be %s rather than %s", jwa.OKP, key.KeyType())
	}

	okpPubKey := key.(jwk.OKPPublicKey)

	if okpPubKey.Crv() != bls12381g2.Bls12381G2 {
		return nil, fmt.Errorf("Bls12381G2Key2020 curve must be %s rather than %s", bls12381g2.Bls12381G2, okpPubKey.Crv())
	}

	return okpPubKey.X(), nil
}
