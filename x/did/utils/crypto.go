package utils

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"fmt"

	"filippo.io/edwards25519"

	"github.com/canow-co/cheqd-node/x/did/utils/bls12381g2"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/primitive/bbs12381g2pub"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/multiformats/go-multibase"
)

func ValidateJWK(rawJwk []byte) error {
	key, err := jwk.ParseKey(rawJwk)
	if err != nil {
		return fmt.Errorf("can't parse jwk: %s", err.Error())
	}

	switch key.KeyType() {
	case jwa.RSA:
		break
	case jwa.EC:
		break
	case jwa.OKP:
		okpPubKey, ok := key.(jwk.OKPPublicKey)
		if !ok {
			return errors.New("jwk with kty=\"OKP\" is not actually OKP public key")
		}

		switch okpPubKey.Crv() {
		case jwa.Ed25519:
			var ed25519PubKey ed25519.PublicKey
			err := okpPubKey.Raw(&ed25519PubKey)
			if err != nil {
				return fmt.Errorf("can't convert jwk to %T: %s", ed25519PubKey, err.Error())
			}
			err = ValidateEd25519PubKey(ed25519PubKey)
			if err != nil {
				return err
			}

		case bls12381g2.Bls12381G2:
			bls12381G2PubKey := bls12381g2.PublicKey(okpPubKey.X())
			err := ValidateBls12381G2PubKey(bls12381G2PubKey)
			if err != nil {
				return err
			}

		default:
			return fmt.Errorf("unsupported jwk cryptographic curve: %s. supported curves are: Ed25519, Bls12381G2", okpPubKey.Crv())
		}
	default:
		return fmt.Errorf("unsupported jwk key type: %s. supported key types are: RSA/pub, EC/pub, OKP/pub", key.KeyType())
	}

	return nil
}

func ValidateEd25519PubKey(keyBytes []byte) error {
	if l := len(keyBytes); l != ed25519.PublicKeySize {
		return fmt.Errorf("ed25519: bad public key length: %d", l)
	}
	_, err := (&edwards25519.Point{}).SetBytes(keyBytes)
	if err != nil {
		return err
	}
	return nil
}

func ValidateMultibaseEncodedBls12381G2PubKey(key string) error {
	_, multicodec, err := multibase.Decode(key)
	if err != nil {
		return err
	}

	code, codePrefixLength := binary.Uvarint(multicodec)
	if codePrefixLength < 0 {
		return errors.New("Invalid multicodec value")
	}
	if code != bls12381g2.Bls12381G2PubCode {
		return errors.New("Not a Bls12381G2 public key")
	}

	keyBytes := multicodec[codePrefixLength:]

	return ValidateBls12381G2PubKey(keyBytes)
}

func ValidateBls12381G2PubKeyJwk(rawJwk []byte) error {
	key, err := jwk.ParseKey(rawJwk)
	if err != nil {
		return fmt.Errorf("can't parse jwk: %s", err.Error())
	}

	if key.KeyType() != jwa.OKP {
		return fmt.Errorf("Bls12381G2Key2020 key type must be %s rather than %s", jwa.OKP, key.KeyType())
	}

	okpPubKey, ok := key.(jwk.OKPPublicKey)
	if !ok {
		return errors.New("jwk with kty=\"OKP\" is not actually OKP public key")
	}

	if okpPubKey.Crv() != bls12381g2.Bls12381G2 {
		return fmt.Errorf("Bls12381G2Key2020 curve must be %s rather than %s", bls12381g2.Bls12381G2, okpPubKey.Crv())
	}

	bls12381G2PubKey := bls12381g2.PublicKey(okpPubKey.X())
	return ValidateBls12381G2PubKey(bls12381G2PubKey)
}

func ValidateBls12381G2PubKey(keyBytes []byte) error {
	_, err := bbs12381g2pub.UnmarshalPublicKey(keyBytes)
	if err != nil {
		return fmt.Errorf("Bls12381G2: %s", err.Error())
	}
	return nil
}

func VerifyED25519Signature(pubKey ed25519.PublicKey, message []byte, signature []byte) error {
	valid := ed25519.Verify(pubKey, message, signature)
	if !valid {
		return errors.New("invalid ed25519 signature")
	}

	return nil
}

func VerifyBLS12381G2Signature(pubKey bls12381g2.PublicKey, message []byte, signature []byte) error {
	messages := [][]byte{message}

	err := bbs12381g2pub.New().Verify(messages, signature, pubKey)
	if err != nil {
		return err
	}
	return nil
}

// VerifyRSASignature uses PSS padding and SHA256 digest
// A good explanation of different paddings: https://security.stackexchange.com/questions/183179/what-is-rsa-oaep-rsa-pss-in-simple-terms
func VerifyRSASignature(pubKey rsa.PublicKey, message []byte, signature []byte) error {
	hasher := crypto.SHA256.New()
	hasher.Write(message)
	digest := hasher.Sum(nil)

	err := rsa.VerifyPSS(&pubKey, crypto.SHA256, digest, signature, nil)
	if err != nil {
		return err
	}
	return nil
}

// VerifyECDSASignature uses ASN1 to decode r and s, SHA265 to calculate message digest
func VerifyECDSASignature(pubKey ecdsa.PublicKey, message []byte, signature []byte) error {
	hasher := crypto.SHA256.New()
	hasher.Write(message)
	digest := hasher.Sum(nil)

	ok := ecdsa.VerifyASN1(&pubKey, digest, signature)
	if !ok {
		return errors.New("invalid ecdsa signature")
	}
	return nil
}
