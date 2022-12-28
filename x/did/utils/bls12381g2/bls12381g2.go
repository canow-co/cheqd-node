package bls12381g2

import "github.com/lestrrat-go/jwx/jwa"

// Bls12381G2PubKey multicodec code
const Bls12381G2PubCode uint64 = 0xeb

const Bls12381G2 jwa.EllipticCurveAlgorithm = "Bls12381G2"

type PublicKey []byte
