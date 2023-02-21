package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"golang.org/x/crypto/curve25519"
	"io"
	"math/big"
)

func DH(pri *PriKey, pub *PubKey) (*[]byte, error) {
	sharedKey, err := curve25519.X25519(pri.Key[:], pub.Key[:])
	if err != nil {
		return nil, err
	}
	return &sharedKey, nil
}

type ECDH[Pub any] interface {
	Marshal() []byte
	Unmarshal([]byte) (*Pub, error)
	GenerateShared(key *Pub) (*[]byte, error)
}

type curve25519ECDH struct {
	pri *PriKey
	pub *PubKey
}

func (e *curve25519ECDH) Marshal() []byte {
	return e.pub.Key[:]
}

func (e *curve25519ECDH) Unmarshal(b []byte) (*PubKey, error) {
	if len(b) != 32 {
		return nil, errors.New("invalid public key")
	}
	var pub [32]byte
	copy(pub[:], b)
	return &PubKey{Key: pub}, nil
}

func (e *curve25519ECDH) GenerateShared(pub *PubKey) (*[]byte, error) {
	return DH(e.pri, pub)
}

func NewCurve25519ECDH() (ECDH[PubKey], error) {
	var pub, pri [32]byte
	if _, err := io.ReadFull(rand.Reader, pri[:]); err != nil {
		return nil, err
	}
	pri[0] &= 248
	pri[31] &= 127
	pri[31] |= 64
	curve25519.ScalarBaseMult(&pub, &pri)
	return &curve25519ECDH{
		pri: &PriKey{Key: pri},
		pub: &PubKey{Key: pub},
	}, nil
}

type ellipticECDH struct {
	curve elliptic.Curve
	d     []byte
	x, y  *big.Int
}

func (e *ellipticECDH) Marshal() []byte {
	return elliptic.Marshal(e.curve, e.x, e.y)
}

func (e *ellipticECDH) Unmarshal(b []byte) (*ecdsa.PublicKey, error) {
	x, y := elliptic.Unmarshal(e.curve, b)
	if x == nil || y == nil {
		return nil, errors.New("invalid public key")
	}
	return &ecdsa.PublicKey{
		Curve: e.curve,
		X:     x,
		Y:     y,
	}, nil
}

func (e *ellipticECDH) GenerateShared(pub *ecdsa.PublicKey) (*[]byte, error) {
	x, _ := e.curve.ScalarMult(pub.X, pub.Y, e.d)
	v := x.Bytes()
	return &v, nil
}

func NewEllipticECDH(curve elliptic.Curve) (ECDH[ecdsa.PublicKey], error) {
	d, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}
	return &ellipticECDH{
		curve: curve,
		d:     d,
		x:     x,
		y:     y,
	}, nil
}
