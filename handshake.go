package CVLAN

import (
	"errors"
	"github.com/cvlan/core/crypto"
	"github.com/cvlan/core/util"
)

type HandShake interface {
	Do() error
}

type ServerHandshake struct{}

type serverHandshakeWithECDH struct{ *Conn }

func (e *serverHandshakeWithECDH) Do() error {
	// recv alice public key
	apk, err := e.ReadAsBytes()
	if err != nil {
		return err
	}

	if len(apk) != 32 {
		return errors.New("invalid read size")
	}

	ecdh, _ := crypto.NewCurve25519ECDH()

	// parse alice public key
	alicePub, err := ecdh.Unmarshal(apk)
	if err != nil {
		return err
	}

	// send bob public key
	if _, err = e.WriteAsBytes(ecdh.Marshal()); err != nil {
		return err
	}

	sharedKey, err := ecdh.GenerateShared(alicePub)
	if err != nil {
		return err
	}
	e.SessionSecret = *sharedKey

	// setup crypt
	if e.crypt, err = crypto.NewGCM(*sharedKey); err != nil {
		return err
	}

	return nil
}

type serverHandshakeWithVerify struct{ *Conn }

func (e *serverHandshakeWithVerify) Do() error {
	bs, err := e.ReadAsBytes()
	if err != nil {
		return err
	}

	data, err := e.crypt.Decrypt(bs, nil)
	if err != nil {
		return err
	}

	// check client hello
	if util.Bytes2String(data) != "Hello,Server" {
		return errors.New("error client hello")
	}

	// create server hello
	if data, err = e.crypt.Encrypt(util.String2Bytes("Hello,Client"), nil); err != nil {
		return err
	}

	_, err = e.WriteAsBytes(data)
	return err
}

func (ServerHandshake) ECDH(conn *Conn) HandShake   { return &serverHandshakeWithECDH{conn} }
func (ServerHandshake) Verify(conn *Conn) HandShake { return &serverHandshakeWithVerify{conn} }

type ClientHandshake struct{}

type clientHandshakeWithECDH struct{ *Conn }

func (e *clientHandshakeWithECDH) Do() (err error) {
	ecdh, _ := crypto.NewCurve25519ECDH()

	// send alice public key
	if _, err = e.WriteAsBytes(ecdh.Marshal()); err != nil {
		return
	}

	// recv bob public key
	bpk, err := e.ReadAsBytes()
	if err != nil {
		return
	}

	if len(bpk) != 32 {
		return errors.New("invalid read size")
	}

	// parse bob public key
	bobPub, err := ecdh.Unmarshal(bpk)
	if err != nil {
		return err
	}

	sharedKey, err := ecdh.GenerateShared(bobPub)
	if err != nil {
		return err
	}
	e.SessionSecret = *sharedKey

	// setup crypt
	if e.crypt, err = crypto.NewGCM(*sharedKey); err != nil {
		return
	}

	return nil
}

type clientHandshakeWithVerify struct{ *Conn }

func (e *clientHandshakeWithVerify) Do() error {
	// create client hello
	data, err := e.crypt.Encrypt(util.String2Bytes("Hello,Server"), nil)
	if err != nil {
		return err
	}

	if _, err = e.WriteAsBytes(data); err != nil {
		return err
	}

	bs, err := e.ReadAsBytes()
	if err != nil {
		return err
	}

	if data, err = e.crypt.Decrypt(bs, nil); err != nil {
		return err
	}

	// check server hello
	if util.Bytes2String(data) != "Hello,Client" {
		return errors.New("error server hello")
	}

	return nil
}

func (ClientHandshake) ECDH(conn *Conn) HandShake   { return &clientHandshakeWithECDH{conn} }
func (ClientHandshake) Verify(conn *Conn) HandShake { return &clientHandshakeWithVerify{conn} }
