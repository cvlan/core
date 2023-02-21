package CVLAN

import (
	"CVLAN/crypto"
	"CVLAN/util"
	"errors"
)

type HandShake interface {
	Do() error
}

type ServerHandshake struct{}

type serverHandshakeWithECDH struct{ *Conn }

func (e *serverHandshakeWithECDH) Do() error {
	// recv alice pub key
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

	// check server hello
	if util.Bytes2String(data) != "Hello,Server" {
		return errors.New("error server hello")
	}

	// create client hello
	if data, err = e.crypt.Encrypt(util.String2Bytes("Hello,Client"), nil); err != nil {
		return err
	}

	_, err = e.WriteAsBytes(data)
	return err
}

func (ServerHandshake) Verify(conn *Conn) HandShake { return &serverHandshakeWithVerify{conn} }
func (ServerHandshake) ECDH(conn *Conn) HandShake   { return &serverHandshakeWithECDH{conn} }
