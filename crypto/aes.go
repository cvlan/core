package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"math"
)

type AES interface {
	Encrypt(msg []byte, iv []byte) ([]byte, error)
	Decrypt(msg []byte, iv []byte) ([]byte, error)

	// stream may not be implemented

	StreamEncrypt(r io.Reader, w io.Writer, nextIV func() []byte) error
	StreamDecrypt(r io.Reader, w io.Writer, nextIV func() []byte) error
}

type GCM struct {
	c    cipher.Block
	aead cipher.AEAD
}

func (g *GCM) Encrypt(msg []byte, _ []byte) ([]byte, error) {
	nonce := make([]byte, g.aead.NonceSize())
	io.ReadFull(rand.Reader, nonce)
	cipherText := g.aead.Seal(nil, nonce, msg, nil)
	cipherText = append(cipherText, nonce...)
	return cipherText, nil
}

func (g *GCM) Decrypt(msg []byte, _ []byte) ([]byte, error) {
	cipherTextSize := len(msg)
	nonceSize := g.aead.NonceSize()
	return g.aead.Open(nil, msg[cipherTextSize-nonceSize:], msg[:cipherTextSize-nonceSize], nil)
}

func (g *GCM) StreamEncrypt(src io.Reader, dst io.Writer, _ func() []byte) error {
	as := NewAEStream()

	p := make([]byte, math.MaxUint32/256)
	for {
		n, err := src.Read(p[:])
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		cipherText, err := g.Encrypt(p[:n], nil)
		if err != nil {
			return err
		}

		if err = as.Append(
			cipherText[len(cipherText)-g.aead.NonceSize():],
			cipherText[:len(cipherText)-g.aead.NonceSize()],
		); err != nil {
			return err
		}
	}

	return as.Encoding(dst)
}

func (g *GCM) StreamDecrypt(src io.Reader, dst io.Writer, _ func() []byte) error {
	as, err := ReadAEStream(src)
	if err != nil {
		return err
	}

	if err = as.Iter(func(nonce, payload []byte) error {
		// iter aes stream
		text, pErr := g.Decrypt(append(payload, nonce...), nil)
		if pErr != nil {
			return pErr
		}

		// write decrypt result
		if _, pErr = dst.Write(text); pErr != nil {
			return pErr
		}

		return nil
	}); err != nil {
		return err
	}

	return nil
}

func NewGCM(key []byte) (AES, error) {
	cipherBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(cipherBlock)
	return &GCM{c: cipherBlock, aead: aead}, nil
}
