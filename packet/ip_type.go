package packet

import (
	"errors"
	"github.com/cvlan/core/util"
	"io"
)

type IPType uint8

const (
	IPv4 IPType = iota
	IPv6
	EmptyIPTypeValue
)

var (
	ipTypeName = map[IPType]string{
		IPv4: "ipv4",
		IPv6: "ipv6",
	}
	ipTypeValue = map[string]IPType{
		"ipv4": IPv4,
		"ipv6": IPv6,
	}
)

func (t *IPType) String() string {
	val, ok := ipTypeName[*t]
	if !ok {
		return "<none>"
	}
	return val
}

func (t *IPType) Valid() bool {
	_, ok := ipTypeName[*t]
	return ok
}

func (t *IPType) IsIPv4() bool {
	return *t == IPv4
}

func (t *IPType) IsIPv6() bool {
	return *t == IPv6
}

func (t *IPType) Encoder(w io.Writer) error {
	if !t.Valid() {
		return errors.New("invalid IPType value")
	}
	_, err := w.Write(util.TypeEncoder[uint8](uint8(*t)))
	return err
}

func (t *IPType) Decoder(r io.Reader) error {
	p := make([]byte, 1)
	_, err := r.Read(p)
	if err != nil {
		return err
	}

	val := util.TypeDecoder[uint8](p)

	if !(*IPType)(&val).Valid() {
		return errors.New("invalid IPType value")
	}

	*t = IPType(val)

	return nil
}

func NewEmptyIPType() *IPType {
	c := EmptyIPTypeValue
	return &c
}

func NewIPType(typ IPType) *IPType {
	if !typ.Valid() {
		return NewEmptyIPType()
	}
	return &typ
}
