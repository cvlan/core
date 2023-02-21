package packet

import (
	"CVLAN/util"
	"errors"
	"io"
)

type Protocol uint8

const (
	TCP Protocol = iota
	UDP
)

var (
	protocolName = map[Protocol]string{
		TCP: "tcp",
		UDP: "udp",
	}
	protocolValue = map[string]Protocol{
		"tcp": TCP,
		"udp": UDP,
	}
)

func (p *Protocol) String() string {
	val, ok := protocolName[*p]
	if !ok {
		return "<none>"
	}
	return val
}

func (p *Protocol) Valid() bool {
	_, ok := protocolName[*p]
	return ok
}

func (p *Protocol) Is(protocol Protocol) bool {
	return *p == protocol
}

func (p *Protocol) Encoder(w io.Writer) error {
	if !p.Valid() {
		return errors.New("invalid Protocol value")
	}
	_, err := w.Write(util.TypeEncoder[uint8](uint8(*p)))
	return err
}

func (p *Protocol) Decoder(r io.Reader) error {
	s := make([]byte, 1)
	_, err := r.Read(s)
	if err != nil {
		return err
	}

	val := util.TypeDecoder[uint8](s)
	if !(*Protocol)(&val).Valid() {
		return errors.New("invalid Protocol value")
	}

	*p = Protocol(val)

	return nil
}
