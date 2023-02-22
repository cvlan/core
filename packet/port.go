package packet

import (
	"github.com/cvlan/core/util"
	"io"
	"strconv"
)

type Port uint16

func (p *Port) String() string {
	return strconv.FormatInt(int64(*p), 10)
}

func (p *Port) Encoder(w io.Writer) error {
	_, err := w.Write(util.TypeEncoder[uint16](uint16(*p)))
	return err
}

func (p *Port) Decoder(r io.Reader) error {
	s := make([]byte, 2)
	_, err := r.Read(s)
	if err != nil {
		return err
	}

	val := util.TypeDecoder[uint16](s)

	*p = Port(val)

	return nil
}

func NewPort(port uint16) *Port {
	return (*Port)(&port)
}
